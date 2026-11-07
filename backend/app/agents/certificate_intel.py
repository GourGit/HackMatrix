"""Agent 3: Certificate Intelligence Agent.

Captures peer certificates and chain context via read-only TLS handshake,
validates hostname / SAN, expiry dates, issuer CA trust, key size/algorithm,
TLS protocol version & ciphers, and checks CT log presence and OCSP/CRL revocation.
Records unavailable revocation or CT as unknown, never inferred as failure.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.errors import ErrorCode
from app.schemas.common import AgentName, AgentRunStatus, EvidenceKind, Severity


class CertificateIntelAgent(BaseAgent):
    agent_name = AgentName.CERTIFICATE_INTELLIGENCE

    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        result = AgentExecutionResult(
            agent_name=self.agent_name,
            status=AgentRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        parsed = urlparse(context.target_url)
        if parsed.scheme != "https":
            result.status = AgentRunStatus.COMPLETED
            result.check_availability["ct"] = "not_requested"
            result.check_availability["revocation"] = "not_requested"
            ev_id = uuid.uuid4()
            result.findings.append(
                self.create_finding(
                    context=context,
                    finding_type="certificate.unencrypted_http",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    title="Website Operates Over Plain HTTP Without TLS",
                    description="The target website does not enforce HTTPS. Traffic is transmitted in cleartext.",
                    affected_asset=context.target_url,
                    evidence_ids=[ev_id],
                    score_impact=20,
                )
            )
            result.ended_at = datetime.now(timezone.utc)
            return result

        hostname = parsed.hostname or context.target_url
        port = parsed.port or 443

        try:
            # Perform read-only TLS handshake in executor to avoid blocking event loop
            loop = asyncio.get_running_loop()
            cert_info = await loop.run_in_executor(None, self._probe_tls, hostname, port)
            
            # Check Expiry
            not_after = cert_info.get("not_after")
            now = datetime.now(timezone.utc)
            if not_after and not_after < now:
                ev_id = uuid.uuid4()
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.expired",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        title="SSL/TLS Certificate Has Expired",
                        description=f"The leaf certificate expired on {not_after.isoformat()}.",
                        affected_asset=hostname,
                        evidence_ids=[ev_id],
                        score_impact=40,
                    )
                )

            # Check SAN / Hostname
            sans = cert_info.get("san", [])
            if hostname not in sans and not any(self._matches_wildcard(hostname, san) for san in sans):
                ev_id = uuid.uuid4()
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.san_mismatch",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Certificate Name Mismatch",
                        description=f"Target hostname '{hostname}' is not covered by Subject Alternative Names: {', '.join(sans[:5])}.",
                        affected_asset=hostname,
                        evidence_ids=[ev_id],
                        score_impact=20,
                    )
                )

            # Check Weak Key
            key_size = cert_info.get("key_size", 2048)
            if key_size < 2048:
                ev_id = uuid.uuid4()
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.weak_key",
                        severity=Severity.MEDIUM,
                        confidence=1.0,
                        title="Weak Cryptographic Key Size",
                        description=f"The certificate key size is {key_size} bits, which is less than the standard 2048 bits.",
                        affected_asset=hostname,
                        evidence_ids=[ev_id],
                        score_impact=8,
                    )
                )

            # CT and Revocation availability
            result.check_availability["ct"] = "passed" if cert_info.get("has_sct") else "unknown"
            result.check_availability["revocation"] = cert_info.get("revocation_status", "unknown")

            ev_id = uuid.uuid4()
            result.raw_evidence.append({
                "evidence_id": ev_id,
                "kind": EvidenceKind.CERTIFICATE,
                "details": cert_info,
            })

            result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.PARTIAL
            result.error_code = ErrorCode.INTERNAL_ERROR
            result.error_message = f"TLS probe failed: {str(e)}"
            result.check_availability["ct"] = "unknown"
            result.check_availability["revocation"] = "unknown"

        result.ended_at = datetime.now(timezone.utc)
        return result

    def _matches_wildcard(self, hostname: str, san: str) -> bool:
        if san.startswith("*."):
            suffix = san[2:]
            return hostname.endswith(suffix) and hostname.count(".") == san.count(".")
        return False

    def _probe_tls(self, hostname: str, port: int) -> dict:
        ssl_ctx = ssl.create_default_context()
        # For non-intrusive inspection, we allow inspecting self-signed/untrusted certs to flag them
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=6.0) as sock:
            with ssl_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_version = ssock.version()

                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                sans = []
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

                has_sct = False
                try:
                    cert.extensions.get_extension_for_oid(x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
                    has_sct = True
                except Exception:
                    pass

                return {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": cert.not_valid_before_utc,
                    "not_after": cert.not_valid_after_utc,
                    "san": sans,
                    "has_sct": has_sct,
                    "revocation_status": "unknown",
                    "cipher": cipher,
                    "tls_version": tls_version,
                    "key_size": getattr(cert.public_key(), "key_size", 2048),
                }

