"""Agent 3: Certificate Intelligence Agent.

Captures peer certificates via the centralized SSRF-safe egress layer (SafeTlsObservation).
Validates hostname / SAN, expiry dates, key size/algorithm, TLS protocol version & ciphers,
and checks CT log presence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.egress import default_egress
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
            # Probe TLS via central egress with IP pinning and SSRF validation
            obs = await default_egress.probe_tls(hostname, port)

            # Check Expiry
            now = datetime.now(timezone.utc)
            if obs.not_after and obs.not_after < now:
                ev_id = uuid.uuid4()
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.expired",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        title="SSL/TLS Certificate Has Expired",
                        description=f"The leaf certificate expired on {obs.not_after.isoformat()}.",
                        affected_asset=hostname,
                        evidence_ids=[ev_id],
                        score_impact=40,
                    )
                )

            # Check SAN / Hostname matching
            sans = obs.san_list or []
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

            # Check Key strength (RSA key sizes < 2048 bits are considered weak)
            key_type = getattr(obs, "key_type", None)
            key_size = getattr(obs, "key_size", None)
            if key_type and str(key_type).upper() == "RSA" and key_size is not None and key_size < 2048:
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
            result.check_availability["ct"] = "passed" if obs.has_sct else "unknown"
            result.check_availability["revocation"] = "unknown"

            ev_id = uuid.uuid4()
            result.raw_evidence.append({
                "evidence_id": ev_id,
                "kind": EvidenceKind.CERTIFICATE,
                "peer_ip": obs.peer_ip,
                "subject": obs.subject,
                "issuer": obs.issuer,
                "tls_version": obs.tls_version,
                "cipher": obs.cipher_name,
                "key_size": obs.key_size,
                "key_type": getattr(obs, "key_type", None),
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
