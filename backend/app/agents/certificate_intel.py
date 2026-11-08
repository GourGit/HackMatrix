"""Agent 3: Certificate Intelligence Agent.

Captures peer certificates via the centralized SSRF-safe egress layer (SafeTlsObservation).
Validates hostname / SAN, expiry dates, key size/algorithm, TLS protocol version & ciphers,
and checks CT log presence.
"""

from __future__ import annotations

import hashlib
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
            result.check_availability = {
                "ct": "not_requested",
                "revocation": "not_requested",
                "ca_chain": "not_requested",
                "hostname_match": "not_requested",
                "validity_dates": "not_requested",
                "tls_configuration": "not_requested",
                "crypto_strength": "not_requested",
            }
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
            result.raw_evidence.append({
                "evidence_id": ev_id,
                "kind": EvidenceKind.HTTP_RESPONSE,
                "scheme": "http",
                "host": context.target_url,
                "checks": dict(result.check_availability),
            })
            result.ended_at = datetime.now(timezone.utc)
            return result

        hostname = parsed.hostname or context.target_url
        port = parsed.port or 443

        try:
            # Probe TLS via central egress with IP pinning and SSRF validation
            obs = await default_egress.probe_tls(hostname, port)
            cert_ev_id = uuid.uuid4()

            # 1. Validity Dates (not_before & not_after)
            validity_status = "passed"
            now = datetime.now(timezone.utc)
            if obs.not_after and obs.not_after < now:
                validity_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.expired",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        title="SSL/TLS Certificate Has Expired",
                        description=f"The leaf certificate expired on {obs.not_after.isoformat()}.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=40,
                    )
                )
            elif obs.not_before and obs.not_before > now:
                validity_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.not_yet_valid",
                        severity=Severity.MEDIUM,
                        confidence=1.0,
                        title="SSL/TLS Certificate Is Not Yet Valid",
                        description=f"The leaf certificate is not valid until {obs.not_before.isoformat()}.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=8,
                    )
                )

            # 2. Hostname / SAN Matching
            hostname_match_status = "passed"
            sans = obs.san_list or []
            matches_san = (hostname in sans) or any(self._matches_wildcard(hostname, san) for san in sans)
            if not matches_san:
                hostname_match_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.san_mismatch",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Certificate Name Mismatch",
                        description=f"Target hostname '{hostname}' is not covered by Subject Alternative Names: {', '.join(sans[:5]) if sans else 'none'}.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=20,
                    )
                )

            # 3. Trusted CA Chain Validation (Separated from passive inspection)
            ca_status = getattr(obs, "chain_status", None)
            trusted_flag = getattr(obs, "trusted_chain", None)
            if ca_status is None:
                ca_status = "passed" if trusted_flag else "unknown"

            if ca_status == "failed" or (ca_status != "passed" and trusted_flag is False):
                ca_status = "failed"
                chain_err = getattr(obs, "chain_error", None) or "Certificate authority not trusted or self-signed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.untrusted_ca",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Untrusted Certificate Authority or Self-Signed Certificate",
                        description=f"The certificate chain could not be verified against the trusted root CA store: {chain_err}.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=20,
                    )
                )

            # 4. Cryptographic Strength (Key size & Signature algorithm)
            crypto_status = "passed"
            key_type = getattr(obs, "key_type", None)
            key_size = getattr(obs, "key_size", None)
            is_weak_key = False
            if key_type and str(key_type).upper() == "RSA" and key_size is not None and key_size < 2048:
                is_weak_key = True
            elif key_type and str(key_type).upper() in ("EC", "ECDSA") and key_size is not None and key_size < 224:
                is_weak_key = True
            elif key_type and str(key_type).upper() == "DSA" and key_size is not None and key_size < 2048:
                is_weak_key = True

            if is_weak_key:
                crypto_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.weak_key",
                        severity=Severity.MEDIUM,
                        confidence=1.0,
                        title="Weak Cryptographic Key Size",
                        description=f"The certificate key size is {key_size} bits ({key_type}), which is less than the standard 2048 bits.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=8,
                    )
                )

            sig_algo = getattr(obs, "signature_algorithm", "") or ""
            sig_lower = sig_algo.lower()
            if any(weak in sig_lower for weak in ("md5", "sha1", "md2")):
                crypto_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.weak_signature",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Weak Certificate Signature Algorithm",
                        description=f"The certificate signature uses an insecure hash algorithm ({sig_algo}) vulnerable to collisions.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=20,
                    )
                )

            # 5. TLS Protocol Version and Cipher Suite
            tls_status = "passed"
            tls_ver = obs.tls_version or "TLSv1.2"
            if tls_ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
                tls_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="tls.obsolete_version",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        title="Obsolete TLS Protocol Version",
                        description=f"The server negotiated {tls_ver}, which is obsolete and insecure.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=20,
                    )
                )

            cipher = obs.cipher_name or ""
            cipher_lower = cipher.lower()
            if any(weak in cipher_lower for weak in ("null", "rc4", "des", "export", "anon", "md5")):
                tls_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="tls.weak_cipher",
                        severity=Severity.MEDIUM,
                        confidence=1.0,
                        title="Weak TLS Cipher Suite",
                        description=f"The server negotiated an insecure cipher suite: {cipher}.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=8,
                    )
                )

            # 6. Certificate Transparency (SCT)
            # Never report CT as passed merely because an assessment completed
            if obs.has_sct:
                ct_status = "passed"
            else:
                ct_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.missing_sct",
                        severity=Severity.LOW,
                        confidence=1.0,
                        title="Certificate Transparency SCT Missing",
                        description="No Signed Certificate Timestamps (SCT) were found embedded in the certificate.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=3,
                    )
                )

            # 7. OCSP / CRL Revocation Status
            # Never report revocation as good because a network request failed
            raw_rev = getattr(obs, "revocation_status", "unknown")
            if raw_rev in ("failed", "revoked"):
                rev_status = "failed"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.revoked",
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        title="SSL/TLS Certificate Has Been Revoked",
                        description="The issuing Certificate Authority reported this certificate as revoked.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=40,
                    )
                )
            elif raw_rev in ("good", "passed"):
                rev_status = "passed"
            elif raw_rev == "unavailable":
                rev_status = "unavailable"
            else:
                rev_status = "unknown"
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="certificate.revocation_unknown",
                        severity=Severity.LOW,
                        confidence=0.7,
                        title="Certificate Revocation Status Unknown",
                        description="Could not determine OCSP/CRL revocation status through the safe egress layer.",
                        affected_asset=hostname,
                        evidence_ids=[cert_ev_id],
                        score_impact=3,
                    )
                )

            # Explicit check availability results
            result.check_availability = {
                "ct": ct_status,
                "revocation": rev_status,
                "ca_chain": ca_status,
                "hostname_match": hostname_match_status,
                "validity_dates": validity_status,
                "tls_configuration": tls_status,
                "crypto_strength": crypto_status,
            }

            # Persist certificate fingerprints and redacted evidence
            sha256_fp = getattr(obs, "sha256_fingerprint", None)
            if not sha256_fp and obs.raw_der:
                sha256_fp = hashlib.sha256(obs.raw_der).hexdigest()

            result.raw_evidence.append({
                "evidence_id": cert_ev_id,
                "kind": EvidenceKind.CERTIFICATE,
                "peer_ip": obs.peer_ip,
                "host": hostname,
                "subject": obs.subject,
                "issuer": obs.issuer,
                "leaf_fingerprint": sha256_fp or "",
                "sha256_fingerprint": sha256_fp or "",
                "tls_version": obs.tls_version,
                "cipher": obs.cipher_name,
                "key_size": obs.key_size,
                "key_type": getattr(obs, "key_type", None),
                "signature_algorithm": getattr(obs, "signature_algorithm", ""),
                "has_sct": obs.has_sct,
                "trusted_chain": getattr(obs, "trusted_chain", False),
                "chain_status": ca_status,
                "revocation_status": rev_status,
                "not_before": obs.not_before.isoformat() if obs.not_before else None,
                "not_after": obs.not_after.isoformat() if obs.not_after else None,
                "san_list": obs.san_list,
                "checks": dict(result.check_availability),
            })

            result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.PARTIAL
            result.error_code = ErrorCode.INTERNAL_ERROR
            result.error_message = f"TLS probe failed: {str(e)}"
            result.check_availability = {
                "ct": "unavailable",
                "revocation": "unavailable",
                "ca_chain": "unavailable",
                "hostname_match": "unavailable",
                "validity_dates": "unavailable",
                "tls_configuration": "unavailable",
                "crypto_strength": "unavailable",
            }

        result.ended_at = datetime.now(timezone.utc)
        return result

    def _matches_wildcard(self, hostname: str, san: str) -> bool:
        if san.startswith("*."):
            suffix = san[2:]
            return hostname.endswith(suffix) and hostname.count(".") == san.count(".")
        return False
