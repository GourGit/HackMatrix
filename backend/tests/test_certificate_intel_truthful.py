"""Tests for truthful certificate and TLS intelligence gathering.

Verifies independent reporting of:
1. Hostname / SAN match
2. Certificate validity dates (expired, not yet valid, valid)
3. Trusted / untrusted CA chain
4. TLS version and cipher suite
5. Weak key size or signature algorithm
6. SCT / Certificate Transparency presence
7. OCSP / CRL revocation status

Ensures explicit result states: passed, failed, unknown, unavailable, not_requested.
Verifies invariants:
- Never report revocation as good because a network request failed.
- Never report CT as passed merely because an assessment completed.
- Persist certificate fingerprints (SHA-256) and redacted evidence.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.requests import Request

from app.agents.base import AgentExecutionContext, AgentExecutionResult
from app.agents.certificate_intel import CertificateIntelAgent
from app.api.deps import AuthenticatedIdentity
from app.api.v1.assessments import get_assessment
from app.core.egress import SafeTlsObservation
from app.models.assessment import Assessment
from app.models.authorization import AuthorizationScope
from app.models.certificate import CertificateObservation
from app.orchestrator.engine import AssessmentOrchestrator
from app.schemas.common import (
    AgentName,
    AgentRunStatus,
    AssessmentStatus,
    CertificateFieldStatus,
    CheckAvailability,
    RevocationStatus,
    ScopeStatus,
    Severity,
)


def _generate_test_certificate(
    common_name: str = "example.com",
    san_names: list[str] | None = None,
    key_size: int = 2048,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    hash_algorithm: hashes.HashAlgorithm = hashes.SHA256(),
) -> tuple[bytes, str, rsa.RSAPrivateKey]:
    """Helper to generate a DER-encoded X.509 certificate fixture with SHA-256 fingerprint."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    nb = not_before or (now - timedelta(days=5))
    na = not_after or (now + timedelta(days=90))

    sans = san_names if san_names is not None else [common_name]
    san_ext = x509.SubjectAlternativeName([x509.DNSName(name) for name in sans])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(san_ext, critical=False)
        .sign(key, hash_algorithm)
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return der, fingerprint, key


def _make_context(url: str = "https://example.com") -> AgentExecutionContext:
    return AgentExecutionContext(
        assessment_id=uuid.uuid4(),
        run_id=uuid.uuid4(),
        target_url=url,
        normalized_url=url,
        scope_id=uuid.uuid4(),
    )


@pytest.mark.asyncio
async def test_valid_certificate_truthful_reporting():
    """Valid certificate with modern TLS, SAN match, CT, and trusted chain passes all checks."""
    der, fingerprint, _ = _generate_test_certificate(
        common_name="example.com",
        san_names=["example.com", "www.example.com"],
        key_size=2048,
    )
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert Global Root CA",
        not_before=datetime.now(timezone.utc) - timedelta(days=10),
        not_after=datetime.now(timezone.utc) + timedelta(days=80),
        san_list=["example.com", "www.example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.status == AgentRunStatus.COMPLETED
    assert len(result.findings) == 0  # no security defects on pristine cert

    checks = result.check_availability
    assert checks["hostname_match"] == CheckAvailability.PASSED.value
    assert checks["validity_dates"] == CheckAvailability.PASSED.value
    assert checks["ca_chain"] == CheckAvailability.PASSED.value
    assert checks["tls_configuration"] == CheckAvailability.PASSED.value
    assert checks["crypto_strength"] == CheckAvailability.PASSED.value
    assert checks["ct"] == CheckAvailability.PASSED.value
    assert checks["revocation"] == CheckAvailability.PASSED.value

    assert len(result.raw_evidence) == 1
    ev = result.raw_evidence[0]
    assert ev["leaf_fingerprint"] == fingerprint
    assert ev["sha256_fingerprint"] == fingerprint


@pytest.mark.asyncio
async def test_expired_certificate_fixture():
    """Expired certificate triggers certificate.expired finding with CRITICAL severity."""
    now = datetime.now(timezone.utc)
    der, fingerprint, _ = _generate_test_certificate(
        not_before=now - timedelta(days=120),
        not_after=now - timedelta(days=10),
    )
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=Let's Encrypt Authority X3",
        not_before=now - timedelta(days=120),
        not_after=now - timedelta(days=10),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.status == AgentRunStatus.COMPLETED
    assert result.check_availability["validity_dates"] == CheckAvailability.FAILED.value

    finding = next((f for f in result.findings if f.type == "certificate.expired"), None)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.score_impact == 40


@pytest.mark.asyncio
async def test_not_yet_valid_certificate_fixture():
    """Certificate not yet valid triggers certificate.not_yet_valid finding."""
    now = datetime.now(timezone.utc)
    der, fingerprint, _ = _generate_test_certificate(
        not_before=now + timedelta(days=5),
        not_after=now + timedelta(days=95),
    )
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=Let's Encrypt Authority X3",
        not_before=now + timedelta(days=5),
        not_after=now + timedelta(days=95),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.status == AgentRunStatus.COMPLETED
    assert result.check_availability["validity_dates"] == CheckAvailability.FAILED.value
    finding = next((f for f in result.findings if f.type == "certificate.not_yet_valid"), None)
    assert finding is not None
    assert finding.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_self_signed_untrusted_ca_fixture():
    """Self-signed / untrusted CA chain sets ca_chain: failed and raises finding."""
    der, fingerprint, _ = _generate_test_certificate(common_name="example.com")
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=example.com",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=False,
        chain_status="failed",
        chain_error="self-signed certificate in certificate chain",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.check_availability["ca_chain"] == CheckAvailability.FAILED.value
    finding = next((f for f in result.findings if f.type == "certificate.untrusted_ca"), None)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.score_impact == 20


@pytest.mark.asyncio
async def test_san_mismatch_fixture():
    """SAN mismatch produces certificate.san_mismatch with HIGH severity."""
    der, fingerprint, _ = _generate_test_certificate(
        common_name="other-domain.test",
        san_names=["other-domain.test", "internal.local"],
    )
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=other-domain.test",
        issuer="CN=DigiCert Global Root CA",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["other-domain.test", "internal.local"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.check_availability["hostname_match"] == CheckAvailability.FAILED.value
    finding = next((f for f in result.findings if f.type == "certificate.san_mismatch"), None)
    assert finding is not None
    assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_weak_crypto_and_obsolete_tls():
    """Weak key size (RSA 1024), obsolete TLS (TLSv1.0), and weak cipher (RC4) are independently flagged."""
    der, fingerprint, _ = _generate_test_certificate(key_size=1024)
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert Global Root CA",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.0",
        cipher_name="RC4-MD5",
        key_type="RSA",
        key_size=1024,
        signature_algorithm="sha1WithRSAEncryption",
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        result = await agent.run(context)

    assert result.check_availability["crypto_strength"] == CheckAvailability.FAILED.value
    assert result.check_availability["tls_configuration"] == CheckAvailability.FAILED.value

    types = {f.type for f in result.findings}
    assert "certificate.weak_key" in types
    assert "certificate.weak_signature" in types
    assert "tls.obsolete_version" in types
    assert "tls.weak_cipher" in types


@pytest.mark.asyncio
async def test_ct_presence_and_absence():
    """CT presence results in passed; absence results in failed (never reported as passed unconditionally)."""
    der, fingerprint, _ = _generate_test_certificate()

    # Case A: SCT absent
    obs_no_sct = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=False,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_no_sct)):
        res_no_sct = await agent.run(context)

    assert res_no_sct.check_availability["ct"] == CheckAvailability.FAILED.value
    assert any(f.type == "certificate.missing_sct" for f in res_no_sct.findings)

    # Case B: SCT present
    obs_with_sct = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_with_sct)):
        res_with_sct = await agent.run(context)

    assert res_with_sct.check_availability["ct"] == CheckAvailability.PASSED.value
    assert not any(f.type == "certificate.missing_sct" for f in res_with_sct.findings)


@pytest.mark.asyncio
async def test_revocation_truthfulness_and_network_failure_invariant():
    """Revocation is never reported as good when unverified or when a network error occurs."""
    der, fingerprint, _ = _generate_test_certificate()
    agent = CertificateIntelAgent()
    context = _make_context("https://example.com")

    # 1. Good revocation status -> passed
    obs_good = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )
    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_good)):
        res_good = await agent.run(context)
    assert res_good.check_availability["revocation"] == CheckAvailability.PASSED.value

    # 2. Revoked certificate -> failed, finding certificate.revoked
    obs_revoked = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="revoked",
    )
    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_revoked)):
        res_revoked = await agent.run(context)
    assert res_revoked.check_availability["revocation"] == CheckAvailability.FAILED.value
    assert any(f.type == "certificate.revoked" for f in res_revoked.findings)

    # 3. Unknown / unverified -> unknown, never good
    obs_unknown = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="unknown",
    )
    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_unknown)):
        res_unknown = await agent.run(context)
    assert res_unknown.check_availability["revocation"] == CheckAvailability.UNKNOWN.value
    assert any(f.type == "certificate.revocation_unknown" for f in res_unknown.findings)

    # 4. Unavailable -> unavailable
    obs_unavail = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        trusted_chain=True,
        chain_status="passed",
        revocation_status="unavailable",
    )
    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs_unavail)):
        res_unavail = await agent.run(context)
    assert res_unavail.check_availability["revocation"] == CheckAvailability.UNAVAILABLE.value


@pytest.mark.asyncio
async def test_persistence_of_fingerprints_and_truthful_api_checks(db_session):
    """Orchestrator persists CertificateObservation with fingerprint and API exposes truthful checks."""
    tenant_id = uuid.uuid4()
    scope_id = uuid.uuid4()
    assessment_id = uuid.uuid4()

    scope = AuthorizationScope(
        id=scope_id,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        targets_json=["https://example.com"],
        valid_from=datetime.now(timezone.utc),
        valid_until=datetime.now(timezone.utc) + timedelta(days=1),
        status=ScopeStatus.ACTIVE.value,
    )
    db_session.add(scope)

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        scope_id=scope_id,
        submitted_url="https://example.com",
        normalized_url="https://example.com",
        status=AssessmentStatus.QUEUED.value,
    )
    db_session.add(assessment)
    await db_session.commit()

    der, fingerprint, _ = _generate_test_certificate(
        common_name="example.com",
        san_names=["example.com"],
        key_size=2048,
    )
    obs = SafeTlsObservation(
        hostname="example.com",
        port=443,
        peer_ip="93.184.216.34",
        raw_der=der,
        sha256_fingerprint=fingerprint,
        subject="CN=example.com",
        issuer="CN=DigiCert Global Root CA",
        not_before=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=datetime.now(timezone.utc) + timedelta(days=30),
        san_list=["example.com"],
        has_sct=True,
        tls_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        key_type="RSA",
        key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        trusted_chain=True,
        chain_status="passed",
        revocation_status="good",
    )

    orchestrator = AssessmentOrchestrator(db_session)

    for agent in orchestrator.agents:
        if agent.agent_name != AgentName.CERTIFICATE_INTELLIGENCE:
            agent.run = AsyncMock(
                return_value=AgentExecutionResult(
                    agent_name=agent.agent_name,
                    status=AgentRunStatus.COMPLETED,
                    findings=[],
                )
            )

    with patch("app.agents.certificate_intel.default_egress.probe_tls", new=AsyncMock(return_value=obs)):
        # Run orchestrator
        completed = await orchestrator.execute_assessment(
            assessment_id=assessment_id,
            safe_scan_enabled=False,
            crypto_scam_analysis=False,
        )

    assert completed.status == AssessmentStatus.COMPLETED.value

    # Verify CertificateObservation in DB
    cert_obs_stmt = select(CertificateObservation).where(CertificateObservation.assessment_id == assessment_id)
    obs_res = await db_session.execute(cert_obs_stmt)
    cert_obs_list = obs_res.scalars().all()
    assert len(cert_obs_list) == 1
    db_obs = cert_obs_list[0]
    assert db_obs.leaf_fingerprint == fingerprint
    assert db_obs.ca_status == CertificateFieldStatus.VALID
    assert db_obs.hostname_status == CertificateFieldStatus.VALID
    assert db_obs.ct_status == CertificateFieldStatus.VALID
    assert db_obs.revocation_status == RevocationStatus.GOOD

    # Verify API get_assessment returns truthful checks
    req = Request(scope={"type": "http", "method": "GET", "path": f"/v1/assessments/{assessment_id}", "headers": []})
    resp = await get_assessment(
        request=req,
        assessment_id=assessment_id,
        db=db_session,
        request_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
    )

    import json
    data = json.loads(resp.body)
    checks = data["checks"]

    assert checks["ct"] == "passed"
    assert checks["revocation"] == "passed"
    assert checks["safeScan"] == "not_requested"
    assert checks["hostnameMatch"] == "passed"
    assert checks["validityDates"] == "passed"
    assert checks["caChain"] == "passed"
    assert checks["tlsConfiguration"] == "passed"
    assert checks["cryptoStrength"] == "passed"
