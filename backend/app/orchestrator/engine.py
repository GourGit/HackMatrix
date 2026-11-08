"""Asyncio Orchestrator for TrustLens assessments.

Coordinates the six deterministic agents, handles timeouts, persists
execution records, stores raw evidence with SHA-256 content hashing and secret
redaction, associates findings with evidence via junction records, executes the
risk engine, and records accurate check statuses.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.base import AgentExecutionContext, AgentExecutionResult
from app.agents.certificate_intel import CertificateIntelAgent
from app.agents.phishing_brand import PhishingBrandAgent
from app.agents.privacy_software import PrivacySoftwareAgent
from app.agents.safe_surface import SafeSurfaceAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.url_redirect import UrlRedirectAgent
from app.config import settings
from app.core.evidence_store import EvidenceMetadata, EvidenceStore, redact_secrets
from app.core.scoring import FindingScore, RiskScoreCalculator
from app.models.agent_run import AgentRun
from app.models.assessment import Assessment
from app.models.certificate import CertificateObservation
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.service import ServiceObservation
from app.schemas.common import (
    AgentName,
    AgentRunStatus,
    AssessmentStatus,
    CertificateFieldStatus,
    CheckAvailability,
    EvidenceKind,
    RevocationStatus,
    score_to_band,
)


def _build_service_observation(
    data: dict[str, Any],
    assessment_id: uuid.UUID,
    default_host: str,
    scope_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
) -> ServiceObservation | None:
    port_val = data.get("port")
    if port_val is None or isinstance(port_val, bool):
        return None

    if isinstance(port_val, int):
        p_int = port_val
    elif isinstance(port_val, str) and port_val.isdigit():
        p_int = int(port_val)
    else:
        return None

    if not (1 <= p_int <= 65535):
        return None

    host_val = data.get("host") or default_host
    protocol_val = data.get("protocol") or "tcp"
    banner_val = data.get("banner")
    version_val = data.get("version") or data.get("version_hint")
    return ServiceObservation(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        host=host_val,
        port=p_int,
        protocol=protocol_val,
        banner=banner_val,
        version_hint=version_val,
        authorization_scope_id=scope_id,
        evidence_id=evidence_id,
    )


class AssessmentOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.agents = [
            UrlRedirectAgent(),
            PhishingBrandAgent(),
            CertificateIntelAgent(),
            SafeSurfaceAgent(),
            PrivacySoftwareAgent(),
            ThreatIntelAgent(),
        ]
        self.scorer = RiskScoreCalculator()
        self.evidence_store = EvidenceStore()

    async def execute_assessment(
        self,
        assessment_id: uuid.UUID,
        safe_scan_enabled: bool = False,
        safe_scan_ports: list[int] | None = None,
        crypto_scam_analysis: bool = False,
    ) -> Assessment:
        """Runs all 6 agents concurrently and persists evidence, findings, and risk metrics."""
        stmt = select(Assessment).where(Assessment.id == assessment_id)
        res = await self.db.execute(stmt)
        assessment = res.scalar_one_or_none()
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found.")

        assessment.status = AssessmentStatus.RUNNING.value
        await self.db.commit()

        effective_safe_scan_ports = list(safe_scan_ports) if safe_scan_ports is not None else []

        tasks = []
        run_records: Dict[AgentName, AgentRun] = {}
        agents_by_name = {a.agent_name: a for a in self.agents}

        try:
            for agent in self.agents:
                run_id = uuid.uuid4()
                agent_run = AgentRun(
                    id=run_id,
                    assessment_id=assessment.id,
                    agent_name=agent.agent_name.value,
                    status=AgentRunStatus.RUNNING.value,
                    rule_version=agent.rule_version,
                    started_at=datetime.now(timezone.utc),
                )
                self.db.add(agent_run)
                run_records[agent.agent_name] = agent_run

                ctx = AgentExecutionContext(
                    assessment_id=assessment.id,
                    run_id=run_id,
                    target_url=assessment.submitted_url,
                    normalized_url=assessment.normalized_url,
                    scope_id=assessment.scope_id,
                    safe_scan_enabled=safe_scan_enabled,
                    safe_scan_ports=effective_safe_scan_ports,
                    crypto_scam_analysis=crypto_scam_analysis,
                )
                tasks.append(self._run_with_timeout(agent, ctx))

            await self.db.commit()

            # Run agents with isolation & timeout
            results: List[AgentExecutionResult] = await asyncio.gather(*tasks, return_exceptions=False)

            all_finding_scores: List[FindingScore] = []
            cert_obs_list: List[CertificateObservation] = []
            service_obs_list: List[ServiceObservation] = []
            seen_services: Dict[tuple[str, int, str], ServiceObservation] = {}
            has_partial_failures = False
            now_utc = datetime.now(timezone.utc)
            retention_deadline = now_utc + timedelta(days=settings.evidence_retention_days)

            for res in results:
                run_rec = run_records[res.agent_name]
                run_rec.status = res.status.value
                run_rec.ended_at = res.ended_at or datetime.now(timezone.utc)
                run_rec.error_code = res.error_code

                current_agent = agents_by_name.get(res.agent_name)
                rule_version = current_agent.rule_version if current_agent else "2026-1"

                meta = EvidenceMetadata(
                    source_uri=assessment.submitted_url,
                    collector_version=rule_version,
                )

                if res.status != AgentRunStatus.COMPLETED:
                    has_partial_failures = True

                # 1. Persist Raw Evidence Items
                evidence_map: Dict[uuid.UUID, Evidence] = {}
                for item in res.raw_evidence:
                    ev_raw_id = item.get("evidence_id")
                    if isinstance(ev_raw_id, str):
                        try:
                            ev_id = uuid.UUID(ev_raw_id)
                        except ValueError:
                            ev_id = uuid.uuid4()
                    elif isinstance(ev_raw_id, uuid.UUID):
                        ev_id = ev_raw_id
                    else:
                        ev_id = uuid.uuid4()
                    item["evidence_id"] = ev_id

                    kind_val = item.get("kind", EvidenceKind.PROVIDER_RESULT)
                    kind_str = kind_val.value if hasattr(kind_val, "value") else str(kind_val)

                    # Redact sensitive parameters and serialize
                    payload_json = json.dumps(item, default=str)
                    redacted_json = redact_secrets(payload_json)
                    content_bytes = redacted_json.encode("utf-8")

                    try:
                        stored = await self.evidence_store.store(content_bytes, meta)

                        ev_model = Evidence(
                            id=ev_id,
                            assessment_id=assessment.id,
                            agent_run_id=run_rec.id,
                            kind=kind_str,
                            source_uri=assessment.submitted_url,
                            content_hash=stored.content_hash,
                            storage_ref=stored.storage_ref,
                            collected_at=now_utc,
                            collector_version=rule_version,
                            redaction_version="1.0",
                            retention_until=retention_deadline,
                        )
                        self.db.add(ev_model)
                        evidence_map[ev_id] = ev_model
                    except Exception:
                        has_partial_failures = True
                        if run_rec.status == AgentRunStatus.COMPLETED.value:
                            run_rec.status = AgentRunStatus.PARTIAL.value
                        if not run_rec.error_code:
                            run_rec.error_code = "EVIDENCE_STORAGE_FAILED"

                # 2. Persist CertificateObservation for Certificate Intelligence Agent
                if res.agent_name in (AgentName.CERTIFICATE_INTELLIGENCE, AgentName.CERTIFICATE_INTELLIGENCE.value, "certificate-intelligence"):
                    for item in res.raw_evidence:
                        kind_val = item.get("kind")
                        if kind_val in (EvidenceKind.CERTIFICATE, EvidenceKind.CERTIFICATE.value, "certificate") or str(kind_val) in ("EvidenceKind.CERTIFICATE", EvidenceKind.CERTIFICATE.value, "certificate"):
                            checks_data = item.get("checks", {})
                            ca_map = {
                                "passed": CertificateFieldStatus.VALID,
                                "failed": CertificateFieldStatus.INVALID,
                            }
                            rev_map = {
                                "passed": RevocationStatus.GOOD,
                                "good": RevocationStatus.GOOD,
                                "failed": RevocationStatus.REVOKED,
                                "revoked": RevocationStatus.REVOKED,
                            }
                            ca_st = ca_map.get(checks_data.get("ca_chain"), CertificateFieldStatus.UNKNOWN)
                            host_st = ca_map.get(checks_data.get("hostname_match"), CertificateFieldStatus.UNKNOWN)
                            ct_st = ca_map.get(checks_data.get("ct"), CertificateFieldStatus.UNKNOWN)
                            rev_st = rev_map.get(checks_data.get("revocation"), RevocationStatus.UNKNOWN)

                            cert_obs = CertificateObservation(
                                id=uuid.uuid4(),
                                assessment_id=assessment.id,
                                host=item.get("host") or assessment.submitted_url,
                                leaf_fingerprint=item.get("leaf_fingerprint") or item.get("sha256_fingerprint") or "",
                                chain_json={"issuer": item.get("issuer"), "subject": item.get("subject")},
                                ca_status=ca_st,
                                hostname_status=host_st,
                                ct_status=ct_st,
                                revocation_status=rev_st,
                                crypto_json={
                                    "key_size": item.get("key_size"),
                                    "key_type": item.get("key_type"),
                                    "signature_algorithm": item.get("signature_algorithm"),
                                    "tls_version": item.get("tls_version"),
                                    "cipher": item.get("cipher"),
                                },
                                evidence_id=item.get("evidence_id") if item.get("evidence_id") in evidence_map else None,
                            )
                            self.db.add(cert_obs)
                            cert_obs_list.append(cert_obs)

                # Persist ServiceObservation for Safe Surface Agent
                if res.agent_name in (AgentName.SAFE_SURFACE, AgentName.SAFE_SURFACE.value, "safe-surface"):
                    parsed_url = urlsplit(assessment.submitted_url or "")
                    default_host = parsed_url.hostname or assessment.submitted_url or ""
                    scope_id = getattr(assessment, "scope_id", None)

                    for item in res.raw_evidence:
                        ev_id = item.get("evidence_id") if item.get("evidence_id") in evidence_map else None

                        candidates: list[dict[str, Any]] = []
                        for svc in item.get("services") or []:
                            if isinstance(svc, dict):
                                svc_data = dict(svc)
                                if "host" not in svc_data and "host" in item:
                                    svc_data["host"] = item["host"]
                                candidates.append(svc_data)

                        if "port" in item and item["port"] is not None:
                            candidates.append(item)

                        for cand in candidates:
                            obs = _build_service_observation(
                                data=cand,
                                assessment_id=assessment.id,
                                default_host=default_host,
                                scope_id=scope_id,
                                evidence_id=ev_id,
                            )
                            if obs is not None:
                                key = (obs.host.lower(), obs.port, obs.protocol.lower())
                                if key not in seen_services:
                                    seen_services[key] = obs
                                    self.db.add(obs)
                                    service_obs_list.append(obs)
                                else:
                                    existing = seen_services[key]
                                    if not existing.banner and obs.banner:
                                        existing.banner = obs.banner
                                    if not existing.version_hint and obs.version_hint:
                                        existing.version_hint = obs.version_hint

                # 3. Persist Findings and associate with Evidence
                for f in res.findings:
                    finding_db = Finding(
                        id=f.finding_id,
                        assessment_id=assessment.id,
                        agent_run_id=run_rec.id,
                        type=f.type,
                        severity=f.severity.value,
                        confidence=f.confidence,
                        score_impact=f.score_impact,
                        status=f.status,
                        asset=f.affected_asset,
                        summary=f.title,
                        rule_version=f.rule_version,
                        observed_at=f.observed_at,
                    )

                    # Link associated evidence
                    linked_any = False
                    for raw_ev_id in f.evidence_ids:
                        if isinstance(raw_ev_id, str):
                            try:
                                ev_uuid = uuid.UUID(raw_ev_id)
                            except ValueError:
                                ev_uuid = uuid.uuid4()
                        elif isinstance(raw_ev_id, uuid.UUID):
                            ev_uuid = raw_ev_id
                        else:
                            ev_uuid = uuid.uuid4()

                        if ev_uuid in evidence_map:
                            finding_db.evidence_items.append(evidence_map[ev_uuid])
                            linked_any = True
                        else:
                            # Finding has an evidence ID that wasn't in raw_evidence:
                            # Persist a matching evidence artifact so every finding's evidence ID corresponds to real persisted evidence
                            ev_payload = {
                                "evidence_id": str(ev_uuid),
                                "kind": EvidenceKind.PROVIDER_RESULT.value,
                                "finding_type": f.type,
                                "title": f.title,
                                "asset": f.affected_asset,
                                "agent": res.agent_name.value if hasattr(res.agent_name, "value") else str(res.agent_name),
                            }
                            ev_json = redact_secrets(json.dumps(ev_payload, default=str))
                            try:
                                stored_ev = await self.evidence_store.store(ev_json.encode("utf-8"), meta)
                                ev_row = Evidence(
                                    id=ev_uuid,
                                    assessment_id=assessment.id,
                                    agent_run_id=run_rec.id,
                                    kind=EvidenceKind.PROVIDER_RESULT.value,
                                    source_uri=assessment.submitted_url,
                                    content_hash=stored_ev.content_hash,
                                    storage_ref=stored_ev.storage_ref,
                                    collected_at=now_utc,
                                    collector_version=rule_version,
                                    redaction_version="1.0",
                                    retention_until=retention_deadline,
                                )
                                self.db.add(ev_row)
                                evidence_map[ev_uuid] = ev_row
                                finding_db.evidence_items.append(ev_row)
                                linked_any = True
                            except Exception:
                                has_partial_failures = True

                    # If finding had no evidence_ids at all, but the agent generated evidence, link to the agent's primary evidence:
                    if not linked_any and evidence_map:
                        primary_ev = next(iter(evidence_map.values()))
                        finding_db.evidence_items.append(primary_ev)

                    self.db.add(finding_db)

                    all_finding_scores.append(
                        FindingScore(
                            finding_id=str(f.finding_id),
                            severity=f.severity,
                            confidence=f.confidence,
                        )
                    )

            # 3. Deterministic Risk Engine Scoring
            risk_result = self.scorer.calculate(all_finding_scores)

            # 4. Durable Assessment-Level Check Statuses
            all_findings = [f for res in results for f in res.findings]
            finding_types = {f.type for f in all_findings}

            safe_run = run_records.get(AgentName.SAFE_SURFACE)
            if safe_run is None:
                safe_scan_state = CheckAvailability.NOT_REQUESTED.value
            elif safe_run.status in (AgentRunStatus.FAILED.value, AgentRunStatus.TIMEOUT.value):
                safe_scan_state = CheckAvailability.FAILED.value
            elif safe_run.status == AgentRunStatus.UNAVAILABLE.value:
                safe_scan_state = CheckAvailability.UNAVAILABLE.value
            elif safe_run.status == AgentRunStatus.COMPLETED.value:
                safe_scan_state = (
                    CheckAvailability.PASSED.value
                    if service_obs_list
                    else CheckAvailability.NOT_REQUESTED.value
                )
            else:
                safe_scan_state = CheckAvailability.UNKNOWN.value

            target_url = assessment.submitted_url or assessment.normalized_url or ""
            is_http = target_url.startswith("http://") or "certificate.unencrypted_http" in finding_types
            cert_run = run_records.get(AgentName.CERTIFICATE_INTELLIGENCE)
            cert_obs = cert_obs_list[0] if cert_obs_list else None

            if is_http or cert_run is None:
                ct_st = CheckAvailability.NOT_REQUESTED.value
                rev_st = CheckAvailability.NOT_REQUESTED.value
                ca_st = CheckAvailability.NOT_REQUESTED.value
                host_st = CheckAvailability.NOT_REQUESTED.value
                val_st = CheckAvailability.NOT_REQUESTED.value
                tls_st = CheckAvailability.NOT_REQUESTED.value
                crypto_st = CheckAvailability.NOT_REQUESTED.value
            elif cert_run.status in (AgentRunStatus.FAILED.value, AgentRunStatus.UNAVAILABLE.value, AgentRunStatus.TIMEOUT.value) and not cert_obs:
                ct_st = CheckAvailability.UNAVAILABLE.value
                rev_st = CheckAvailability.UNAVAILABLE.value
                ca_st = CheckAvailability.UNAVAILABLE.value
                host_st = CheckAvailability.UNAVAILABLE.value
                val_st = CheckAvailability.UNAVAILABLE.value
                tls_st = CheckAvailability.UNAVAILABLE.value
                crypto_st = CheckAvailability.UNAVAILABLE.value
            else:
                if "certificate.missing_sct" in finding_types:
                    ct_st = CheckAvailability.FAILED.value
                elif cert_obs and cert_obs.ct_status == CertificateFieldStatus.VALID:
                    ct_st = CheckAvailability.PASSED.value
                else:
                    ct_st = CheckAvailability.UNKNOWN.value

                if "certificate.revoked" in finding_types:
                    rev_st = CheckAvailability.FAILED.value
                elif "certificate.revocation_unknown" in finding_types:
                    rev_st = CheckAvailability.UNKNOWN.value
                elif cert_obs:
                    if cert_obs.revocation_status == RevocationStatus.GOOD:
                        rev_st = CheckAvailability.PASSED.value
                    elif cert_obs.revocation_status == RevocationStatus.REVOKED:
                        rev_st = CheckAvailability.FAILED.value
                    elif cert_obs.revocation_status == RevocationStatus.UNAVAILABLE:
                        rev_st = CheckAvailability.UNAVAILABLE.value
                    else:
                        rev_st = CheckAvailability.UNKNOWN.value
                else:
                    rev_st = CheckAvailability.UNKNOWN.value

                if "certificate.untrusted_ca" in finding_types:
                    ca_st = CheckAvailability.FAILED.value
                elif cert_obs and cert_obs.ca_status == CertificateFieldStatus.VALID:
                    ca_st = CheckAvailability.PASSED.value
                elif cert_obs and cert_obs.ca_status == CertificateFieldStatus.INVALID:
                    ca_st = CheckAvailability.FAILED.value
                elif cert_run.status == AgentRunStatus.COMPLETED.value:
                    ca_st = CheckAvailability.PASSED.value
                else:
                    ca_st = CheckAvailability.UNKNOWN.value

                if "certificate.san_mismatch" in finding_types:
                    host_st = CheckAvailability.FAILED.value
                elif cert_obs and cert_obs.hostname_status == CertificateFieldStatus.VALID:
                    host_st = CheckAvailability.PASSED.value
                elif cert_obs and cert_obs.hostname_status == CertificateFieldStatus.INVALID:
                    host_st = CheckAvailability.FAILED.value
                elif cert_run.status == AgentRunStatus.COMPLETED.value:
                    host_st = CheckAvailability.PASSED.value
                else:
                    host_st = CheckAvailability.UNKNOWN.value

                if "certificate.expired" in finding_types or "certificate.not_yet_valid" in finding_types:
                    val_st = CheckAvailability.FAILED.value
                elif cert_run.status == AgentRunStatus.COMPLETED.value:
                    val_st = CheckAvailability.PASSED.value
                else:
                    val_st = CheckAvailability.UNKNOWN.value

                if "tls.obsolete_version" in finding_types or "tls.weak_cipher" in finding_types:
                    tls_st = CheckAvailability.FAILED.value
                elif cert_run.status == AgentRunStatus.COMPLETED.value:
                    tls_st = CheckAvailability.PASSED.value
                else:
                    tls_st = CheckAvailability.UNKNOWN.value

                if "certificate.weak_key" in finding_types or "certificate.weak_signature" in finding_types:
                    crypto_st = CheckAvailability.FAILED.value
                elif cert_run.status == AgentRunStatus.COMPLETED.value:
                    crypto_st = CheckAvailability.PASSED.value
                else:
                    crypto_st = CheckAvailability.UNKNOWN.value

            durable_checks = {
                "ct": ct_st,
                "revocation": rev_st,
                "safeScan": safe_scan_state,
                "hostnameMatch": host_st,
                "validityDates": val_st,
                "caChain": ca_st,
                "tlsConfiguration": tls_st,
                "cryptoStrength": crypto_st,
            }

            # 5. Finalize Assessment
            assessment.score = risk_result.score
            assessment.score_band = risk_result.band.value
            assessment.score_version = risk_result.version
            assessment.checks_json = durable_checks
            assessment.status = (
                AssessmentStatus.PARTIAL.value if has_partial_failures else AssessmentStatus.COMPLETED.value
            )
            assessment.completed_at = datetime.now(timezone.utc)

            await self.db.commit()
            await self.db.refresh(assessment)
            return assessment

        except Exception:
            await self.db.rollback()
            now_failed = datetime.now(timezone.utc)
            await self.db.execute(
                update(Assessment)
                .where(Assessment.id == assessment_id)
                .values(
                    status=AssessmentStatus.FAILED.value,
                    completed_at=now_failed,
                )
            )
            await self.db.execute(
                update(AgentRun)
                .where(
                    AgentRun.assessment_id == assessment_id,
                    AgentRun.status == AgentRunStatus.RUNNING.value,
                )
                .values(
                    status=AgentRunStatus.FAILED.value,
                    ended_at=now_failed,
                    error_code="ORCHESTRATOR_ERROR",
                )
            )
            await self.db.commit()
            raise

    async def _run_with_timeout(self, agent, ctx: AgentExecutionContext) -> AgentExecutionResult:
        try:
            return await asyncio.wait_for(agent.run(ctx), timeout=15.0)
        except asyncio.TimeoutError:
            return AgentExecutionResult(
                agent_name=agent.agent_name,
                status=AgentRunStatus.TIMEOUT,
                error_code="AGENT_TIMEOUT",
                error_message="Agent exceeded deadline",
                ended_at=datetime.now(timezone.utc),
            )
        except Exception as e:
            return AgentExecutionResult(
                agent_name=agent.agent_name,
                status=AgentRunStatus.FAILED,
                error_code="INTERNAL_ERROR",
                error_message=str(e),
                ended_at=datetime.now(timezone.utc),
            )
