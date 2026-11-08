"""Agent 1: URL & Redirect Agent.

Uses the central egress layer to trace a bounded redirect chain (max 10 hops),
revalidating DNS/IP at every hop against SSRF rules, detecting deceptive
destinations, downgrade redirects (HTTPS -> HTTP), and cross-domain hops.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.egress import default_egress
from app.core.errors import ErrorCode, UnsafeTargetError
from app.schemas.common import AgentName, AgentRunStatus, EvidenceKind, Severity


class UrlRedirectAgent(BaseAgent):
    agent_name = AgentName.URL_REDIRECT

    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        result = AgentExecutionResult(
            agent_name=self.agent_name,
            status=AgentRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        current_url = context.target_url
        hops = []
        max_hops = 10
        trace_ev_id = uuid.uuid4()

        try:
            for hop_idx in range(max_hops):
                parsed = urlparse(current_url)
                hostname = parsed.hostname
                if not hostname:
                    break

                try:
                    resp = await default_egress.fetch_url(current_url, follow_redirects=False)
                except UnsafeTargetError as e:
                    result.status = AgentRunStatus.FAILED
                    result.error_code = ErrorCode.DESTINATION_NOT_ALLOWED
                    result.error_message = f"SSRF Check blocked hop {hop_idx}: {str(e)}"
                    result.ended_at = datetime.now(timezone.utc)
                    return result
                except Exception as e:
                    hops.append({
                        "position": hop_idx,
                        "from_url": current_url,
                        "to_url": None,
                        "status_code": 0,
                        "error": str(e),
                    })
                    break

                next_url = resp.redirect_location
                hops.append({
                    "position": hop_idx,
                    "from_url": current_url,
                    "to_url": next_url,
                    "status_code": resp.status_code,
                    "peer_ip": resp.peer_ip,
                    "headers": resp.headers,
                    "elapsed_ms": resp.elapsed_ms,
                })

                if resp.status_code in (301, 302, 303, 307, 308) and next_url:
                    if next_url.startswith("/"):
                        next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"

                    # Detect HTTPS downgrade
                    if current_url.startswith("https://") and next_url.startswith("http://"):
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="redirect.https_downgrade",
                                severity=Severity.HIGH,
                                confidence=1.0,
                                title="HTTPS to HTTP Downgrade Redirect Detected",
                                description=f"Redirect chain downgraded from secure HTTPS ({current_url}) to unencrypted HTTP ({next_url}).",
                                affected_asset=current_url,
                                evidence_ids=[trace_ev_id],
                                score_impact=20,
                            )
                        )

                    # Detect cross-domain hop
                    next_host = urlparse(next_url).hostname
                    if next_host and next_host != hostname:
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="redirect.cross_domain",
                                severity=Severity.LOW,
                                confidence=0.9,
                                title="Cross-Domain Redirect Observed",
                                description=f"Redirect jumped to an external domain: {hostname} -> {next_host}.",
                                affected_asset=current_url,
                                evidence_ids=[trace_ev_id],
                                score_impact=3,
                            )
                        )

                    current_url = next_url
                else:
                    break
            else:
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="redirect.too_many_hops",
                        severity=Severity.MEDIUM,
                        confidence=1.0,
                        title="Excessive Redirect Chain",
                        description=f"Redirect chain exceeded maximum limit of {max_hops} hops.",
                        affected_asset=context.target_url,
                        evidence_ids=[trace_ev_id],
                        score_impact=8,
                    )
                )

            result.raw_evidence.append({
                "evidence_id": trace_ev_id,
                "kind": EvidenceKind.HTTP_RESPONSE,
                "hops": hops,
                "final_url": current_url,
            })
            result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.FAILED
            result.error_code = ErrorCode.INTERNAL_ERROR
            result.error_message = str(e)

        result.ended_at = datetime.now(timezone.utc)
        return result
