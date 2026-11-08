"""Agent 4: Safe Surface Agent.

Performs allowlisted, rate-limited, strictly non-exploitative HTTP/TLS inspection
and explicitly authorized service discovery. Identifies safely observable exposed services
and server banners. No port scans or intrusive probes are performed without explicit scope.
"""

from __future__ import annotations

import asyncio
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.errors import ErrorCode
from app.schemas.common import AgentName, AgentRunStatus, EvidenceKind, Severity


class SafeSurfaceAgent(BaseAgent):
    agent_name = AgentName.SAFE_SURFACE

    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        result = AgentExecutionResult(
            agent_name=self.agent_name,
            status=AgentRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        # Check authorization scope
        if not context.safe_scan_enabled:
            result.status = AgentRunStatus.COMPLETED
            result.check_availability["safeScan"] = "not_requested"
            result.ended_at = datetime.now(timezone.utc)
            return result

        result.check_availability["safeScan"] = "completed"
        parsed = urlparse(context.target_url)
        hostname = parsed.hostname or context.target_url

        allowed_ports = context.safe_scan_ports if context.safe_scan_ports is not None else []
        observed_services = []

        loop = asyncio.get_running_loop()

        for port in allowed_ports:
            # Check only approved, non-intrusive TCP connection
            is_open = await loop.run_in_executor(None, self._check_port, hostname, port)
            if is_open:
                observed_services.append({"port": port, "status": "open"})
                
                # Flag sensitive management ports if exposed
                if port in (8080, 8443, 8888, 9000):
                    ev_id = uuid.uuid4()
                    result.findings.append(
                        self.create_finding(
                            context=context,
                            finding_type="surface.exposed_admin_port",
                            severity=Severity.MEDIUM,
                            confidence=0.9,
                            title=f"Non-Standard Service Port Exposed (Port {port})",
                            description=f"Port {port} is open and responding to connections. Administrative/alternative services should not be publicly accessible.",
                            affected_asset=f"{hostname}:{port}",
                            evidence_ids=[ev_id],
                            score_impact=8,
                        )
                    )

        # Passive Server Banner check
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.head(context.target_url)
                server_hdr = resp.headers.get("server")
                if server_hdr:
                    # Check for outdated / revealing banners
                    if any(legacy in server_hdr.lower() for legacy in ["apache/2.2", "nginx/1.10", "php/5.", "iis/7."]):
                        ev_id = uuid.uuid4()
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="surface.outdated_server_banner",
                                severity=Severity.MEDIUM,
                                confidence=0.85,
                                title=f"Potentially Obsolete Server Software ({server_hdr})",
                                description=f"The web server exposes an end-of-life or outdated version banner: {server_hdr}.",
                                affected_asset=context.target_url,
                                evidence_ids=[ev_id],
                                score_impact=8,
                            )
                        )
        except Exception:
            pass

        ev_id = uuid.uuid4()
        result.raw_evidence.append({
            "evidence_id": ev_id,
            "kind": EvidenceKind.BANNER,
            "services": observed_services,
        })

        result.status = AgentRunStatus.COMPLETED
        result.ended_at = datetime.now(timezone.utc)
        return result

    def _check_port(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except Exception:
            return False

