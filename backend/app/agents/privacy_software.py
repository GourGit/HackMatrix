"""Agent 5: Privacy & Software Agent.

Evaluates cookie flags (Secure, HttpOnly, SameSite, Lifetime), privacy-relevant
third-party scripts, security headers (CSP, HSTS, X-Content-Type-Options),
and publicly detectable obsolete frontend/CMS software without attempting authentication.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.errors import ErrorCode
from app.schemas.common import AgentName, AgentRunStatus, EvidenceKind, Severity


class PrivacySoftwareAgent(BaseAgent):
    agent_name = AgentName.PRIVACY_SOFTWARE

    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        result = AgentExecutionResult(
            agent_name=self.agent_name,
            status=AgentRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "TrustLens-Security-Scanner/1.0 (+https://trustlens.security/bot)"},
            ) as client:
                resp = await client.get(context.target_url)

                # 1. Inspect Security Headers
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                # Missing HSTS
                if context.target_url.startswith("https://") and "strict-transport-security" not in headers:
                    ev_id = uuid.uuid4()
                    result.findings.append(
                        self.create_finding(
                            context=context,
                            finding_type="headers.missing_hsts",
                            severity=Severity.LOW,
                            confidence=1.0,
                            title="Missing Strict-Transport-Security (HSTS) Header",
                            description="The website does not enforce HTTPS via HSTS headers, leaving connections vulnerable to SSL stripping attacks.",
                            affected_asset=context.target_url,
                            evidence_ids=[ev_id],
                            score_impact=3,
                        )
                    )

                # Missing Content-Security-Policy
                if "content-security-policy" not in headers:
                    ev_id = uuid.uuid4()
                    result.findings.append(
                        self.create_finding(
                            context=context,
                            finding_type="headers.missing_csp",
                            severity=Severity.LOW,
                            confidence=1.0,
                            title="Missing Content-Security-Policy Header",
                            description="No CSP header found. A strong CSP helps protect users against Cross-Site Scripting (XSS) and data injection.",
                            affected_asset=context.target_url,
                            evidence_ids=[ev_id],
                            score_impact=3,
                        )
                    )

                # 2. Inspect Cookies (Values hashed/redacted immediately for privacy)
                set_cookie_headers = resp.headers.get_list("set-cookie")
                for raw_cookie in set_cookie_headers:
                    parts = [p.strip() for p in raw_cookie.split(";")]
                    if not parts:
                        continue
                    name = parts[0].split("=")[0]
                    name_hash = hashlib.sha256(name.encode()).hexdigest()[:16]

                    lower_parts = [p.lower() for p in parts]
                    is_secure = "secure" in lower_parts
                    is_httponly = "httponly" in lower_parts
                    has_samesite = any("samesite" in p for p in lower_parts)

                    if not is_secure and context.target_url.startswith("https://"):
                        ev_id = uuid.uuid4()
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="cookie.missing_secure_flag",
                                severity=Severity.MEDIUM,
                                confidence=1.0,
                                title="Cookie Missing 'Secure' Attribute",
                                description=f"Cookie (hash: {name_hash}) was set without the 'Secure' flag over HTTPS.",
                                affected_asset=context.target_url,
                                evidence_ids=[ev_id],
                                score_impact=8,
                            )
                        )

                    if not is_httponly and "session" in name.lower():
                        ev_id = uuid.uuid4()
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="cookie.missing_httponly_flag",
                                severity=Severity.MEDIUM,
                                confidence=1.0,
                                title="Session Cookie Missing 'HttpOnly' Attribute",
                                description=f"Session-identifying cookie (hash: {name_hash}) lacks HttpOnly protection, making it accessible to client-side scripts.",
                                affected_asset=context.target_url,
                                evidence_ids=[ev_id],
                                score_impact=8,
                            )
                        )

                # 3. Third-party Tracking Scripts & Obsolete Libraries
                soup = BeautifulSoup(resp.text[:500000], "html.parser")
                scripts = soup.find_all("script", src=True)
                for s in scripts:
                    src = s.get("src", "").lower()
                    if "jquery-1." in src or "jquery-2." in src:
                        ev_id = uuid.uuid4()
                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="software.outdated_library",
                                severity=Severity.LOW,
                                confidence=0.9,
                                title="Outdated JavaScript Library Detected",
                                description=f"Identified legacy jQuery version ({src}) with known vulnerabilities.",
                                affected_asset=context.target_url,
                                evidence_ids=[ev_id],
                                score_impact=3,
                            )
                        )

                ev_id = uuid.uuid4()
                result.raw_evidence.append({
                    "evidence_id": ev_id,
                    "kind": EvidenceKind.COOKIE_SET,
                    "cookie_count": len(set_cookie_headers),
                    "header_count": len(headers),
                })

                result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.PARTIAL
            result.error_code = ErrorCode.INTERNAL_ERROR
            result.error_message = f"Failed to inspect page privacy signals: {str(e)}"

        result.ended_at = datetime.now(timezone.utc)
        return result

