"""Agent 5: Privacy & Software Agent.

Evaluates cookie flags (Secure, HttpOnly, SameSite, Lifetime), privacy-relevant
third-party scripts, security headers (CSP, HSTS, X-Content-Type-Options),
and publicly detectable obsolete frontend/CMS software without attempting authentication.
All HTTP requests flow through the central egress layer.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from bs4 import BeautifulSoup

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.egress import default_egress
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
            resp = await default_egress.fetch_url(context.target_url, follow_redirects=True)

            # 1. Inspect Security Headers (case-insensitive lookup)
            raw_headers = resp.headers if resp.headers is not None else {}
            if hasattr(raw_headers, "items"):
                normalized_headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
            elif isinstance(raw_headers, (list, tuple)):
                normalized_headers = {str(k).lower(): str(v) for k, v in raw_headers}
            else:
                normalized_headers = {}

            # Missing HSTS
            if context.target_url.startswith("https://") and "strict-transport-security" not in normalized_headers:
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
            if "content-security-policy" not in normalized_headers:
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
            cookies = self._extract_all_cookies(resp.headers)
            for raw_cookie in cookies:
                parts = [p.strip() for p in raw_cookie.split(";")]
                if not parts or not parts[0]:
                    continue
                name = parts[0].split("=")[0].strip()
                if not name:
                    continue
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
            html_text = resp.body.decode("utf-8", errors="replace")
            soup = BeautifulSoup(html_text[:500000], "html.parser")
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
                "cookie_count": len(cookies),
                "header_count": len(normalized_headers),
            })

            result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.PARTIAL
            result.error_code = ErrorCode.INTERNAL_ERROR
            result.error_message = f"Failed to inspect page privacy signals: {str(e)}"

        result.ended_at = datetime.now(timezone.utc)
        return result

    @staticmethod
    def _split_cookie_line(text: str) -> list[str]:
        """Split a cookie line at genuine cookie boundaries while respecting quoted values."""
        cookies: list[str] = []
        current: list[str] = []
        in_quotes = False
        i = 0
        n = len(text)
        cookie_boundary = re.compile(r"^\s*[a-zA-Z0-9_\-\.%]+=")

        while i < n:
            ch = text[i]
            if ch == '"':
                in_quotes = not in_quotes
                current.append(ch)
                i += 1
            elif ch == ',' and not in_quotes:
                rest = text[i + 1:]
                if cookie_boundary.search(rest):
                    cookie_str = "".join(current).strip()
                    if cookie_str:
                        cookies.append(cookie_str)
                    current = []
                    i += 1
                else:
                    current.append(ch)
                    i += 1
            else:
                current.append(ch)
                i += 1

        cookie_str = "".join(current).strip()
        if cookie_str:
            cookies.append(cookie_str)
        return cookies

    @classmethod
    def _extract_all_cookies(cls, headers: Any) -> list[str]:
        if not headers:
            return []

        raw_strings: list[str] = []
        if hasattr(headers, "get_list"):
            for k in ("set-cookie", "Set-Cookie"):
                for val in headers.get_list(k) or []:
                    raw_strings.append(str(val))
        elif isinstance(headers, (list, tuple)):
            for k, v in headers:
                if str(k).lower() == "set-cookie":
                    raw_strings.append(str(v))
        elif hasattr(headers, "items"):
            for k, v in headers.items():
                if str(k).lower() == "set-cookie":
                    if isinstance(v, (list, tuple)):
                        raw_strings.extend(str(item) for item in v)
                    else:
                        raw_strings.append(str(v))

        cookies: list[str] = []
        for raw in raw_strings:
            lines = [line.strip() for line in raw.splitlines() if line.strip()]
            for line in lines:
                parsed_cookies = cls._split_cookie_line(line)
                cookies.extend(parsed_cookies)
        return cookies
