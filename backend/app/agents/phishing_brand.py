"""Agent 2: Phishing & Brand Impersonation Agent.

Evaluates domain typosquatting / Levenshtein distance against known high-profile brands,
analyzes HTML content for password inputs / credential harvesting forms without submitting them,
and searches for deceptive brand signals.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
import Levenshtein
import tldextract

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.core.errors import ErrorCode
from app.schemas.common import AgentName, AgentRunStatus, EvidenceKind, Severity

KNOWN_BRANDS = [
    "google", "paypal", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "binance", "coinbase", "metamask", "twitter", "linkedin", "dropbox"
]


class PhishingBrandAgent(BaseAgent):
    agent_name = AgentName.PHISHING_BRAND

    async def run(self, context: AgentExecutionContext) -> AgentExecutionResult:
        result = AgentExecutionResult(
            agent_name=self.agent_name,
            status=AgentRunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        parsed = urlparse(context.target_url)
        extracted = tldextract.extract(context.target_url)
        domain_name = extracted.domain.lower()

        # 1. Typosquatting / Lookalike analysis
        for brand in KNOWN_BRANDS:
            if domain_name == brand:
                continue
            
            dist = Levenshtein.distance(domain_name, brand)
            ratio = Levenshtein.ratio(domain_name, brand)
            
            # If very close (edit distance 1 or 2, or similarity > 0.8)
            if (dist in (1, 2) and len(domain_name) >= 4) or (ratio > 0.82 and brand in domain_name):
                ev_id = uuid.uuid4()
                result.findings.append(
                    self.create_finding(
                        context=context,
                        finding_type="phishing.typosquatting",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title=f"Potential Typosquatting of Brand '{brand}'",
                        description=f"Domain '{domain_name}' is suspiciously similar to major brand '{brand}' (edit distance: {dist}, similarity: {ratio:.2f}).",
                        affected_asset=context.target_url,
                        evidence_ids=[ev_id],
                        score_impact=20,
                    )
                )

        # 2. Page Content & Form Inspection (Passive observation only, no form submissions)
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "TrustLens-Security-Scanner/1.0 (+https://trustlens.security/bot)"},
            ) as client:
                resp = await client.get(context.target_url)
                
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text[:500000], "html.parser")
                    
                    # Check for credential harvesting forms
                    password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
                    forms = soup.find_all("form")
                    
                    if password_inputs:
                        # Check form actions
                        suspicious_action = False
                        for f in forms:
                            action = f.get("action", "")
                            if action.startswith("http://"):
                                suspicious_action = True
                        
                        ev_id = uuid.uuid4()
                        severity = Severity.HIGH if suspicious_action else Severity.MEDIUM
                        score = 20 if suspicious_action else 8
                        desc = "Form asking for user credentials (password field detected)."
                        if suspicious_action:
                            desc += " Warning: Form submits over unencrypted HTTP!"

                        result.findings.append(
                            self.create_finding(
                                context=context,
                                finding_type="phishing.credential_harvesting_form",
                                severity=severity,
                                confidence=0.8,
                                title="Password / Credential Input Detected",
                                description=desc,
                                affected_asset=context.target_url,
                                evidence_ids=[ev_id],
                                score_impact=score,
                            )
                        )

                    # Crypto scam analysis extension (feature-flagged)
                    if context.crypto_scam_analysis:
                        crypto_keywords = ["seed phrase", "12-word recovery", "connect wallet", "free crypto", "giveaway double"]
                        page_text = soup.get_text().lower()
                        matches = [k for k in crypto_keywords if k in page_text]
                        if matches:
                            ev_id = uuid.uuid4()
                            result.findings.append(
                                self.create_finding(
                                    context=context,
                                    finding_type="crypto.scam_indicators",
                                    severity=Severity.HIGH,
                                    confidence=0.75,
                                    title="Cryptocurrency Scam Heuristics Triggered",
                                    description=f"Identified suspicious cryptocurrency recovery/giveaway phrasing: {', '.join(matches)}.",
                                    affected_asset=context.target_url,
                                    evidence_ids=[ev_id],
                                    score_impact=20,
                                )
                            )

            result.status = AgentRunStatus.COMPLETED

        except Exception as e:
            result.status = AgentRunStatus.PARTIAL
            result.error_code = ErrorCode.PROVIDER_UNAVAILABLE
            result.error_message = f"Failed to fetch content for visual/brand analysis: {str(e)}"

        result.ended_at = datetime.now(timezone.utc)
        return result

