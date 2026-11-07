"""TrustLens Agents package.

Exports the six bounded, auditable analyzers and common agent interfaces.
"""

from app.agents.base import AgentExecutionContext, AgentExecutionResult, BaseAgent
from app.agents.certificate_intel import CertificateIntelAgent
from app.agents.phishing_brand import PhishingBrandAgent
from app.agents.privacy_software import PrivacySoftwareAgent
from app.agents.safe_surface import SafeSurfaceAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.url_redirect import UrlRedirectAgent

__all__ = [
    "BaseAgent",
    "AgentExecutionContext",
    "AgentExecutionResult",
    "UrlRedirectAgent",
    "PhishingBrandAgent",
    "CertificateIntelAgent",
    "SafeSurfaceAgent",
    "PrivacySoftwareAgent",
    "ThreatIntelAgent",
]

