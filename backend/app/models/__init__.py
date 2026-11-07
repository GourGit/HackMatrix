"""SQLAlchemy model registry for TrustLens.

Importing this package ensures every model class and the declarative
``Base`` are registered with SQLAlchemy's mapper, which Alembic needs
to auto-generate migrations.
"""

from app.models.base import Base

from app.models.authorization import AuthorizationScope
from app.models.assessment import Assessment
from app.models.agent_run import AgentRun
from app.models.finding import Finding, finding_evidence
from app.models.evidence import Evidence
from app.models.redirect_hop import RedirectHop
from app.models.certificate import CertificateObservation
from app.models.service import ServiceObservation
from app.models.cookie import CookieObservation
from app.models.indicator import Indicator
from app.models.audit import AuditEvent

__all__ = [
    "Base",
    "AuthorizationScope",
    "Assessment",
    "AgentRun",
    "Finding",
    "finding_evidence",
    "Evidence",
    "RedirectHop",
    "CertificateObservation",
    "ServiceObservation",
    "CookieObservation",
    "Indicator",
    "AuditEvent",
]
