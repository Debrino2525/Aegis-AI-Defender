"""
Aegis AI — Critical Alert Routing & Multi-Channel Escalation Engine.
"""

from aegis.alerting.models import (
    CriticalAlert, OnCallContact, AssetOwnerMapping,
    SeverityLevel, DoDZTPillar, ChannelType, DispatchResult
)
from aegis.alerting.router import AlertRouter, alert_router
from aegis.alerting.queue import AlertQueue
from aegis.alerting.classifier import AlertClassifier
from aegis.alerting.dedup import FlapDamper
from aegis.alerting.escalation import EscalationManager
from aegis.alerting.security import generate_triage_token, verify_triage_token

__all__ = [
    "CriticalAlert",
    "OnCallContact",
    "AssetOwnerMapping",
    "SeverityLevel",
    "DoDZTPillar",
    "ChannelType",
    "DispatchResult",
    "AlertRouter",
    "alert_router",
    "AlertQueue",
    "AlertClassifier",
    "FlapDamper",
    "EscalationManager",
    "generate_triage_token",
    "verify_triage_token",
]
