"""
Aegis AI — Critical Alert Routing Models.
Defines core data structures for alert classification, DoD Zero Trust tagging,
escalation states, and dispatch records.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DoDZTPillar(str, Enum):
    USER = "User"
    DEVICE = "Device"
    APPLICATION_WORKLOAD = "Application & Workload"
    DATA = "Data"
    NETWORK_ENVIRONMENT = "Network & Environment"
    AUTOMATION_ORCHESTRATION = "Automation & Orchestration"
    VISIBILITY_ANALYTICS = "Visibility & Analytics"


class ChannelType(str, Enum):
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    SMS_LOCAL = "sms_local"
    VOICE_CALL = "voice_call"
    MODEM_OOB = "modem_oob"
    WEBHOOK = "webhook"
    CONSOLE = "console"


class OnCallContact(BaseModel):
    contact_id: str
    name: str
    role: str = "SOC Responder"
    phone: str  # e.g. "+233244000000"
    email: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    whatsapp_number: Optional[str] = None
    is_active: bool = True


class AssetOwnerMapping(BaseModel):
    cidr_or_host: str
    environment: str = "Production"
    owner_team: str = "SOC-Tier2"
    primary_contact_id: str
    escalation_contact_id: str
    escalation_timeout_mins: int = 5


class CriticalAlert(BaseModel):
    alert_id: str
    fingerprint: str
    title: str
    severity: SeverityLevel
    summary: str
    source_ip: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    process: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_cisa_kev: bool = False
    zt_pillars: List[DoDZTPillar] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    escalation_level: int = 0
    occurrence_count: int = 1
    last_occurrence: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DispatchResult(BaseModel):
    channel: ChannelType
    success: bool
    recipient: str
    provider_ref: Optional[str] = None
    error: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
