"""
Core domain models for Aegis Vulnerability Scanner.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ServiceInfo(BaseModel):
    """Represents an enumerated network service and detected fingerprint."""
    port: int
    protocol: str = "tcp"
    service_name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    tls: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityDefinition(BaseModel):
    """Known CVE or misconfiguration rule definition."""
    id: str  # e.g. CVE-2021-44228 or AEGIS-MISCONFIG-001
    title: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    epss_score: float = 0.0
    is_cisa_kev: bool = False
    cpe_match: Optional[str] = None
    affected_version_ranges: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    """An identified vulnerability instance on a target."""
    id: str
    title: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    severity: Severity
    cvss_score: float = 0.0
    epss_score: float = 0.0
    is_cisa_kev: bool = False
    composite_risk_score: float = 0.0  # Dynamic prioritized risk score (0 - 100)
    confidence: str = "MEDIUM"  # Detection confidence: HIGH, MEDIUM, LOW
    description: str
    evidence: str
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HostScanResult(BaseModel):
    """Complete assessment result for a single target host."""
    host: str
    ip: str
    status: str = "UP"
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServiceInfo] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0


class ScanReport(BaseModel):
    """Aggregated scan execution report."""
    scan_id: str
    target: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    hosts: List[HostScanResult] = Field(default_factory=list)
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
