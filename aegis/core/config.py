"""
Global configuration and scanning profile definitions for Aegis.
"""

from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

# Default Top Ports commonly targeted in enterprise infrastructure
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 7001, 8000,
    8080, 8443, 8888, 9000, 9200, 27017
]


class ScanConfig(BaseModel):
    """Configuration options for a scan session."""
    target: str
    ports: List[int] = Field(default_factory=lambda: TOP_PORTS)
    concurrency: int = 250
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    enable_service_probe: bool = True
    enable_template_checks: bool = True
    enable_cpe_vdb_matching: bool = True
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".aegis")
    output_format: str = "console"  # console, json, sarif
    output_file: Optional[Path] = None

    class Config:
        arbitrary_types_allowed = True
