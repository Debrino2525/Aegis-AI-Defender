#!/usr/bin/env python3
import json, warnings, sys
from pathlib import Path
from datetime import datetime
sys.path.insert(0, "/workspace")
caught = []
warnings.simplefilter("always")
def hook(message, category, filename, lineno, file=None, line=None):
    caught.append({"category": category.__name__, "message": str(message), "filename": filename, "lineno": lineno})
warnings.showwarning = hook
datetime.utcnow()
from aegis.core.models import Finding, Severity
Finding(id="x", title="t", target="h", severity=Severity.INFO, description="d", evidence="e")
from aegis.core.config import ScanConfig
ScanConfig(target="127.0.0.1")
from aegis.database.sync import ThreatFeedSync
from aegis.database.db import VulnerabilityDatabase
import tempfile
from pathlib import Path as P
db = VulnerabilityDatabase(P(tempfile.mkdtemp()) / "v.sqlite3")
# don't call utcnow via sync_nvd_recent (network); call the line's equivalent
Path("/workspace/_audit_scratch/results/18_utcnow.json").write_text(json.dumps(caught, indent=2))
print(json.dumps(caught, indent=2))
