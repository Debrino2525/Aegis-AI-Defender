"""Isolate pytest from the operator's ~/.aegis and any repo .env secrets."""

import os
import tempfile
from pathlib import Path

_DATA = Path(tempfile.mkdtemp(prefix="aegis-pytest-"))
_ENV_FILE = _DATA / "test.env"
_ENV_FILE.write_text("", encoding="utf-8")

os.environ["AEGIS_DATA_DIR"] = str(_DATA)
os.environ["AEGIS_ENV_FILE"] = str(_ENV_FILE)
os.environ["AEGIS_ADMIN_TOKEN"] = "pytest-admin-token-not-public"
os.environ["AEGIS_DEV"] = "1"
os.environ["AEGIS_ENV"] = "test"
os.environ["ALERT_SIGNING_KEY"] = "pytest-signing-key-not-the-public-default"
os.environ.pop("AEGIS_ADMIN_PASSWORD", None)
os.environ.pop("AEGIS_ALLOW_INSECURE_SIGNING_KEY", None)
os.environ["AEGIS_HOST"] = "127.0.0.1"
