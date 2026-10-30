#!/usr/bin/env bash
set -o pipefail
cd /workspace
export PYTHONWARNINGS=default
python3 tests/test_alerting.py > /workspace/_audit_scratch/results/17_tests.out 2>&1
echo EXIT:$? >> /workspace/_audit_scratch/results/17_tests.out
python3 -W default -c "import tests.test_alerting" >/dev/null 2>/workspace/_audit_scratch/results/17_import_warns.txt || true
# module inventory
python3 - <<'PY'
from pathlib import Path
root = Path("/workspace")
mods = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.py") if "_audit_scratch" not in p.as_posix() and ".git" not in p.as_posix())
Path("/workspace/_audit_scratch/results/17_py_modules.txt").write_text("\n".join(mods)+"\n")
print("modules", len(mods))
PY
