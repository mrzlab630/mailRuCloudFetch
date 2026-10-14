#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else "Python 3.10+ required")'
  if command -v uv >/dev/null 2>&1; then
    uv venv --python python3 .venv
  else
    python3 -m venv .venv
  fi
fi
if ! .venv/bin/python - <<'PY'
from pathlib import Path
import cryptography, requests, textual
stamp=Path('.venv/requirements.installed')
raise SystemExit(0 if stamp.exists() and stamp.read_bytes()==Path('requirements.txt').read_bytes() else 1)
PY
then
  if command -v uv >/dev/null 2>&1; then
    uv pip install --python .venv/bin/python -r requirements.txt
  else
    if ! .venv/bin/python -m pip --version >/dev/null 2>&1; then
      .venv/bin/python -m ensurepip --upgrade
    fi
    .venv/bin/python -m pip install -r requirements.txt
  fi
  cp requirements.txt .venv/requirements.installed
fi
exec .venv/bin/python cloudmail_downloader.py "$@"
