#!/bin/bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 "$here/test_probe.py"
