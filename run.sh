#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 pipeline/generate_fleet.py
python3 pipeline/aggregate.py
python3 pipeline/render.py
python3 pipeline/privacy_check.py
echo "status page: site/index.html"
