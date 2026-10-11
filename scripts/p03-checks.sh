#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/runtime-env.sh
python3 scripts/p03-contracts.py
python3 scripts/check-p03-drift.py
npm --prefix packages/api-client run lint
npm --prefix packages/api-client run typecheck
npm --prefix packages/api-client test
python3 scripts/dev-stack.py up
python3 scripts/dev-stack.py test
python3 scripts/check-p03-http.py
python3 scripts/check_baseline.py
