#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/toy"
python3 experiments.py "${1:-50}" | tee ../results_experiments.txt
python3 small_curve_attacks.py "${2:-20}" | tee ../results_small_curve.txt
