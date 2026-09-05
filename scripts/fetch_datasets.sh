#!/usr/bin/env bash
# Fetch the public SOC datasets into data/. Optional — Bishop runs without them.
#
# Bishop's committed corpus is 20 synthetic alerts (see scripts/build_corpus.py
# for why). These are the real ones, for anyone who wants to normalise their own
# corpus and run Bishop against it. They are large and they are gitignored.
#
# Check each project's licence before redistributing anything you derive from
# them. Bishop does not vendor any of it.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${ROOT}/data"
mkdir -p "${DATA}"

clone() {
  local name="$1" url="$2" note="$3"
  local target="${DATA}/${name}"
  if [ -d "${target}" ]; then
    echo "  ${name} already present, skipping"
    return
  fi
  echo "  ${name} — ${note}"
  git clone --depth 1 --quiet "${url}" "${target}"
}

echo "Fetching datasets into data/ (gitignored)"
echo

clone security-datasets \
  https://github.com/OTRF/Security-Datasets \
  "Sysmon and Windows telemetry from emulated ATT&CK techniques"

clone sigma \
  https://github.com/SigmaHQ/sigma \
  "detection rules, useful for comparing Bishop's detectors against community logic"

echo
echo "Not fetched automatically, because they need a click-through or an account:"
echo "  Splunk BOTS v1-v3   https://github.com/splunk/botsv3  (full-scenario SOC data)"
echo "  CICIDS2017          https://www.unb.ca/cic/datasets/ids-2017.html  (network flow)"
echo "  abuse.ch feeds      https://abuse.ch/  (indicator reputation — see 'just intel')"
echo
echo "Done. Normalising these into Bishop's alert schema is not automated;"
echo "src/bishop/schema/alert.py is the target shape."
