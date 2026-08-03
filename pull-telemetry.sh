#!/usr/bin/env bash
# Pull the captured JSONL telemetry off the http-bait host into ./data/logs
# locally.
#
# The service is appending to that file as this runs, so the last line of the
# copy is routinely truncated. analyze.py skips and counts torn lines rather
# than aborting; do not "fix" a torn tail by hand.
#
# Usage: ./pull-telemetry.sh <host_ip>
set -euo pipefail
IP="${1:?usage: pull-telemetry.sh <droplet_ip>}"
KEY="${SSH_KEY:-$HOME/.ssh/id_honeypot}"
DEST="$(cd "$(dirname "$0")" && pwd)/data/logs"
mkdir -p "$DEST"
rsync -az -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  "root@$IP:/opt/http-bait/data/logs/" "$DEST/"
echo ">> pulled to $DEST"
ls -la "$DEST"
