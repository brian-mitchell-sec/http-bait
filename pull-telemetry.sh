#!/usr/bin/env bash
# Pull the captured JSONL telemetry off the http-bait droplet into ./data/logs
# locally. Mirrors ../deploy/pull-telemetry.sh for this standalone service.
# Usage: http-bait/pull-telemetry.sh <droplet_ip>
set -euo pipefail
IP="${1:?usage: pull-telemetry.sh <droplet_ip>}"
KEY="${SSH_KEY:-$HOME/.ssh/id_honeypot}"
DEST="$(cd "$(dirname "$0")" && pwd)/data/logs"
mkdir -p "$DEST"
rsync -az -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  "root@$IP:/opt/http-bait/data/logs/" "$DEST/"
echo ">> pulled to $DEST"
ls -la "$DEST"
