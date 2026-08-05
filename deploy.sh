#!/usr/bin/env bash
# Push http-bait to its own already-provisioned host and bring the stack up.
# Syncs this directory to /opt/http-bait. See DEPLOY.md for what the host
# needs beforehand (Docker, and a /var/lib/cloud/honeypot-ready marker).
# Usage: http-bait/deploy.sh <droplet_ip> <hostname>
#   <hostname> is the TLS server name Caddy serves (a domain you control, or an nip.io name).
set -euo pipefail

IP="${1:?usage: deploy.sh <droplet_ip> <hostname>}"
HOST="${2:?usage: deploy.sh <droplet_ip> <hostname>}"
KEY="${SSH_KEY:-$HOME/.ssh/id_honeypot}"
USER="${SSH_USER:-root}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $USER@$IP"
READY_TIMEOUT="${READY_TIMEOUT:-600}"

# Prove we can log in before waiting on anything, and say what failed if we
# cannot. The wait loop below treats "file not there yet" as normal, so without
# this an auth failure, a wrong address, or a host that is simply down all
# printed "still provisioning" forever.
echo ">> checking ssh to $USER@$IP"
if ! err=$($SSH true 2>&1); then
  echo "!! cannot ssh to $USER@$IP with key $KEY" >&2
  echo "   $err" >&2
  echo "   Set SSH_KEY to the right key, or SSH_USER if root login is disabled." >&2
  echo "   Most cloud images disable root ssh: try SSH_USER=ubuntu (AWS/Azure)," >&2
  echo "   SSH_USER=debian, or your provider's default account." >&2
  exit 1
fi

echo ">> waiting for cloud-init (docker install) to finish on $IP"
waited=0
until $SSH 'test -f /var/lib/cloud/honeypot-ready'; do
  if [ "$waited" -ge "$READY_TIMEOUT" ]; then
    echo "!! /var/lib/cloud/honeypot-ready still absent after ${READY_TIMEOUT}s" >&2
    echo "   ssh works, so the marker was never created. On the host run:" >&2
    echo "     mkdir -p /var/lib/cloud && touch /var/lib/cloud/honeypot-ready" >&2
    echo "   after confirming 'docker compose version' works there." >&2
    exit 1
  fi
  sleep 5; waited=$((waited + 5))
  echo "   ...still provisioning (${waited}s)"
done

echo ">> setting Caddy server name to $HOST"
sed "s/http-bait.example.com/$HOST/" "$ROOT/Caddyfile" > "$ROOT/Caddyfile.deployed"

echo ">> setting HB_CANARY_BASE to https://$HOST"
sed "s#https://http-bait.example.com#https://$HOST#" "$ROOT/docker-compose.yml" > "$ROOT/docker-compose.deployed.yml"

echo ">> syncing repo to /opt/http-bait"
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  --exclude 'data/' --exclude '.git/' --exclude 'Caddyfile.deployed' --exclude 'docker-compose.deployed.yml' \
  --exclude '__pycache__/' \
  --exclude 'FINDINGS.md' --exclude 'fixtures/' --exclude '.github/' \
  "$ROOT/" "$USER@$IP:/opt/http-bait/"
scp -i "$KEY" "$ROOT/Caddyfile.deployed" "$USER@$IP:/opt/http-bait/Caddyfile"
scp -i "$KEY" "$ROOT/docker-compose.deployed.yml" "$USER@$IP:/opt/http-bait/docker-compose.yml"

echo ">> bringing stack up"
$SSH 'cd /opt/http-bait && docker compose up -d --build'

echo ">> done. smoke check:"
$SSH "cd /opt/http-bait && docker compose ps"
