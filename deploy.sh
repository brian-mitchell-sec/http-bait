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
ROOT="$(cd "$(dirname "$0")" && pwd)"
SSH="ssh -i $KEY -o StrictHostKeyChecking=accept-new root@$IP"

echo ">> waiting for cloud-init (docker install) to finish on $IP"
until $SSH 'test -f /var/lib/cloud/honeypot-ready' 2>/dev/null; do sleep 5; echo "   ...still provisioning"; done

echo ">> setting Caddy server name to $HOST"
sed "s/http-bait.example.com/$HOST/" "$ROOT/Caddyfile" > "$ROOT/Caddyfile.deployed"

echo ">> setting HB_CANARY_BASE to https://$HOST"
sed "s#https://http-bait.example.com#https://$HOST#" "$ROOT/docker-compose.yml" > "$ROOT/docker-compose.deployed.yml"

echo ">> syncing repo to /opt/http-bait"
rsync -az --delete -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  --exclude 'data/' --exclude '.git/' --exclude 'Caddyfile.deployed' --exclude 'docker-compose.deployed.yml' \
  --exclude '__pycache__/' \
  --exclude 'FINDINGS.md' --exclude 'CONTENT_IDEAS.md' --exclude 'social/' \
  "$ROOT/" "root@$IP:/opt/http-bait/"
scp -i "$KEY" "$ROOT/Caddyfile.deployed" "root@$IP:/opt/http-bait/Caddyfile"
scp -i "$KEY" "$ROOT/docker-compose.deployed.yml" "root@$IP:/opt/http-bait/docker-compose.yml"

echo ">> bringing stack up"
$SSH 'cd /opt/http-bait && docker compose up -d --build'

echo ">> done. smoke check:"
$SSH "cd /opt/http-bait && docker compose ps"
