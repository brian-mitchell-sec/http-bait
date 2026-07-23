# Deploying

The honeypot only collects anything interesting when it is reachable from the open
internet. This is what that takes.

## What you need

- A host you are willing to point at the internet and, in the worst case, rebuild. Any
  small VPS works; $4–6/month is enough. **Do not run this alongside anything you care
  about** — the entire point is to attract people who attack things.
- Docker and Docker Compose on that host.
- A DNS name pointing at it. Use a hostname with no history and no association with
  anything else you run: a name that ties back to you mixes traffic populations and
  identifies the operator. An `nip.io` name works for a smoke test but its certificate
  hits the certificate-transparency logs immediately, which produces a burst of CT-scraper
  traffic that is easy to mistake for real discovery.
- Ports 80 and 443 free. Caddy binds both and provisions TLS itself.

## First deploy

`deploy.sh` waits for a `/var/lib/cloud/honeypot-ready` marker on the host before syncing,
so that provisioning cannot race the deploy. Create it once the host has Docker:

```bash
ssh root@<host> 'command -v docker && touch /var/lib/cloud/honeypot-ready'
```

Then, from a checkout:

```bash
./deploy.sh <host_ip> <hostname>
```

That rsyncs the repository to `/opt/http-bait`, rewrites the placeholder hostname in
`Caddyfile` and `docker-compose.yml`, and brings the stack up. `SSH_KEY` overrides the
default key path (`~/.ssh/id_honeypot`).

Collected telemetry under `data/` is excluded from the sync in both directions, so
redeploying never destroys data.

## Checking on it

```bash
ssh root@<host> 'cd /opt/http-bait && docker compose ps'
./pull-telemetry.sh <host_ip>
python analyze.py data/logs/http_events.jsonl
```

`docker compose ps` reports the app container as `healthy` only while telemetry is
actually being written — a full disk makes writes fail without stopping the service, and
that is the failure mode most likely to cost you a week of data. If it reports
`unhealthy`, check free space first.

## Before you point it at the internet

Read [SPEC.md §2](SPEC.md). The guardrails there are not stylistic.
