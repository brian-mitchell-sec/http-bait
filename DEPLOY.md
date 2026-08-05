# Deploying

The honeypot only collects anything interesting when it is reachable from the open
internet. This is what that takes.

## What you need

- A host you are willing to point at the internet and, in the worst case, rebuild. Any
  small VPS works; $4–6/month is enough. **Do not run this alongside anything you care
  about**, the entire point is to attract people who attack things.
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
python3 analyze.py data/logs/http_events.jsonl
```

`docker compose ps` reports the app container as `healthy` only while telemetry is
actually being written, a full disk makes writes fail without stopping the service, and
that is the failure mode most likely to cost you a week of data. If it reports
`unhealthy`, check free space first.

## Before you point it at the internet

Read [SPEC.md §2](SPEC.md). The guardrails there are not stylistic.

## After the first deploy

`docker compose ps` reporting healthy does not mean the honeypot is collecting.
The two most common first-deploy failures both leave a healthy-looking stack and
an empty log. Work through these in order before you trust anything.

### 1. Confirm it is reachable from outside

From a machine that is neither the honeypot nor your deploy box:

```bash
curl -sI https://<your-hostname>/.env
```

A hang or a connection refusal is almost always your provider's inbound firewall
on 80/443, not this software. AWS security groups, GCP VPC firewall rules, Azure
NSGs and Oracle security lists all block inbound by default. "Ports 80 and 443
free" in the requirements above means free on the host, and separately open in
your provider's firewall.

### 2. Confirm TLS actually provisioned

```bash
docker compose logs caddy | grep -i 'certificate obtained'
```

ACME fails if DNS has not propagated or port 80 is blocked, and Caddy keeps
running afterwards. The stack stays Up and collects nothing.

### 3. Confirm it is recording

```bash
./pull-telemetry.sh <host_ip>
python3 analyze.py 'data/logs/http_events*.jsonl'
```

You should see exactly your own smoke-test request. **Note your own address and
pass `--exclude-ip <your ip>` on every run from here on**, or your testing ends
up in your own findings.

### 4. Day one with no traffic is normal

First hits usually arrive within minutes to hours of the certificate being
issued, and most of the earliest ones are certificate-transparency log scrapers
rather than discovery. Treat a sub-minute time-to-first-hit as an artifact of how
the host was stood up. `FINDINGS.md` covers this in the caveats you should read
before quoting anything.

### 5. How to tell it stopped

`/healthz` returns `{"ok": false}` and a 503 when the writer is failing or the
disk is low, and the body deliberately carries no detail, because that endpoint
is reachable from the internet. The reason goes to the container log:

```bash
docker compose logs app | grep UNHEALTHY
```

### 6. Week four and beyond

Rotation renames the live file to `http_events.<stamp>.jsonl`. **Always analyze
with the glob**:

```bash
python3 analyze.py 'data/logs/http_events*.jsonl' --rescan
```

Passing the singular filename reads one segment and prints a smaller number with
no indication anything is missing. The analyzer warns when it spots rotated
siblings it was not given, but the glob is the habit to build.

`HB_LOG_MAX_BYTES` times `HB_LOG_KEEP_ROTATED` caps total log size, roughly 2.2GB
at the defaults. Setting `HB_LOG_KEEP_ROTATED=0` keeps everything, fills the
disk, and stops collection.

### Sizing

Running this is cheap. **Building it is not.** `deploy.sh` runs
`docker compose up -d --build` on the honeypot host, and the default
`caddy/Dockerfile` compiles Caddy from source with the JA4+ plugins, which pulls
`golang:1.25` (about 1.3GB) first. Budget roughly 2GB of free disk and 2GB of RAM
or swap for the build. On a 1GB VPS expect ten to fifteen minutes and treat
running out of memory as a live risk.

To skip the build entirely, use the fingerprint-free stack, which pulls a stock
Caddy image instead:

```bash
docker compose -f docker-compose.nofingerprint.yml up -d --build
```

That also avoids the FoxIO License 1.1 commercial-use restriction on JA4+. See
[NOTICE](NOTICE). The app records `ja4` and `ja4h` as empty strings and nothing
else changes; `analyze.py` never reads those fields.

### Before you point it at the internet

- Set `HB_OPERATOR_CONTACT` in `docker-compose.yml`. Without it,
  `/.well-known/security.txt` says no contact is configured, which is honest and
  not what you want on a service inviting people to report things.
- Set `HB_WINDOW_LABEL` to something meaningful for this collection window, and
  change it before you publish anything about the deployment.
- Read [DATA-HANDLING.md](DATA-HANDLING.md). You are about to become the
  custodian of a file of third-party network activity.
