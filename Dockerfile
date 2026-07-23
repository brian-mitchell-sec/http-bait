FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt
COPY app/ .

ENV HB_LOG_DIR=/data/logs PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8100

# No USER directive: the
# bind-mounted ./data volume is host-root-owned on the droplet, and a non-root
# UID here would need a matching chown step at deploy time to keep write
# access. cap_drop ALL + read_only rootfs + no-new-privileges (docker-compose.yml)
# already remove most of what root-in-container would otherwise buy an attacker.

# Single worker on purpose: keeps all telemetry in one ordered JSONL file
# --no-server-header: uvicorn's own "Server: uvicorn" header would otherwise be
# appended alongside the app's fake-version Server header (SPEC §4.3), leaking
# the real stack and defeating the bait.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1", "--no-access-log", "--no-server-header"]
