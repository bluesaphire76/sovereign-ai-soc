# AI SOC Safe Start/Stop Scripts v2

These scripts safely stop and start the configured AI SOC runtime without
deleting Docker volumes, images, containers, databases, semantic memory or
Wazuh/observability state.

## Files

- `stop-ai-soc.sh`: safe stop sequence
- `start-ai-soc.sh`: safe start sequence

## Permissions

From `~/lab/ai-soc-assistant/bin`:

```bash
chmod +x ./start-ai-soc.sh ./stop-ai-soc.sh
```

## Stop AI SOC

```bash
cd ~/lab/ai-soc-assistant/bin
./stop-ai-soc.sh
```

## Start AI SOC

```bash
cd ~/lab/ai-soc-assistant/bin
./start-ai-soc.sh
```

## What changed in v2

- Fixes the systemd service loop so `ai-soc-worker`, `ai-soc-frontend`, and `ai-soc-api` are checked individually.
- Stops `postgres-soc` as part of the full AI SOC shutdown.
- Keeps `arcane-edge-agent` untouched because it is not an AI SOC container.
- Records previously running matching containers under `~/.local/state/ai-soc/last-running-containers.txt`.
- Uses a lock file to avoid start/stop running at the same time.
- Uses `docker compose stop` for stop and `docker compose up -d` for start. No volumes are removed.

The scripts are host convenience wrappers. They are separate from the
role-governed Service Operations API and do not create Operation History
records.

## Safety guarantees

The scripts do not run:

```bash
docker compose down -v
docker system prune
docker volume rm
docker rm
docker rmi
```

They also do not prune Qdrant, Loki, Prometheus or Grafana volumes.

## Current environment defaults

Default project path:

```bash
~/lab/ai-soc-assistant
```

Override if needed:

```bash
AI_SOC_HOME=/custom/path ./stop-ai-soc.sh
AI_SOC_HOME=/custom/path ./start-ai-soc.sh
```

Default health checks:

```bash
AI_SOC_API_HEALTH_URL=http://127.0.0.1:8008/health
AI_SOC_FRONTEND_URL=http://127.0.0.1:3000
```

Override if your ports differ:

```bash
AI_SOC_API_HEALTH_URL=http://127.0.0.1:8008/health \
AI_SOC_FRONTEND_URL=http://127.0.0.1:3000 \
./start-ai-soc.sh
```
