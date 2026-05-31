#!/usr/bin/env bash
set -Eeuo pipefail

# Safe start script for AI SOC.
# It starts existing services/containers/compose stacks. It never removes data.

AI_SOC_HOME="${AI_SOC_HOME:-$HOME/lab/ai-soc-assistant}"
STATE_DIR="${AI_SOC_STATE_DIR:-$HOME/.local/state/ai-soc}"
LOG_DIR="$STATE_DIR/logs"
LOCK_FILE="$STATE_DIR/runtime.lock"
LAST_SERVICES_FILE="$STATE_DIR/last-active-services.txt"
LAST_CONTAINERS_FILE="$STATE_DIR/last-running-containers.txt"
API_HEALTH_URL="${AI_SOC_API_HEALTH_URL:-http://127.0.0.1:8008/health}"
FRONTEND_URL="${AI_SOC_FRONTEND_URL:-http://127.0.0.1:3000}"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/start-$(date +%Y%m%d-%H%M%S).log"

exec > >(tee -a "$LOG_FILE") 2>&1
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date '+%F %T')] [ERROR] Another AI SOC start/stop operation is already running. Lock: $LOCK_FILE"
  exit 1
fi

log()  { echo "[$(date '+%F %T')] $*"; }
warn() { echo "[$(date '+%F %T')] [WARN] $*"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

systemd_unit_exists() {
  local svc="${1%.service}.service"
  local load_state
  load_state="$(systemctl show -p LoadState --value "$svc" 2>/dev/null || true)"
  [[ -n "$load_state" && "$load_state" != "not-found" ]]
}

start_systemd_service() {
  local svc="$1"
  if ! have_cmd systemctl; then
    warn "systemctl not available; skipping $svc"
    return 0
  fi
  if systemd_unit_exists "$svc"; then
    if systemctl is-active --quiet "$svc"; then
      log "Service already active: $svc"
    else
      log "Starting service: $svc"
      sudo systemctl start "$svc"
    fi
  else
    warn "Service not found: $svc; skipping"
  fi
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" == "true" ]]
}

start_container_if_exists() {
  local name="$1"
  if container_exists "$name"; then
    if container_running "$name"; then
      log "Container already running: $name"
    else
      log "Starting container: $name"
      docker start "$name" >/dev/null
    fi
  fi
}

wait_container_running() {
  local name="$1"
  local seconds="${2:-60}"
  local i
  for ((i=1; i<=seconds; i++)); do
    if container_running "$name"; then
      log "Container is running: $name"
      return 0
    fi
    sleep 1
  done
  warn "Container did not report running within ${seconds}s: $name"
  return 0
}

wait_http() {
  local url="$1"
  local seconds="${2:-60}"
  local i
  if ! have_cmd curl; then
    warn "curl not available; cannot wait for $url"
    return 0
  fi
  for ((i=1; i<=seconds; i++)); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      log "HTTP check OK: $url"
      return 0
    fi
    sleep 1
  done
  warn "HTTP check not ready within ${seconds}s: $url"
  return 0
}

wait_tcp() {
  local host="$1"
  local port="$2"
  local seconds="${3:-60}"
  local i
  for ((i=1; i<=seconds; i++)); do
    if timeout 1 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1; then
      log "TCP check OK: $host:$port"
      return 0
    fi
    sleep 1
  done
  warn "TCP check not ready within ${seconds}s: $host:$port"
  return 0
}

compose_file_is_relevant() {
  local file="$1"
  grep -Eiq '(ai-soc|wazuh|suricata|grafana|prometheus|cadvisor|node-exporter|postgres-soc|qdrant|ollama)' "$file"
}

find_relevant_compose_files() {
  [[ -d "$AI_SOC_HOME" ]] || return 0
  find "$AI_SOC_HOME" -maxdepth 5 -type f \
    \( -name 'docker-compose.yml' -o -name 'docker-compose.yaml' -o -name 'compose.yml' -o -name 'compose.yaml' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \) \
    | sort \
    | while read -r file; do
        if compose_file_is_relevant "$file"; then
          echo "$file"
        fi
      done
}

start_compose_stack() {
  local file="$1"
  local dir
  dir="$(dirname "$file")"
  log "Starting Docker compose stack: $file"
  docker compose --project-directory "$dir" -f "$file" up -d
}

show_runtime_summary() {
  log "Runtime summary after start"
  if have_cmd docker && docker info >/dev/null 2>&1; then
    local matching
    matching="$(docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
      | awk 'NR==1 || $1 ~ /^(ai-soc-|single-node-wazuh\.|postgres-soc$|qdrant$|wazuh|suricata|grafana|prometheus|cadvisor|node-exporter)/')"
    echo
    if [[ -n "$matching" ]]; then
      echo "$matching"
    else
      echo "No matching AI SOC containers are running."
    fi
  fi
}

log "Starting AI SOC runtime"
log "Project directory: $AI_SOC_HOME"
log "Log file: $LOG_FILE"

if ! have_cmd docker; then
  warn "docker command not found; Docker containers cannot be started"
elif ! docker info >/dev/null 2>&1; then
  warn "Docker daemon is not reachable. If Docker is managed by systemd, start it first with: sudo systemctl start docker"
else
  # 1) Start compose stacks first. This is non-destructive and preserves volumes.
  mapfile -t COMPOSE_FILES < <(find_relevant_compose_files)
  if (( ${#COMPOSE_FILES[@]} > 0 )); then
    for file in "${COMPOSE_FILES[@]}"; do
      start_compose_stack "$file"
    done
  else
    warn "No relevant Docker compose files found under $AI_SOC_HOME"
  fi

  # 2) Start standalone containers in dependency order.
  ORDERED_START_CONTAINERS=(
    postgres-soc
    qdrant
    single-node-wazuh.indexer-1
    single-node-wazuh.manager-1
    single-node-wazuh.dashboard-1
    ai-soc-prometheus
    ai-soc-node-exporter
    ai-soc-cadvisor
    ai-soc-grafana
    ai-soc-suricata
    ai-soc-worker
    ai-soc-api
    ai-soc-frontend
  )

  for name in "${ORDERED_START_CONTAINERS[@]}"; do
    start_container_if_exists "$name"
  done

  # 3) Restore any matching container captured during the previous stop but not listed above.
  if [[ -f "$LAST_CONTAINERS_FILE" ]]; then
    while read -r name; do
      [[ -z "$name" ]] && continue
      start_container_if_exists "$name"
    done < "$LAST_CONTAINERS_FILE"
  fi

  wait_container_running postgres-soc 30
  wait_tcp 127.0.0.1 5432 45
  wait_container_running qdrant 30
  wait_container_running single-node-wazuh.indexer-1 90
  wait_container_running single-node-wazuh.manager-1 90
  wait_container_running single-node-wazuh.dashboard-1 90
fi

# 4) Start local model and application systemd services after storage/security dependencies.
start_systemd_service ollama
start_systemd_service ai-soc-api
wait_http "$API_HEALTH_URL" 75
start_systemd_service ai-soc-worker
start_systemd_service ai-soc-frontend
wait_http "$FRONTEND_URL" 75

# 5) Start local ingress last.
start_systemd_service nginx
start_systemd_service cloudflared

show_runtime_summary
log "AI SOC start sequence completed"
log "No Docker volumes/images were removed. No systemd service was disabled/enabled."
