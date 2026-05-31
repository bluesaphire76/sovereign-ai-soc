#!/usr/bin/env bash
set -Eeuo pipefail

# Safe stop script for AI SOC.
# It stops services and containers only. It never removes Docker volumes, images or containers.

AI_SOC_HOME="${AI_SOC_HOME:-$HOME/lab/ai-soc-assistant}"
STATE_DIR="${AI_SOC_STATE_DIR:-$HOME/.local/state/ai-soc}"
LOG_DIR="$STATE_DIR/logs"
LOCK_FILE="$STATE_DIR/runtime.lock"
LAST_SERVICES_FILE="$STATE_DIR/last-active-services.txt"
LAST_CONTAINERS_FILE="$STATE_DIR/last-running-containers.txt"
LAST_STOP_FILE="$STATE_DIR/last-stop.env"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/stop-$(date +%Y%m%d-%H%M%S).log"

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

stop_systemd_services() {
  local svc
  for svc in "$@"; do
    if ! have_cmd systemctl; then
      warn "systemctl not available; skipping $svc"
      continue
    fi
    if systemd_unit_exists "$svc"; then
      if systemctl is-active --quiet "$svc"; then
        log "Stopping service: $svc"
        sudo systemctl stop "$svc"
      else
        log "Service already inactive: $svc"
      fi
    else
      warn "Service not found: $svc; skipping"
    fi
  done
}

record_active_services() {
  : > "$LAST_SERVICES_FILE"
  local svc
  for svc in "$@"; do
    if have_cmd systemctl && systemd_unit_exists "$svc" && systemctl is-active --quiet "$svc"; then
      echo "$svc" >> "$LAST_SERVICES_FILE"
    fi
  done
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" == "true" ]]
}

stop_container_if_running() {
  local name="$1"
  local timeout="${2:-60}"
  if container_exists "$name"; then
    if container_running "$name"; then
      log "Stopping container: $name"
      docker stop -t "$timeout" "$name" >/dev/null
    else
      log "Container already stopped: $name"
    fi
  fi
}

record_running_containers() {
  : > "$LAST_CONTAINERS_FILE"
  if ! have_cmd docker || ! docker info >/dev/null 2>&1; then
    warn "Docker is not available; cannot record running containers"
    return 0
  fi

  docker ps --format '{{.Names}}' \
    | grep -E '^(ai-soc-|single-node-wazuh\.|postgres-soc$|qdrant$|wazuh|suricata|grafana|prometheus|cadvisor|node-exporter)' \
    | sort > "$LAST_CONTAINERS_FILE" || true
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

stop_compose_stack() {
  local file="$1"
  local dir
  dir="$(dirname "$file")"
  log "Stopping Docker compose stack without removing volumes: $file"
  docker compose --project-directory "$dir" -f "$file" stop
}

show_runtime_summary() {
  log "Runtime summary after stop"
  if have_cmd docker && docker info >/dev/null 2>&1; then
    local remaining
    remaining="$(docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
      | awk 'NR==1 || $1 ~ /^(ai-soc-|single-node-wazuh\.|postgres-soc$|qdrant$|wazuh|suricata|grafana|prometheus|cadvisor|node-exporter)/')"
    if [[ -n "$remaining" ]]; then
      echo
      echo "$remaining"
    else
      echo
      echo "No matching AI SOC containers are running."
    fi
  fi
}

APP_SERVICES=(ai-soc-worker ai-soc-frontend ai-soc-api)
EDGE_SERVICES=(cloudflared nginx ollama)
ALL_SERVICES=("${APP_SERVICES[@]}" "${EDGE_SERVICES[@]}")

log "Stopping AI SOC runtime"
log "Project directory: $AI_SOC_HOME"
log "Log file: $LOG_FILE"

record_active_services "${ALL_SERVICES[@]}"
record_running_containers
cat > "$LAST_STOP_FILE" <<EOF
AI_SOC_HOME=$AI_SOC_HOME
LAST_STOP_AT=$(date --iso-8601=seconds)
LOG_FILE=$LOG_FILE
EOF
log "Runtime state recorded under: $STATE_DIR"

# 1) Stop application services first so they stop writing to DB/indexes.
stop_systemd_services "${APP_SERVICES[@]}"

# 2) Stop external ingress/model services next.
stop_systemd_services "${EDGE_SERVICES[@]}"

# 3) Stop relevant compose stacks safely: stop only, no volume/container removal.
if have_cmd docker && docker info >/dev/null 2>&1; then
  mapfile -t COMPOSE_FILES < <(find_relevant_compose_files)
  if (( ${#COMPOSE_FILES[@]} > 0 )); then
    for file in "${COMPOSE_FILES[@]}"; do
      stop_compose_stack "$file"
    done
  else
    warn "No relevant Docker compose files found under $AI_SOC_HOME"
  fi

  # 4) Stop standalone / previously-created AI SOC containers in safe reverse dependency order.
  log "Stopping remaining matching containers without deletion"
  ORDERED_STOP_CONTAINERS=(
    ai-soc-frontend
    ai-soc-api
    ai-soc-worker
    ai-soc-grafana
    ai-soc-prometheus
    ai-soc-cadvisor
    ai-soc-node-exporter
    ai-soc-suricata
    single-node-wazuh.dashboard-1
    single-node-wazuh.manager-1
    single-node-wazuh.indexer-1
    qdrant
    postgres-soc
  )

  for name in "${ORDERED_STOP_CONTAINERS[@]}"; do
    stop_container_if_running "$name" 70
  done

  # Stop any matching containers that were running but are not in the explicit order list.
  while read -r name; do
    [[ -z "$name" ]] && continue
    stop_container_if_running "$name" 70
  done < "$LAST_CONTAINERS_FILE"
else
  warn "Docker is not available; skipping Docker container stop"
fi

show_runtime_summary
log "AI SOC stop sequence completed"
log "No Docker volumes/images were removed. No systemd service was disabled."
