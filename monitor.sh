#!/bin/bash
# ============================================================================
# AgentGuard Monitoring Script v5.0
# ============================================================================
# Usage:
#   ./monitor.sh              # Monitoring interactif (refresh 5s)
#   ./monitor.sh --once       # Snapshot unique (pour cron)
#   ./monitor.sh --watch      # Mode watch (utilise `watch`)
#   ./monitor.sh --check      # Health check only (exit 0/1)
# ============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
readonly COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8080}"
readonly API_KEY="${AGENTGUARD_API_KEY:-}"
readonly REFRESH_INTERVAL="${REFRESH_INTERVAL:-5}"
readonly ALERT_THRESHOLD_BLOCKED=10     # % bloqués pour alerte
readonly ALERT_THRESHOLD_LATENCY=5000   # ms pour alerte latence

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Mode
MODE="interactive"
[[ "${1:-}" == "--once" ]] && MODE="once"
[[ "${1:-}" == "--watch" ]] && MODE="watch"
[[ "${1:-}" == "--check" ]] && MODE="check"
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && cat <<EOF && exit 0
AgentGuard Monitor

Usage: $0 [OPTIONS]

Options:
  --once      Single snapshot (useful for cron)
  --watch     Use system 'watch' command
  --check     Health check only (exit 0 if healthy, 1 otherwise)
  -h, --help  Show help

Environment:
  COLLECTOR_URL  URL of collector (default: http://localhost:8080)
  AGENTGUARD_API_KEY  API key for authentication
  REFRESH_INTERVAL    Seconds between refreshes (default: 5)

Examples:
  $0                          # Interactive monitoring
  $0 --once                   # One-shot (for cron: */5 * * * * ...)
  AGENTGUARD_API_KEY=ag-xxx $0 --check && echo OK
EOF

# ── Prérequis ─────────────────────────────────────────────────────────────────
check_tools() {
    local missing=()
    command -v curl >/dev/null || missing+=("curl")
    command -v jq >/dev/null || missing+=("jq")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "❌ Outils manquants: ${missing[*]}" >&2
        echo "   Installation: sudo apt install ${missing[*]}" >&2
        exit 1
    fi
}

# ── API helpers ───────────────────────────────────────────────────────────────
api_call() {
    local endpoint="$1"
    local url="${COLLECTOR_URL}${endpoint}"
    local headers=(-H "Accept: application/json")
    
    if [[ -n "$API_KEY" ]]; then
        headers+=(-H "X-API-Key: ${API_KEY}")
    fi
    
    curl -fsS "${headers[@]}" --max-time 5 "$url" 2>/dev/null
}

# ── Fetch metrics ─────────────────────────────────────────────────────────────
fetch_metrics() {
    local metrics traces detection
    metrics=$(api_call "/api/metrics" 2>/dev/null) || return 1
    traces=$(api_call "/api/traces" 2>/dev/null || echo "[]")
    detection=$(api_call "/api/detection/stats" 2>/dev/null || echo "{}")
    
    echo "$metrics" | jq --argjson traces "$traces" --argjson det "$detection" '{
        total_spans: .total_spans // 0,
        total_traces: .total_traces // 0,
        blocked: .blocked_operations // 0,
        cost: (.total_cost_usd // 0),
        avg_latency: (.avg_latency_ms // 0),
        avg_ml: (.avg_ml_score // 0),
        avg_llm: (.avg_llm_score // 0),
        llm_count: (.llm_judge_count // 0),
        risk: (.risk_distribution // {}),
        traces_count: ($traces | length),
        detection: $det
    }'
}

# ── System metrics ────────────────────────────────────────────────────────────
get_system_metrics() {
    local cpu load mem_used mem_total mem_pct
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        load=$(sysctl -n vm.loadavg | awk '{print $2}')
        mem_total=$(sysctl -n hw.memsize 2>/dev/null | awk '{printf "%.1f", $1/1073741824}')
        mem_used=$(vm_stat | awk '/Pages active/ {print $3}' | tr -d '.' | awk '{printf "%.1f", $1*4096/1073741824}')
    else
        # Linux
        load=$(awk '{print $1}' /proc/loadavg)
        mem_total=$(awk '/MemTotal/ {printf "%.1f", $2/1048576}' /proc/meminfo)
        mem_used=$(awk '/MemAvailable/ {avail=$2} /MemTotal/ {total=$2} END {printf "%.1f", (total-avail)/1048576}' /proc/meminfo)
    fi
    
    echo "{\"load\": $load, \"mem_used_gb\": $mem_used, \"mem_total_gb\": $mem_total}"
}

# ── Check services ────────────────────────────────────────────────────────────
check_services() {
    local status=()
    
    # Collector
    if curl -fsS "${COLLECTOR_URL}/healthz" >/dev/null 2>&1; then
        status+=("collector:${GREEN}UP${NC}")
    else
        status+=("collector:${RED}DOWN${NC}")
    fi
    
    # PostgreSQL (si docker)
    if command -v docker >/dev/null 2>&1; then
        local pg_status
        pg_status=$(docker inspect --format='{{.State.Status}}' agentguard-postgres-1 2>/dev/null || echo "unknown")
        if [[ "$pg_status" == "running" ]]; then
            status+=("postgres:${GREEN}UP${NC}")
        else
            status+=("postgres:${YELLOW}${pg_status}${NC}")
        fi
        
        # Redis
        local redis_status
        redis_status=$(docker inspect --format='{{.State.Status}}' agentguard-redis-1 2>/dev/null || echo "unknown")
        if [[ "$redis_status" == "running" ]]; then
            status+=("redis:${GREEN}UP${NC}")
        else
            status+=("redis:${YELLOW}${redis_status}${NC}")
        fi
    fi
    
    echo -n "${status[*]}"
}

# ── Alertes ───────────────────────────────────────────────────────────────────
generate_alerts() {
    local metrics="$1"
    local alerts=()
    
    local total blocked pct lat
    total=$(echo "$metrics" | jq -r '.total_spans')
    blocked=$(echo "$metrics" | jq -r '.blocked')
    lat=$(echo "$metrics" | jq -r '.avg_latency')
    
    if [[ "$total" -gt 0 ]]; then
        pct=$((blocked * 100 / total))
        if [[ "$pct" -gt "$ALERT_THRESHOLD_BLOCKED" ]]; then
            alerts+=("${RED}⚠️  Taux de blocage élevé: ${pct}%${NC}")
        fi
    fi
    
    if (( $(echo "$lat > $ALERT_THRESHOLD_LATENCY" | bc -l 2>/dev/null || echo 0) )); then
        alerts+=("${YELLOW}⚠️  Latence élevée: ${lat}ms${NC}")
    fi
    
    if [[ ${#alerts[@]} -gt 0 ]]; then
        printf '%s\n' "${alerts[@]}"
    fi
}

# ── Affichage ─────────────────────────────────────────────────────────────────
display() {
    local metrics sys services
    metrics=$(fetch_metrics) || {
        clear
        echo -e "${RED}═══════════════════════════════════════════════${NC}"
        echo -e "${RED}❌ Collector inaccessible: ${COLLECTOR_URL}${NC}"
        echo -e "${RED}═══════════════════════════════════════════════${NC}"
        echo ""
        echo "Vérifie que le service tourne :"
        echo "  docker compose ps"
        echo "  docker compose logs collector"
        return 1
    }
    
    sys=$(get_system_metrics 2>/dev/null || echo '{"load":0,"mem_used_gb":0,"mem_total_gb":0}')
    services=$(check_services)
    
    local total_spans blocked cost avg_lat llm_count
    total_spans=$(echo "$metrics" | jq -r '.total_spans')
    blocked=$(echo "$metrics" | jq -r '.blocked')
    cost=$(echo "$metrics" | jq -r '.cost')
    avg_lat=$(echo "$metrics" | jq -r '.avg_latency')
    llm_count=$(echo "$metrics" | jq -r '.llm_count')
    
    local block_rate
    if [[ "$total_spans" -gt 0 ]]; then
        block_rate=$(awk "BEGIN {printf \"%.2f\", ($blocked/$total_spans)*100}")
    else
        block_rate="0.00"
    fi
    
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   🛡️  AgentGuard Monitor  ·  $(date '+%H:%M:%S')${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Services
    echo -e "${BOLD}SERVICES${NC}"
    echo -e "  ${services}"
    echo ""
    
    # KPIs
    echo -e "${BOLD}KPIs${NC}"
    printf "  %-20s %s\n" "Spans totales:" "${BOLD}${total_spans}${NC}"
    printf "  %-20s %s\n" "Bloquées:" "${BOLD}${blocked}${NC} (${block_rate}%)"
    printf "  %-20s %s\n" "Coût total:" "${BOLD}\$${cost}${NC}"
    printf "  %-20s %s\n" "Latence moy:" "${BOLD}${avg_lat} ms${NC}"
    printf "  %-20s %s\n" "LLM Judge calls:" "${BOLD}${llm_count}${NC}"
    echo ""
    
    # Système
    echo -e "${BOLD}SYSTÈME${NC}"
    local load mem_used mem_total
    load=$(echo "$sys" | jq -r '.load')
    mem_used=$(echo "$sys" | jq -r '.mem_used_gb')
    mem_total=$(echo "$sys" | jq -r '.mem_total_gb')
    printf "  %-20s %s\n" "Load avg:" "${load}"
    printf "  %-20s %s / %s GB\n" "Mémoire:" "${mem_used}" "${mem_total}"
    echo ""
    
    # Alertes
    local alerts
    alerts=$(generate_alerts "$metrics")
    if [[ -n "$alerts" ]]; then
        echo -e "${BOLD}⚠️  ALERTES${NC}"
        echo -e "$alerts"
        echo ""
    fi
    
    echo -e "${DIM}Actualisation dans ${REFRESH_INTERVAL}s... (Ctrl+C pour quitter)${NC}"
}

# ── Health check (mode check) ────────────────────────────────────────────────
health_check() {
    local metrics
    if metrics=$(fetch_metrics); then
        local total blocked
        total=$(echo "$metrics" | jq -r '.total_spans // 0')
        blocked=$(echo "$metrics" | jq -r '.blocked // 0')
        echo "✓ AgentGuard healthy: ${total} spans, ${blocked} blocked"
        exit 0
    else
        echo "✗ AgentGuard unhealthy: collector unreachable" >&2
        exit 1
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    check_tools
    
    case "$MODE" in
        check)
            health_check
            ;;
        once)
            display
            ;;
        watch)
            if command -v watch >/dev/null; then
                watch -n "$REFRESH_INTERVAL" -c "$0 --once"
            else
                echo "❌ 'watch' non installé. Utilise --once ou mode interactif." >&2
                exit 1
            fi
            ;;
        interactive)
            trap 'echo -e "\n${DIM}Au revoir !${NC}"; exit 0' INT
            while true; do
                display || true
                sleep "$REFRESH_INTERVAL"
            done
            ;;
    esac
}

main "$@"
