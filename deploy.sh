#!/bin/bash
# ============================================================================
# AgentGuard Deployment Script v5.0 (Production-Ready)
# ============================================================================
# Usage:
#   ./deploy.sh              # Déploiement standard
#   ./deploy.sh --no-backup  # Sans backup DB
#   ./deploy.sh --dry-run    # Simulation uniquement
# ============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_NAME="agentguard"
readonly HEALTH_TIMEOUT=60      # secondes max pour health check
readonly HEALTH_RETRY_INTERVAL=3
readonly BACKUP_DIR="${SCRIPT_DIR}/backups"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Flags
DRY_RUN=false
NO_BACKUP=false

# ── Fonctions utilitaires ─────────────────────────────────────────────────────
log() { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC}  $*" >&2; }
die() { err "$*"; exit 1; }

usage() {
    cat <<EOF
AgentGuard Deployment Script

Usage: $0 [OPTIONS]

Options:
  --no-backup    Skip database backup before deployment
  --dry-run      Simulate deployment without making changes
  -h, --help     Show this help

Examples:
  $0                    # Deploy with backup
  $0 --no-backup        # Quick deploy without backup
  $0 --dry-run          # Show what would be done
EOF
    exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-backup) NO_BACKUP=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)   usage ;;
        *)           die "Option inconnue: $1" ;;
    esac
done

# ── Vérification des prérequis ────────────────────────────────────────────────
check_prereqs() {
    log "Vérification des prérequis..."
    local missing=()
    
    command -v docker >/dev/null || missing+=("docker")
    command -v python3 >/dev/null || missing+=("python3")
    
    # Vérifie docker compose (v2 plugin) ou docker-compose (v1 standalone)
    if ! docker compose version >/dev/null 2>&1; then
        if ! command -v docker-compose >/dev/null; then
            missing+=("docker compose")
        fi
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Outils manquants: ${missing[*]}"
    fi
    
    # Vérifie que docker daemon tourne
    if ! docker info >/dev/null 2>&1; then
        die "Le daemon Docker n'est pas accessible"
    fi
    
    ok "Prérequis OK"
}

# ── Chargement et validation du .env ──────────────────────────────────────────
load_env() {
    log "Chargement de l'environnement..."
    
    if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
        if [[ -f "${SCRIPT_DIR}/env.example" ]]; then
            warn ".env manquant — copie de env.example"
            cp "${SCRIPT_DIR}/env.example" "${SCRIPT_DIR}/.env"
            die "Configure ${SCRIPT_DIR}/.env puis relance le script"
        else
            die "Fichier .env introuvable"
        fi
    fi
    
    # Charge .env
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
    
    # Validation des variables critiques
    local errors=0
    
    if [[ -z "${AGENTGUARD_API_KEY:-}" ]]; then
        err "AGENTGUARD_API_KEY non définie dans .env"
        err "Génère-la avec : python3 -c \"import secrets; print('ag-' + secrets.token_urlsafe(32))\""
        errors=1
    fi
    
    if [[ -z "${AGENTGUARD_FLASK_SECRET:-}" ]]; then
        warn "AGENTGUARD_FLASK_SECRET non définie — sessions invalidées à chaque restart"
    fi
    
    if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
        warn "POSTGRES_PASSWORD non définie — utilise une valeur par défaut non sécurisée"
    fi
    
    if [[ "${AGENTGUARD_DB_TYPE:-sqlite}" == "postgres" && -z "${DATABASE_URL:-}" ]]; then
        err "DB_TYPE=postgres mais DATABASE_URL non défini"
        errors=1
    fi
    
    [[ $errors -eq 1 ]] && die "Variables d'environnement invalides"
    
    ok "Environnement chargé"
}

# ── Backup DB ─────────────────────────────────────────────────────────────────
backup_database() {
    if [[ "$NO_BACKUP" == "true" ]]; then
        warn "Backup ignoré (--no-backup)"
        return
    fi
    
    if [[ "${AGENTGUARD_DB_TYPE:-sqlite}" != "postgres" ]]; then
        log "DB SQLite — backup via volume (pas de dump nécessaire)"
        return
    fi
    
    log "Backup de la base PostgreSQL..."
    mkdir -p "$BACKUP_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/agentguard_${timestamp}.sql.gz"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Commande qui serait exécutée :"
        log "  docker compose exec -T postgres pg_dump -U agentguard agentguard | gzip > ${backup_file}"
        return
    fi
    
    # Attend que postgres soit up
    if ! docker compose ps postgres | grep -q "Up"; then
        warn "Postgres pas encore up — premier déploiement ?"
        return
    fi
    
    if docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-agentguard}" "${POSTGRES_DB:-agentguard}" \
        | gzip > "$backup_file"; then
        ok "Backup créé: ${backup_file} ($(du -h "$backup_file" | cut -f1))"
        
        # Nettoyage des anciens backups (garde les 10 derniers)
        cd "$BACKUP_DIR"
        ls -t agentguard_*.sql.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
        cd - > /dev/null
    else
        warn "Backup échoué — déploiement continue quand même"
        rm -f "$backup_file"
    fi
}

# ── Build & Deploy ────────────────────────────────────────────────────────────
deploy() {
    log "Build de l'image Docker..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] docker compose build"
    else
        docker compose build
        ok "Image buildée"
    fi
    
    log "Démarrage des services..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] docker compose up -d"
        return
    fi
    
    docker compose up -d
    ok "Services démarrés"
}

# ── Health Check avec retry ───────────────────────────────────────────────────
wait_for_health() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Attente health check..."
        return
    fi
    
    log "Attente du health check (max ${HEALTH_TIMEOUT}s)..."
    local start=$SECONDS
    local attempt=0
    
    while (( SECONDS - start < HEALTH_TIMEOUT )); do
        attempt=$((attempt + 1))
        
        # Check Docker health status
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' "${PROJECT_NAME}-collector-1" 2>/dev/null || echo "unknown")
        
        if [[ "$health" == "healthy" ]]; then
            ok "Service healthy après ${attempt} tentatives ($((SECONDS - start))s)"
            return 0
        fi
        
        # Check HTTP health si pas de healthcheck docker
        if [[ "$health" == "unknown" ]]; then
            if curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then
                ok "Service répond après ${attempt} tentatives ($((SECONDS - start))s)"
                return 0
            fi
        fi
        
        printf "."
        sleep "$HEALTH_RETRY_INTERVAL"
    done
    
    echo ""
    err "Timeout: le service n'est pas healthy après ${HEALTH_TIMEOUT}s"
    err "Logs du conteneur :"
    docker compose logs --tail=50 collector
    die "Déploiement échoué — vérifie les logs ci-dessus"
}

# ── Post-deploy ───────────────────────────────────────────────────────────────
post_deploy() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Déploiement AgentGuard terminé avec succès !${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🌐 ${GREEN}Dashboard${NC}:  http://localhost:8080"
    echo -e "   → Utilise ta clé API (${YELLOW}AGENTGUARD_API_KEY${NC}) pour te connecter"
    echo -e "   → ${RED}Ne mets JAMAIS la clé dans l'URL${NC} (fuite dans les logs)"
    echo ""
    echo -e "📡 ${GREEN}Health${NC}:    http://localhost:8080/healthz"
    echo -e "📚 ${GREEN}Logs${NC}:      docker compose logs -f"
    echo -e "🛑 ${GREEN}Stop${NC}:      docker compose down"
    echo -e "🔄 ${GREEN}Restart${NC}:   docker compose restart"
    echo ""
    
    # Affiche un résumé des services
    echo -e "${CYAN}Statut des services :${NC}"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
        || docker compose ps
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║   🛡️  AgentGuard Deployment Script v5.0                  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    cd "$SCRIPT_DIR"
    
    check_prereqs
    load_env
    backup_database
    deploy
    wait_for_health
    post_deploy
}

# Rollback handler
trap 'err "Déploiement interrompu"; docker compose ps 2>/dev/null' ERR

main "$@"
