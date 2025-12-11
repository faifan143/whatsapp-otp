#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
  echo -e "${2:-$NC}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

check_command() {
  if ! command -v "$1" &>/dev/null; then
    log "Error: $1 is required but not installed." "$RED"
    exit 1
  fi
}

COMPOSE_FILE="docker-compose.yml"
APP_NAME="whatsapp-otp"
PORT="3002"
HEALTH_URL="http://localhost:${PORT}/health"

log "Checking required tools..." "$YELLOW"
check_command docker
check_command docker-compose
check_command curl
log "All required tools are installed." "$GREEN"

# Ensure auth dir exists on host (for persistence)
if [ ! -d "./wwebjs_auth" ]; then
  log "Creating wwebjs_auth directory..." "$YELLOW"
  mkdir -p ./wwebjs_auth
  chmod 777 ./wwebjs_auth || true
fi

log "Deploying ${APP_NAME}..." "$GREEN"

log "Stopping existing stack..." "$YELLOW"
docker-compose -f "$COMPOSE_FILE" down || true

log "Building image..." "$YELLOW"
docker-compose -f "$COMPOSE_FILE" build --no-cache

log "Starting stack..." "$YELLOW"
docker-compose -f "$COMPOSE_FILE" up -d

log "Waiting for container to start..." "$YELLOW"
for i in {1..30}; do
  if docker ps -q -f name="$APP_NAME" | grep -q .; then
    log "Container ${APP_NAME} is running." "$GREEN"
    break
  fi
  sleep 2
done

if ! docker ps -q -f name="$APP_NAME" | grep -q .; then
  log "Container failed to start within timeout." "$RED"
  docker-compose -f "$COMPOSE_FILE" logs
  exit 1
fi

log "Checking HTTP health endpoint..." "$YELLOW"
for i in {1..30}; do
  if curl -s -f "$HEALTH_URL" >/dev/null; then
    log "Application is reachable at http://localhost:${PORT}" "$GREEN"
    curl -s "$HEALTH_URL" || true
    log "Deployment completed. If not authenticated, scan QR via logs:" "$YELLOW"
    log "docker-compose logs -f" "$YELLOW"
    exit 0
  fi
  sleep 2
done

log "Health endpoint did not become ready in time." "$RED"
docker-compose -f "$COMPOSE_FILE" logs
exit 1
