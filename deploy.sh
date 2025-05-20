#!/bin/bash

# deploy.sh - Script to build and deploy the WhatsApp OTP application using Docker and Docker Compose

# Exit on any error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print messages
log() {
    echo -e "${2:-$NC}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        log "Error: $1 is required but not installed." "$RED"
        exit 1
    fi
}

# Check for required tools
log "Checking for required tools..." "$YELLOW"
check_command docker
check_command docker-compose
log "All required tools are installed." "$GREEN"

# Variables
COMPOSE_FILE="docker-compose.yml"
APP_NAME="whatsapp-otp"
IMAGE_NAME="whatsapp-otp"
PORT="3002"

# Function to check if the container is running
check_container_status() {
    if docker ps -q -f name="$APP_NAME" | grep -q .; then
        log "Container $APP_NAME is already running." "$YELLOW"
        return 0
    else
        return 1
    fi
}

# Function to stop and remove existing container
cleanup() {
    log "Cleaning up existing container..." "$YELLOW"
    if check_container_status; then
        log "Stopping and removing container $APP_NAME..." "$YELLOW"
        docker-compose -f "$COMPOSE_FILE" down || {
            log "Failed to stop container." "$RED"
            exit 1
        }
    else
        log "No running container found for $APP_NAME." "$YELLOW"
    fi
}

# Function to build and deploy
deploy() {
    log "Building Docker image for $APP_NAME..." "$YELLOW"
    docker-compose -f "$COMPOSE_FILE" build || {
        log "Failed to build Docker image." "$RED"
        exit 1
    }

    log "Starting Docker container..." "$YELLOW"
    docker-compose -f "$COMPOSE_FILE" up -d || {
        log "Failed to start Docker container." "$RED"
        exit 1
    }
}

# Main deployment process
log "Starting deployment of $APP_NAME..." "$GREEN"

# Perform cleanup
cleanup

# Deploy the application
deploy

# Wait for the container to be healthy
log "Checking container status..." "$YELLOW"
for i in {1..30}; do
    if check_container_status; then
        log "Container $APP_NAME is running." "$GREEN"
        break
    fi
    log "Waiting for container to start... ($i/30)" "$YELLOW"
    sleep 2
done

if ! check_container_status; then
    log "Container failed to start within timeout." "$RED"
    docker-compose -f "$COMPOSE_FILE" logs
    exit 1
fi

# Verify the application is accessible
log "Verifying application health..." "$YELLOW"
sleep 5 # Give the app time to initialize
if curl -s -f "http://localhost:$PORT/health" > /dev/null; then
    log "Application is healthy and accessible at http://localhost:$PORT" "$GREEN"
else
    log "Failed to verify application health. Check container logs for details." "$RED"
    docker-compose -f "$COMPOSE_FILE" logs
    exit 1
fi

log "Deployment completed successfully!" "$GREEN"
log "You may need to scan the QR code from the container logs to authenticate WhatsApp." "$YELLOW"
log "View logs with: docker-compose logs -f" "$YELLOW"