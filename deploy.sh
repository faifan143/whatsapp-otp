#!/bin/bash
set -e

echo "🚀 WhatsApp OTP Service - Deployment Script"
echo "==========================================="

# Check requirements
if ! command -v docker &>/dev/null; then
  echo "❌ Docker not installed. Please install Docker first."
  exit 1
fi

if ! command -v docker-compose &>/dev/null; then
  echo "❌ Docker Compose not installed. Please install it first."
  exit 1
fi

# Create auth directory
mkdir -p wwebjs_auth
chmod 777 wwebjs_auth

# Cleanup old container
echo "📦 Stopping existing containers..."
docker-compose down || true

# Build and start
echo "🔨 Building Docker image..."
docker-compose build --no-cache

echo "🎯 Starting service..."
docker-compose up -d

# Wait for container
echo "⏳ Waiting for service to start..."
sleep 3

if docker ps | grep -q whatsapp-otp; then
  echo "✅ Service started successfully!"
  echo ""
  echo "📱 Check logs for QR code:"
  echo "  docker-compose logs -f"
  echo ""
  echo "🌐 Endpoints:"
  echo "  GET  http://localhost:3002/health"
  echo "  GET  http://localhost:3002/status"
  echo "  POST http://localhost:3002/send-otp"
  echo "  POST http://localhost:3002/send-message"
else
  echo "❌ Service failed to start. Check logs:"
  docker-compose logs
  exit 1
fi