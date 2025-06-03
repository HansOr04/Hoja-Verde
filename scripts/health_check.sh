#!/bin/bash

# Health check para monitoreo
HEALTH_URL="${RENDER_EXTERNAL_URL:-http://localhost:8000}/health"

# Verificar que la aplicación responda
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL")

if [ "$HTTP_STATUS" = "200" ]; then
    echo "✅ Aplicación saludable (HTTP $HTTP_STATUS)"
    exit 0
else
    echo "❌ Aplicación no saludable (HTTP $HTTP_STATUS)"
    exit 1
fi