#!/bin/bash
set -e

echo "Starting vulnerable applications..."
docker-compose -f docker/docker-compose.vulnerable-targets.yml up -d

echo "Waiting for applications to be healthy..."
timeout 300 bash -c '
while true; do
    if docker-compose -f docker/docker-compose.vulnerable-targets.yml ps | grep -q "unhealthy"; then
        echo "Waiting for services to become healthy..."
        sleep 5
    else
        break
    fi
done
'

echo "Verifying services..."
curl -f http://localhost:8080/WebGoat/login || exit 1
curl -f http://localhost:8081/ || exit 1
curl -f http://localhost:3000/ || exit 1
curl -f http://localhost:8090/ || exit 1

echo "✓ All vulnerable applications are ready!"
echo "  - WebGoat: http://localhost:8080/WebGoat"
echo "  - DVWA: http://localhost:8081"
echo "  - Juice Shop: http://localhost:3000"
echo "  - ZAP: http://localhost:8090"
