#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
SOURCE_IP="${SOURCE_IP:-192.168.0.14}"
SOURCE_MAC="${SOURCE_MAC:-AA:BB:CC:05}"
VENDOR="${VENDOR:-IoT Camera}"

for port in 21 22 23 53 80 443 554 1883 5000 8080 8443; do
  curl -s -X POST "${API_URL}/api/observe" \
    -H "Content-Type: application/json" \
    -d "{
      \"sourceIp\": \"${SOURCE_IP}\",
      \"sourceMac\": \"${SOURCE_MAC}\",
      \"vendor\": \"${VENDOR}\",
      \"destinationIp\": \"192.168.0.1\",
      \"destinationPort\": ${port},
      \"protocol\": \"TCP\",
      \"bytesOut\": 600,
      \"dnsQuery\": null
    }" > /dev/null
done

curl -s -X POST "${API_URL}/api/observe" \
  -H "Content-Type: application/json" \
  -d "{
    \"sourceIp\": \"${SOURCE_IP}\",
    \"sourceMac\": \"${SOURCE_MAC}\",
    \"vendor\": \"${VENDOR}\",
    \"destinationIp\": \"8.8.8.8\",
    \"destinationPort\": 53,
    \"protocol\": \"UDP\",
    \"bytesOut\": 250,
    \"dnsQuery\": \"camera-feed.webhook.site\"
  }" > /dev/null

curl -s -X POST "${API_URL}/api/observe" \
  -H "Content-Type: application/json" \
  -d "{
    \"sourceIp\": \"${SOURCE_IP}\",
    \"sourceMac\": \"${SOURCE_MAC}\",
    \"vendor\": \"${VENDOR}\",
    \"destinationIp\": \"34.117.59.81\",
    \"destinationPort\": 443,
    \"protocol\": \"TLS\",
    \"bytesOut\": 2500000,
    \"dnsQuery\": null
  }" > /dev/null

curl -s "${API_URL}/api/events"
