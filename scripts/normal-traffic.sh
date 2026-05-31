#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"

for i in $(seq 1 5); do
  curl -s -X POST "${API_URL}/api/observe" \
    -H "Content-Type: application/json" \
    -d "{
      \"sourceIp\": \"192.168.0.14\",
      \"sourceMac\": \"AA:BB:CC:05\",
      \"vendor\": \"IoT Camera\",
      \"destinationIp\": \"1.1.1.1\",
      \"destinationPort\": 443,
      \"protocol\": \"TLS\",
      \"bytesOut\": 12000,
      \"dnsQuery\": \"pool.ntp.org\"
    }" > /dev/null
done

curl -s "${API_URL}/api/events"
