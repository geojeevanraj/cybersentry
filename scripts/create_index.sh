#!/usr/bin/env bash
set -euo pipefail
OS_URL=${OPENSEARCH_URL:-http://localhost:9200}
 
echo "applying index template..."
curl -sS -X PUT "$OS_URL/_index_template/sentry-events" \
  -H "Content-Type: application/json" \
  --data-binary @config/opensearch_index.json
 
echo "applying retention policy (${EVENT_RETENTION_DAYS:-30} days)..."
curl -sS -X PUT "$OS_URL/_plugins/_ism/policies/sentry-retention" \
  -H "Content-Type: application/json" -d "{
    \"policy\": {
      \"description\": \"delete telemetry indices after retention\",
      \"default_state\": \"hot\",
      \"states\": [
        {\"name\": \"hot\", \"transitions\": [
          {\"state_name\": \"delete\", \"conditions\": {
            \"min_index_age\": \"${EVENT_RETENTION_DAYS:-30}d\"}}]},
        {\"name\": \"delete\", \"actions\": [{\"delete\": {}}]}
      ]
    }}"
 
echo
echo "index template and ISM policy applied"