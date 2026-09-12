# ADR-0001: Two stores: OpenSearch for telemetry, PostgreSQL for case state
 
**Status:** Accepted
**Date:** 2026-09-11
 
## Context
 
Telemetry search needs inverted indexes and time-partitioned shards. Incident
workflow needs transactions, foreign keys and frequent small updates. One engine
doing both does each badly.
 
## Decision
 
Normalised events are indexed in OpenSearch with daily indices and an ISM policy.
Assets, rules, detections, incidents and response actions live in PostgreSQL.
A detection row stores the OpenSearch document id, so drilling from incident to
raw evidence is one lookup.
 
## Consequences
 
+ Each store runs the workload it is designed for.
+ Telemetry retention is tuned independently of case retention.- Two systems to operate and keep consistent.- Cross-store joins must happen in the application layer.