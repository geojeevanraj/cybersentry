# CyberSentry — Autonomous SOC & Threat Detection Platform
 
CyberSentry is an agentic security operations platform. Telemetry becomes normalised events, events
  become detections mapped to MITRE ATT&CK techniques, and detections are correlated into a small
    number of incidents an analyst can actually work.
 
## Problem Statement
 
A mid-size SOC generates tens of thousands of alerts a day and closes most of them as noise.
The bottleneck is not detection but correlation: the same intrusion produces a dozen alerts
across endpoint, proxy and identity logs, and an analyst re-derives the connection by hand
every time. CyberSentry makes correlation a first-class, deterministic stage — entity-based
grouping inside a bounded time window — so the analyst receives one incident with its full
detection chain rather than twelve independent alerts.
 
## Architecture (M1 baseline)
 
```
 endpoint / network / cloud telemetry
        |
        v
 [log-collector] --(sec.raw)--> [normalizer] --(sec.normalized)--> OpenSearch
                                                   |
                                                   v
                                          [detection-engine]
                                            rule catalogue + models
                                                   |
                                             (sec.detections)
                                                   |
                                                   v
                                         [correlation-agent]
                                          entity + time window
                                                   |
                                         PostgreSQL: incidents
                                                   |
                                                   v
                                          [response-agent] --> analyst
```
 
## Milestones
 
| Milestone | Focus |
|-----------|-------|
| M1 | Architecture, streaming and search infrastructure, detection schema |
| M2 | Anomaly detection and behavioural model training on normalised events |
| M3 | Detection engine with rule and model blending, ATT&CK mapping |
| M4 | Agentic triage and threat-hunting copilot with playbook reasoning |
| M5 | SOC console with incident timeline and entity graph |
| M6 | Deployment, detection-as-code CI and model drift monitoring |
 
## Quick Start
 
```bash
cp .env.example .env
make up          # start the full infrastructure stack
make db-init     # apply schema (auto-applied on first boot)
make seed        # load reference + demo data
make verify      # M1 acceptance checks
```
 
## Repository Layout
 - `libs/sentry_domain/` — pure severity and correlation logic- `services/` — one container per agent- `scripts/` — schema, topic and index creation, dataset ETL, seeding, verification- `config/` — topics, detection rules and the OpenSearch index template- `docs/adr/` — architecture decision records
 
## Tech Stack
 - **Kafka** — Telemetry event bus — raw, normalised and detection topics- **Zookeeper** — Kafka coordination (single-node dev mode)- **OpenSearch** — Full-text and time-range search over normalised events- **PostgreSQL** — Assets, rules, incidents and response actions — the case state- **Redis** — Deduplication windows and enrichment cache- **MLflow** — Anomaly and classification model tracking from M2
 
## License
 
MIT