.
# CyberSentry — Architecture
 
## 1. Context
 
Security telemetry is high-volume, append-only and queried by time range and free text.
Incident state is low-volume, heavily relational and updated frequently. These are opposite
workloads, so CyberSentry uses two stores rather than forcing one to do both. M1 provisions
both and the pipeline between them; no model is trained yet.
 
## 2. Component Responsibilities
 - **log-collector** — Receives agent and syslog telemetry, validates it, publishes to sec.raw- **normalizer** — Maps vendor formats to a single event schema, enriches with asset and identity
  context- **detection-engine** — Applies the rule catalogue and behavioural models, emits detections- **correlation-agent** — Groups related detections into incidents by entity and time window- **response-agent** — Executes or proposes containment playbooks and records every action
 
## 3. Data Flow
 
1. `log-collector` accepts telemetry over HTTP and syslog, validates the envelope and
   publishes to `sec.raw` keyed by `host_id`.
2. `normalizer` maps each vendor format to the common event schema, enriches with asset and
   identity context, indexes into OpenSearch and republishes to `sec.normalized`.
3. `detection-engine` evaluates the rule catalogue, writes a `detections` row per match with
   its ATT&CK technique, and publishes to `sec.detections`.
4. `correlation-agent` groups detections sharing an entity within the correlation window into
   an `incidents` row, appending each detection to the incident's chain.
5. `response-agent` selects a playbook, records every proposed and executed action, and
   requires approval for any destructive step.
 
## 4. Non-Functional Targets
 - Detection and incident state survive a broker restart; raw telemetry replay is bounded- Every detection carries the rule version and the ATT&CK technique that justified it- Destructive response actions are never auto-executed without a recorded approval- Analyst-visible entity identifiers are pseudonymised in exports and model artefacts