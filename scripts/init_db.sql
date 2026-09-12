-- ============================================================-- CyberSentry — M1 schema-- ============================================================
 
CREATE EXTENSION IF NOT EXISTS pgcrypto;
 -- ============================================================-- ENVIRONMENT MODEL-- ============================================================
 
CREATE TABLE IF NOT EXISTS assets (
    asset_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         VARCHAR(80) UNIQUE NOT NULL,
    hostname        VARCHAR(160) NOT NULL,
    asset_type      VARCHAR(30) NOT NULL
                    CHECK (asset_type IN ('workstation','server','domain_controller',
                                          'cloud_instance','container','network_device')),
    os_family       VARCHAR(30),
    ip_address      INET,
    business_unit   VARCHAR(80),
    owner_email     VARCHAR(200),
    criticality     VARCHAR(10) NOT NULL DEFAULT 'medium'
                    CHECK (criticality IN ('low','medium','high','crown_jewel')),
    is_internet_facing BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
 
CREATE TABLE IF NOT EXISTS identities (
    identity_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_name       VARCHAR(120) UNIQUE NOT NULL,
    display_name    VARCHAR(200),
    identity_type   VARCHAR(20) NOT NULL DEFAULT 'user'
                    CHECK (identity_type IN ('user','service','machine','admin')),
    is_privileged   BOOLEAN NOT NULL DEFAULT FALSE,
    department      VARCHAR(80),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);
 -- ============================================================-- DETECTION CATALOGUE-- ============================================================
 
CREATE TABLE IF NOT EXISTS attack_tactics (
 tactic_id       VARCHAR(20) PRIMARY KEY,      -- TA0006
    tactic_slug     VARCHAR(60) UNIQUE NOT NULL,  -- credential-access
    tactic_name     VARCHAR(120) NOT NULL
);
 
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id    VARCHAR(20) PRIMARY KEY,      -- T1003.001
    technique_name  VARCHAR(200) NOT NULL,
    tactic_id       VARCHAR(20) REFERENCES attack_tactics(tactic_id),
    parent_technique VARCHAR(20) REFERENCES attack_techniques(technique_id),
    description     TEXT
);
CREATE INDEX IF NOT EXISTS idx_technique_tactic ON attack_techniques(tactic_id);
 
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_code       VARCHAR(40) NOT NULL,
    version         INT NOT NULL,
    title           VARCHAR(200) NOT NULL,
    technique_id    VARCHAR(20) REFERENCES attack_techniques(technique_id),
    base_severity   VARCHAR(10) NOT NULL
                    CHECK (base_severity IN ('info','low','medium','high','critical')),
    params          JSONB NOT NULL DEFAULT '{}',
    query_dsl       TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    author          VARCHAR(120),
    effective_from  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rule_code, version)
);
 -- ============================================================-- CASE LAYER-- ============================================================
 
CREATE TABLE IF NOT EXISTS detections (
    detection_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_code       VARCHAR(40) NOT NULL,
    rule_version    INT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL,
    asset_id        UUID REFERENCES assets(asset_id) ON DELETE SET NULL,
    identity_id     UUID REFERENCES identities(identity_id) ON DELETE SET NULL,
    source_ip       INET,
    destination_ip  INET,
    process_guid    VARCHAR(80),
    severity        VARCHAR(10) NOT NULL
  CHECK (severity IN ('info','low','medium','high','critical')),
    risk_score      INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    dedup_key       VARCHAR(200) NOT NULL,
    evidence_index  VARCHAR(80),        -- OpenSearch index name
    evidence_doc_id VARCHAR(120),       -- OpenSearch _id
    detail          JSONB NOT NULL DEFAULT '{}',
    model_score     DOUBLE PRECISION,   -- NULL until the M2 model exists
    FOREIGN KEY (rule_code, rule_version) REFERENCES detection_rules(rule_code, version),
    UNIQUE (dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_asset ON detections(asset_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity, detected_at DESC);
 
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(24) UNIQUE NOT NULL,
    title           VARCHAR(300) NOT NULL,
    primary_entity  VARCHAR(200) NOT NULL,   -- host_id, user_name or source_ip
    entity_type     VARCHAR(20) NOT NULL
                    CHECK (entity_type IN ('host','identity','source_ip','process')),
    severity        VARCHAR(10) NOT NULL
                    CHECK (severity IN ('info','low','medium','high','critical')),
    risk_score      INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    status          VARCHAR(24) NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new','triaging','contained','eradicated',
                                      'closed_true_positive','closed_false_positive')),
    assigned_to     VARCHAR(120),
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at       TIMESTAMPTZ,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    CHECK (window_end >= window_start)
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents(primary_entity, window_start DESC);
 
CREATE TABLE IF NOT EXISTS incident_detections (
    incident_id     UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    detection_id    UUID NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    chain_position  INT NOT NULL,
    PRIMARY KEY (incident_id, detection_id)
);
CREATE TABLE IF NOT EXISTS incident_notes (
    note_id         BIGSERIAL PRIMARY KEY,
    incident_id     UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    author          VARCHAR(120) NOT NULL,
    note_type       VARCHAR(20) NOT NULL DEFAULT 'comment'
                    CHECK (note_type IN ('comment','hypothesis','finding','closure')),
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
 
CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id     VARCHAR(40) PRIMARY KEY,
    title           VARCHAR(200) NOT NULL,
    trigger_technique VARCHAR(20) REFERENCES attack_techniques(technique_id),
    steps           JSONB NOT NULL DEFAULT '[]',
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE
);
 
CREATE TABLE IF NOT EXISTS response_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    playbook_id     VARCHAR(40) REFERENCES playbooks(playbook_id),
    action_type     VARCHAR(40) NOT NULL
                    CHECK (action_type IN ('isolate_host','disable_account','block_ip',
                                           'kill_process','collect_forensics','notify_owner')),
    target          VARCHAR(200) NOT NULL,
    is_destructive  BOOLEAN NOT NULL DEFAULT FALSE,
    status          VARCHAR(20) NOT NULL DEFAULT 'proposed'
                    CHECK (status IN ('proposed','approved','executing','succeeded','failed','rejected')
                      ),
    proposed_by     VARCHAR(120) NOT NULL,
    proposed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at     TIMESTAMPTZ,
    result_detail   JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions(incident_id, proposed_at);
 
CREATE TABLE IF NOT EXISTS action_approvals (
    approval_id     BIGSERIAL PRIMARY KEY,
    action_id       UUID NOT NULL REFERENCES response_actions(action_id) ON DELETE CASCADE,
    approver        VARCHAR(120) NOT NULL,
    decision        VARCHAR(10) NOT NULL CHECK (decision IN ('approve','reject')),
    reason          TEXT,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (action_id, approver)
);
 
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor           VARCHAR(120) NOT NULL,
    action          VARCHAR(50) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     VARCHAR(100) NOT NULL,
    detail          JSONB NOT NULL DEFAULT '{}'
);