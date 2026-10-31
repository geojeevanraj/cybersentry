-- M2: one generic prediction table, shared by every model this project trains.-- The M1 nullable columns are filled FROM this table (step 2.11), so the raw-- predictions stay auditable even if the M1 join keys change later.
CREATE TABLE IF NOT EXISTS ml_predictions (
    entity_id      TEXT        NOT NULL,
    step           TEXT        NOT NULL,      -- cycle, timestamp, date or token span
    model_name     TEXT        NOT NULL,
    model_version  TEXT        NOT NULL,      -- registry name:version, e.g. my-model:v3
    score          DOUBLE PRECISION,
    label          TEXT,
    extra          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_id, step, model_name)
);
CREATE INDEX IF NOT EXISTS ix_ml_predictions_model ON ml_predictions (model_name, model_version);
