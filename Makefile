.PHONY: up down logs ps db-init seed verify test lint clean reset

COMPOSE = docker compose -p cybersentry

up:                ## start the full stack
	$(COMPOSE) up -d --build
	@echo "stack up — run 'make ps' to check health"

down:              ## stop containers, keep volumes
	$(COMPOSE) down

reset:             ## stop and wipe all volumes
	$(COMPOSE) down -v

ps:                ## container health
	$(COMPOSE) ps

logs:              ## tail all logs
	$(COMPOSE) logs -f --tail=100

db-init:           ## re-apply schema (idempotent)
	docker compose exec -T postgres psql -U $${DB_USER} -d $${DB_NAME} -f /docker-entrypoint-initdb.d/01_init.sql

seed:              ## load reference + demo data
	python scripts/seed_db.py

data:              ## download raw datasets
	python scripts/download_datasets.py

verify:            ## M1 acceptance checks
	python scripts/verify_m1.py

test:              ## unit tests for the domain library
	pytest tests/ -v

lint:              ## format and lint
	black . && flake8 .

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} +

# ---- M2 targets (append to the M1 Makefile) ----
# '>' replaces TAB as the recipe prefix from here down, so this block survives copy-paste.
.RECIPEPREFIX = >
-include .env
export
PY   := PYTHONPATH=ml/src python
PKG  := cybersentry
PSQL := docker compose exec -T postgres psql -U $$POSTGRES_USER

mlflow-up:
> $(PSQL) -tc "SELECT 1 FROM pg_database WHERE datname='mlflow'" | grep -q 1 \
>   || $(PSQL) -c "CREATE DATABASE mlflow"
> docker compose exec -T minio sh -c \
>   "mc alias set l http://localhost:9000 $$MINIO_ROOT_USER $$MINIO_ROOT_PASSWORD \
>    && mc mb -p l/mlflow-artifacts" || true
> docker compose -f docker-compose.yml -f docker-compose.mlflow.yml up -d mlflow

migrate-m2:
> $(PSQL) -d $$POSTGRES_DB < db/migrations/002_m2_predictions.sql

extract:
> $(PY) -m $(PKG).split

test-m2:
> PYTHONPATH=ml/src pytest -q ml/tests/test_m2_leakage.py

baseline:
> $(PY) -m $(PKG).baseline

train:
> $(PY) -m $(PKG).train

hpo:
> $(PY) -m $(PKG).hpo --trials 30

evaluate:
> $(PY) -m $(PKG).evaluate

promote:
> $(PY) -m $(PKG).promote

writeback:
> $(PY) -m $(PKG).writeback

verify-m2:
> $(PY) scripts/verify_m2.py

m2: extract test-m2 train evaluate promote writeback verify-m2

.PHONY: mlflow-up migrate-m2 extract test-m2 baseline train hpo evaluate promote writeback verify-m2 m2
