# ZeroTrust Policy Advisor — orchestration
# Cold start:  make setup  ->  edit .env  ->  make db  ->  make demo  ->  make backend (+ make frontend)
SHELL := /bin/bash
PY    := backend/.venv/bin/python
PIP   := backend/.venv/bin/pip

.PHONY: help setup db auth-db seed seed-scale precompute precompute-ai demo backend frontend dev stop verify admin set-password send-reset

help:
	@echo "setup         create venv + install backend & frontend deps"
	@echo "db            apply db/schema.sql to \$$DATABASE_URL (psql, psycopg fallback)"
	@echo "seed          write the simulated tool exports (data/mock/*.json)"
	@echo "precompute    run the deterministic engine -> persist snapshot to Postgres"
	@echo "precompute-ai cache ranked actions + change decisions (add --explanations to warm all)"
	@echo "demo          seed + precompute + precompute-ai (full snapshot, demo-proof)"
	@echo "backend       run the FastAPI API on :8000"
	@echo "frontend      run the Next.js dashboard on :3000"
	@echo "dev           run backend + frontend together"
	@echo "stop          kill the dev servers"

setup:
	python3.12 -m venv backend/.venv || python3 -m venv backend/.venv
	$(PIP) install -q -U pip
	$(PIP) install -q -r backend/requirements.txt
	cd frontend && npm install --no-audit --no-fund
	@test -f .env || cp .env.example .env
	ln -sf ../.env frontend/.env   # Next reads env from its own dir; share the root .env
	@echo "==> setup done. Edit .env (DATABASE_URL + AUTH_SECRET required; ANTHROPIC_API_KEY/RESEND_API_KEY optional)."

db:
	set -a; . ./.env; set +a; \
	psql "$$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/schema.sql || $(PY) db/migrate.py
	$(MAKE) auth-db

auth-db:
	set -a; . ./.env; set +a; \
	psql "$$DATABASE_URL" --single-transaction -v ON_ERROR_STOP=1 -f db/auth_schema.sql

admin:
	cd frontend && node scripts/create-admin.mjs $(EMAIL)

set-password:   # make set-password EMAIL=you@x.com PASSWORD='secret'
	cd frontend && node scripts/create-admin.mjs $(EMAIL) $(PASSWORD)

send-reset:     # make send-reset EMAIL=you@x.com  (emails a set-password link; tests Resend)
	cd frontend && node scripts/send-reset.mjs $(EMAIL)

seed:
	$(PY) backend/scripts/seed_demo.py

seed-scale:   # make seed-scale N=1000  -> base demo + N synthetic assets (then `make precompute`)
	$(PY) backend/scripts/seed_scale.py $(N)

precompute:
	$(PY) backend/scripts/precompute.py

precompute-ai:
	$(PY) backend/scripts/precompute_ai.py

demo: seed precompute precompute-ai
	@echo "==> snapshot built + cached. Run 'make backend' and 'make frontend' (or 'make dev')."

backend:
	cd backend && .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

frontend:
	cd frontend && npm run dev

dev:
	@echo "starting backend (:8000) + frontend (:3000) — Ctrl-C to stop both"
	@( cd backend && .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 & echo $$! > /tmp/ztpa-api.pid ); \
	trap 'kill $$(cat /tmp/ztpa-api.pid) 2>/dev/null' EXIT; \
	cd frontend && npm run dev

verify:
	$(PY) backend/scripts/verify_engine.py

stop:
	-pkill -f "uvicorn app.main:app"
	-pkill -f "next dev"
