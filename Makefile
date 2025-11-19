# -------- CONFIG --------
SHELL := /bin/bash
ENV_FILE := .env
ARGS ?=

# Python interpreter (override via `make PY=python3`)
PY := python

# Scripts
S_DEPLOY   := scripts/deploy.sh
S_REQUEST  := scripts/request_report.sh

.PHONY: help env chain deploy request don-up don-down clean install run add-mf link rm hash test

help:
	@echo "Make targets:"
	@echo "  make env       # create .env from .env.example if needed"
	@echo "  make deploy    # deploy TrustGraph and persist the address into .env"
	@echo "  make don-up    # start aggregator + oracle nodes in Docker"
	@echo "  make don-down  # stop the DON docker stack"
	@echo "  make request   # request a trust report via DON (uses scripts/request_report.sh)"
	@echo "  make clean     # remove generated logs/state"

env:
	@if [ ! -f $(ENV_FILE) ]; then cp .env.example $(ENV_FILE); echo "✅ Created .env (from .env.example)"; else echo "ℹ️  .env already exists"; fi

deploy:
	@bash $(S_DEPLOY)

request:
	@bash $(S_REQUEST) $(ARGS)

don-up:
	@docker compose up -d --build aggregator oracle_node oracle_moderna oracle_dhl

don-down:
	@docker compose down

clean:
	@rm -rf logs/*.json state/*.csv || true
	@echo "🧹 Cleaned generated logs/state"

install:
	python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

run:
	. .venv/bin/activate && python -m src.trustkb.cli --help

add-mf:
	. .venv/bin/activate && python -m src.trustkb.cli add-manufacturer Pfizer --score 0.95

link:
	. .venv/bin/activate && python -m src.trustkb.cli trust Pfizer McKesson

rm:
	. .venv/bin/activate && python -m src.trustkb.cli rm Pfizer

hash:
	. .venv/bin/activate && python -m src.trustkb.cli graph-hash

test:
	. .venv/bin/activate && pytest -q
