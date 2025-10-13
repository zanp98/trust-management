# -------- CONFIG --------
SHELL := /bin/bash
ENV_FILE := .env
ARGS ?=

# Python interpreter (override via `make PY=python3`)
PY := python

# Scripts
S_CHAIN   := scripts/chain.sh
S_DEPLOY  := scripts/deploy.sh
S_EVAL    := scripts/eval.sh
S_PUBLISH := scripts/publish.sh
S_CHECK   := scripts/check.sh
S_DEMO    := scripts/run_demo.sh

.PHONY: help env chain deploy eval publish check demo clean

help:
	@echo "Make targets:"
	@echo "  make env       # create .env from .env.example if needed"
	@echo "  make chain     # start anvil (local node)"
	@echo "  make deploy    # deploy TrustGraph and persist the address into .env"
	@echo "  make eval      # run the hybrid evaluation and export CSVs"
	@echo "  make publish   # read CSV and publish trust results on-chain"
	@echo "  make check     # query a sample trust decision from the chain"
	@echo "  make demo      # chain → deploy → eval → publish → check"
	@echo "  make clean     # remove generated CSV/log files"

env:
	@if [ ! -f $(ENV_FILE) ]; then cp .env.example $(ENV_FILE); echo "✅ Created .env (from .env.example)"; else echo "ℹ️  .env already exists"; fi

chain:
	@bash $(S_CHAIN)

deploy:
	@bash $(S_DEPLOY)

# Note:
#  - If you do not have src/run_hybrid_eval.py, swap the invocation in scripts/eval.sh with your custom evaluator.
eval:
	@bash $(S_EVAL) $(ARGS)

publish:
	@bash $(S_PUBLISH) $(ARGS)

check:
	@bash $(S_CHECK) $(ARGS)

demo:
	@bash $(S_DEMO)

clean:
	@rm -rf results/*.csv logs/*.json || true
	@echo "🧹 Cleaned (results/, logs/)"
