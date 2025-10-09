# -------- CONFIG --------
SHELL := /bin/bash
ENV_FILE := .env

# Python virtualenv (opcijsko)
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
	@echo "  make env       # ustvari .env iz .env.example (če ne obstaja)"
	@echo "  make chain     # zžene anvil (lokalni node)"
	@echo "  make deploy    # deploya TrustGraph in zapiše naslov v .env"
	@echo "  make eval      # izvede hibridno evalvacijo (round0/round1) in shrani CSV"
	@echo "  make publish   # prebere CSV in zapiše rezultate na verigo (batch)"
	@echo "  make check     # primer branja iz verige (npr. Pfizer → DHL)"
	@echo "  make demo      # chain → deploy → eval → publish → check"
	@echo "  make clean     # počisti rezultate/loge (ne briše pogodbe)"

env:
	@if [ ! -f $(ENV_FILE) ]; then cp .env.example $(ENV_FILE); echo "✅ Ustvarjen .env (iz .env.example)"; else echo "ℹ️  .env že obstaja"; fi

chain:
	@bash $(S_CHAIN)

deploy:
	@bash $(S_DEPLOY)

# OPOMBA:
#  - Če nimaš src/run_hybrid_eval.py, zamenjaj v scripts/eval.sh klic za tvoj obstoječi eval skript
#    (ti ga že imaš v glavnem fajlu, ki generira CSV).
eval:
	@bash $(S_EVAL)

publish:
	@bash $(S_PUBLISH)

check:
	@bash $(S_CHECK)

demo:
	@bash $(S_DEMO)

clean:
	@rm -rf results/*.csv logs/*.json || true
	@echo "🧹 Počiščeno (results/, logs/)"
