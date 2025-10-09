# Trust Management Demo

This repository contains a small workflow for evaluating trust policies and publishing the results to an on-chain trust graph. The provided Make targets and shell scripts wrap the common steps so you can run local demos with a couple of commands.

## Prerequisites
- Python 3.9+ (with `pip`)
- Foundry toolchain (`anvil`, `forge`)  
  Install via `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- A local clone of this repository

## Setup
1. Create and activate a Python virtual environment (optional but recommended).
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a local environment file if you don't already have one:
   ```bash
   make env
   ```
   This copies `.env.example` to `.env`. Adjust any paths or configuration values as needed (RPC URL, ontology/policy paths, etc.).

## Project Structure
```
trust-management/
├─ .env.example
├─ Makefile
├─ scripts/
│  ├─ chain.sh        # starts anvil (local Ethereum test node)
│  ├─ deploy.sh       # deploys TrustGraph.sol and stores address in .env
│  ├─ eval.sh         # runs hybrid evaluation to produce CSV + logs
│  ├─ publish.sh      # pushes evaluation results on-chain
│  ├─ check.sh        # sample read from on-chain trust graph
│  └─ run_demo.sh     # convenience wrapper: deploy → eval → publish → check
├─ src/
│  ├─ run_hybrid_eval.py
│  ├─ write_results_onchain.py
│  └─ read_trustgraph.py
└─ …
```

If you use a different evaluation script than `src/run_hybrid_eval.py`, update `scripts/eval.sh` accordingly.

## Running the Demo
1. **Terminal A** – start the local chain:
   ```bash
   make chain
   ```
   Leave this running; it starts `anvil`.

2. **Terminal B** – run the full demo:
   ```bash
   make demo
   ```
   This executes `deploy → eval → publish → check` in order:
   - `make deploy`: Deploys `TrustGraph.sol` using Foundry and writes the contract address into `.env`.
   - `make eval`: Runs the hybrid evaluation script, generating CSV output under `results/` plus metadata logs.
   - `make publish`: Calls `src/write_results_onchain.py` to batch publish the evaluation results to the deployed contract.
   - `make check`: Invokes `src/read_trustgraph.py` for a sample trust query (e.g., Pfizer → DHL).

You can run each step individually if you prefer (use `make deploy`, `make eval`, etc.).

## Cleanup
To remove generated CSVs and log files, run:
```bash
make clean
```

## Troubleshooting
- Ensure `.env` has the correct `RPC_URL`, `PRIVATE_KEY`, and `CONTRACT_ADDRESS`. Re-run `make deploy` if you started a fresh `anvil` instance.
- If Foundry binaries (`forge`, `anvil`) are not found, make sure the Foundry installation directory is in your `PATH`.
- Replace the Python scripts referenced in `scripts/*.sh` with your own equivalents if your project structure differs. Keep the Make targets intact so the workflow remains a one-liner.
