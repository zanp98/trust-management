#!/usr/bin/env bash
set -euo pipefail

echo "📦 DEMO: deploy → eval → publish → check"
echo "⚠️ Ensure anvil is running in a separate terminal (make chain)."

make deploy
make eval
make publish
make check

echo "🎉 Demo finished."
