#!/usr/bin/env bash
set -euo pipefail

echo "📦 DEMO: deploy → eval → publish → check"
echo "⚠️ Poskrbi, da anvil teče v drugem terminalu (make chain)."

make deploy
make eval
make publish
make check

echo "🎉 Demo zaključen."
