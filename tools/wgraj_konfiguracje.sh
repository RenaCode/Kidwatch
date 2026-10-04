#!/usr/bin/env bash
# Wgrywa prawdziwa konfiguracje klastra do Sekretu kidwatch-config i restartuje
# poda. Konfiguracja NIE jest w repo (repo jest publiczne) — lezy lokalnie
# w config.cluster.yaml (w .gitignore).
#
# Uzycie:  tools/wgraj_konfiguracje.sh [plik] [host-ssh]
#   domyslnie: config.cluster.yaml, renacode
#
# Plik jest najpierw walidowany lokalnie tym samym kodem co w podzie — zly
# config nie trafia do klastra, wiec nie zatrzyma dzialajacego poda.
set -euo pipefail

PLIK="${1:-config.cluster.yaml}"
HOST="${2:-renacode}"
cd "$(dirname "$0")/.."

[ -f "$PLIK" ] || { echo "nie ma pliku $PLIK — skopiuj charts/kidwatch/files/config.yaml i uzupelnij" >&2; exit 2; }

# Walidacja bez sekretow: klucze API nie sa potrzebne do sprawdzenia struktury.
NEXTDNS_API_KEY=x BRAMKA_KLUCZ=x NTFY_TOPIC=x uv run python - "$PLIK" <<'PY'
import sys
from kidwatch.config import Config
cfg = Config.model_validate(__import__("yaml").safe_load(open(sys.argv[1], encoding="utf-8")))
print("config OK:", [d.display_name for d in cfg.devices])
PY

ssh "$HOST" 'sudo kubectl -n default create secret generic kidwatch-config \
  --from-file=config.yaml=/dev/stdin --dry-run=client -o yaml | sudo kubectl apply -f -' < "$PLIK"

# Sekret montowany przez subPath nie odswieza sie w dzialajacym podzie.
if ssh "$HOST" 'sudo kubectl -n default get deploy kidwatch' >/dev/null 2>&1; then
  ssh "$HOST" 'sudo kubectl -n default rollout restart deploy/kidwatch'
else
  echo "deployment kidwatch jeszcze nie istnieje — konfiguracja czeka w Sekrecie"
fi
