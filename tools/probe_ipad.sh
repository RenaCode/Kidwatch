#!/usr/bin/env bash
# Zbiera z iPada probki sygnalow, na ktorych ma stanac monitorowanie na zywo.
#
# Po co: nie wiadomo z gory, jakie zdarzenia systemowe realnie przychodza z
# iPadOS przez lockdown. Zamiast zakladac, ze "blokada ekranu pewnie da sie
# wykryc", ten skrypt to SPRAWDZA i zapisuje dowod.
#
# Uzycie:
#   ./tools/probe_ipad.sh              # pelny przebieg
#   ./tools/probe_ipad.sh --raw        # bez zaciemniania danych osobowych
#   ./tools/probe_ipad.sh --seconds 40 # dluzsze probki strumieni
#
# Nie wymaga: MDM, nadzoru, Developer Mode, jailbreaka, wymazywania iPada.
# Wymaga: kabla PRZY PIERWSZYM uruchomieniu (potem dziala po Wi-Fi).

set -uo pipefail
# Celowo bez `set -e`: pojedyncza nieudana proba ma byc ZAPISANA jako wynik,
# a nie przerwac zbieranie. Brak danej probki to tez informacja.

export LC_ALL=C   # stabilne, porownywalne wyjscie niezaleznie od ustawien

SECONDS_SAMPLE=25
REDACT=1
# Petla `while` z jawnym `shift`, nie `for arg in "$@"` z shiftem w srodku:
# `for` iteruje po KOPII listy, wiec `--raw --seconds 40` ustawialo
# SECONDS_SAMPLE na literal "--seconds", a pozniejsze `[ -lt ]` wywalalo sie
# na "integer expression expected".
while [ $# -gt 0 ]; do
  case "$1" in
    --raw) REDACT=0; shift ;;
    --seconds) SECONDS_SAMPLE="${2:-25}"; shift 2 ;;
    --seconds=*) SECONDS_SAMPLE="${1#*=}"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "nieznany argument: $1" >&2; exit 2 ;;
  esac
done
case "$SECONDS_SAMPLE" in
  ''|*[!0-9]*) echo "--seconds musi byc liczba, dostalem: $SECONDS_SAMPLE" >&2; exit 2 ;;
esac

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${TMPDIR:-/tmp}/kidwatch-probe-$STAMP"
mkdir -p "$OUT"
SUMMARY="$OUT/PODSUMOWANIE.txt"

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
# pymobiledevice3 loguje z data, hostname i PID — do oczu uzytkownika ma isc
# sama tresc bledu.
msg()  { sed -E 's/^.*(ERROR|WARNING) +//' "$1" 2>/dev/null | tail -1; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m%s\033[0m\n' "$*"; }
bad()  { printf '  \033[31m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m%s\033[0m\n' "$*"; }

# ----------------------------------------------------------------- narzedzie
find_pmd() {
  if command -v pymobiledevice3 >/dev/null 2>&1; then
    command -v pymobiledevice3; return 0
  fi
  for c in "$HOME/.local/bin/pymobiledevice3" /opt/homebrew/bin/pymobiledevice3; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

say "1/8  Narzedzie pymobiledevice3"
PMD="$(find_pmd)" || {
  warn "nie znalazlem — instaluje przez uv (to potrwa minute)"
  if command -v uv >/dev/null 2>&1; then
    uv tool install --quiet pymobiledevice3 >/dev/null 2>&1
    PMD="$(find_pmd)" || { bad "instalacja nie udala sie. Zrob: uv tool install pymobiledevice3"; exit 1; }
  else
    bad "brak uv i brak pymobiledevice3. Zainstaluj: pip3 install --user pymobiledevice3"
    exit 1
  fi
}
ok "$PMD ($("$PMD" version 2>/dev/null || echo '?'))"

# ------------------------------------------------------------------- host
say "2/8  Czy ten Mac jest gotowy (doctor)"
"$PMD" doctor > "$OUT/01-doctor.txt" 2>&1
sed -n '1,25p' "$OUT/01-doctor.txt" | sed 's/^/  /'

# --------------------------------------------------------------- urzadzenia
say "3/8  Widoczne urzadzenia"
"$PMD" usbmux list > "$OUT/02-devices.json" 2>&1
"$PMD" usbmux list --network > "$OUT/03-devices-network.json" 2>&1
# grep -c wypisuje 0 I zwraca kod 1, wiec `|| echo 0` dawaloby DWA zera
USB_COUNT=$(grep -c '"Identifier"' "$OUT/02-devices.json" 2>/dev/null); USB_COUNT=${USB_COUNT:-0}
NET_COUNT=$(grep -c '"Identifier"' "$OUT/03-devices-network.json" 2>/dev/null); NET_COUNT=${NET_COUNT:-0}
info "przez USB lub Wi-Fi: $USB_COUNT"
info "tylko po Wi-Fi:      $NET_COUNT"

if [ "$USB_COUNT" -eq 0 ]; then
  bad "Nie widze zadnego urzadzenia."
  cat <<'HOWTO'

  Co zrobic:
    1. podlacz iPada kablem do tego Maca
    2. ODBLOKUJ iPada (bez tego lockdown milczy)
    3. na iPadzie stuknij "Zaufaj temu komputerowi" i podaj kod
    4. odpal ten skrypt ponownie

HOWTO
  exit 1
fi
ok "urzadzenie widoczne"

# ------------------------------------------------------------------ tozsamosc
say "4/8  Co to za urzadzenie"
# Bez rekordu parowania lockdown odda tylko czesc wartosci albo nic. To normalne
# na tym etapie — krok 5 to naprawi.
"$PMD" lockdown info > "$OUT/04-lockdown-info.json" 2>&1
for k in DeviceName ProductType ProductVersion BuildVersion; do
  v=$(python3 -c "
import json,sys
try:
    d=json.load(open('$OUT/04-lockdown-info.json'))
    print(d.get('$k','?'))
except Exception:
    print('?')
" 2>/dev/null)
  printf '  %-16s %s\n' "$k" "$v"
done

# ------------------------------------------------------------------ parowanie
say "5/8  Parowanie i dostep po Wi-Fi"

# Okno "Zaufaj temu komputerowi" pojawia sie na iPadzie DOPIERO w chwili, gdy
# komenda parowania dziala — i tylko gdy ekran jest odblokowany. Jedna proba
# prawie nigdy nie trafia w to okno, wiec ponawiamy i prowadzimy uzytkownika.
#
# Uwaga: "Zaufaj" zatwierdzone kiedys w Finderze NIE wystarczy. Finder trzyma
# swoj rekord w /var/db/lockdown (tylko dla root), a to narzedzie ma wlasny
# klucz hosta w ~/.pymobiledevice3 i potrzebuje wlasnego zaufania.
cat <<'HOWTO'
  WEZ IPADA DO REKI. Przez najblizsza minute:
    * trzymaj ekran ODBLOKOWANY (dotykaj, zeby nie zgasl)
    * gdy pojawi sie "Zaufaj temu komputerowi" — stuknij ZAUFAJ i podaj kod

  Podpowiedz: Ustawienia > Ekran i jasnosc > Autoblokada > Nigdy
  ulatwia sprawe. Mozesz to cofnac zaraz po sparowaniu.

HOWTO

PAIRED=0
for attempt in $(seq 1 20); do
  if "$PMD" lockdown pair > "$OUT/05-pair.txt" 2>&1; then
    PAIRED=1; ok "sparowane (proba $attempt)"; break
  fi
  REASON="$(msg "$OUT/05-pair.txt")"
  case "$REASON" in
    *"password protected"*|*"unlock"*) printf '  proba %2d/20: iPad zablokowany — odblokuj go\n' "$attempt" ;;
    *"UserDeniedPairing"*|*"denied"*)  bad "odmowiles zaufania na iPadzie. Odpal ponownie i stuknij ZAUFAJ."; exit 3 ;;
    *"PasswordProtected"*)             printf '  proba %2d/20: czekam na kod na iPadzie\n' "$attempt" ;;
    *)                                  printf '  proba %2d/20: %s\n' "$attempt" "$(echo "$REASON" | cut -c1-60)" ;;
  esac
  sleep 5
done

if [ "$PAIRED" -eq 0 ]; then
  bad "Nie udalo sie sparowac."
  cat <<'HOWTO'

  Sprawdz po kolei:
    * iPad byl ODBLOKOWANY przez caly czas?
    * pojawilo sie okno "Zaufaj temu komputerowi"? Jesli nie — odepnij i wepnij kabel
    * jesli kiedys stuknalismy "Nie ufaj": Ustawienia > Ogolne > Przenies lub
      wyzeruj iPada > Wyzeruj > Wyzeruj lokalizacje i prywatnosc, potem raz jeszcze

  Ostatnia deska ratunku, gdy Finder juz ufa temu Macowi — uzyj rekordu systemowego:
      sudo pymobiledevice3 lockdown pair
      sudo pymobiledevice3 lockdown wifi-connections on

HOWTO
  exit 4
fi

"$PMD" lockdown wifi-connections on > "$OUT/06-wifi-on.txt" 2>&1 \
  && ok "dostep po Wi-Fi WLACZONY — kabel nie bedzie juz potrzebny" \
  || warn "wifi-connections: $(msg "$OUT/06-wifi-on.txt")"

# --------------------------------------------------- 1. lista aplikacji
say "6/8  Lista zainstalowanych aplikacji"
if "$PMD" apps list > "$OUT/07-apps.json" 2>"$OUT/07-apps.err"; then
  N=$(python3 -c "
import json
try:
    d=json.load(open('$OUT/07-apps.json'))
    print(len(d) if isinstance(d,(list,dict)) else 0)
except Exception:
    print(0)
" 2>/dev/null)
  ok "pobrano: $N pozycji"
  python3 - "$OUT/07-apps.json" <<'PY' 2>/dev/null | sed 's/^/  /' | head -25
import json, sys
d = json.load(open(sys.argv[1]))
items = d.items() if isinstance(d, dict) else [(x.get('CFBundleIdentifier','?'), x) for x in d]
rows = []
for bid, meta in items:
    if not isinstance(meta, dict):
        continue
    # Interesuja nas aplikacje uzytkownika, nie systemowe.
    if meta.get('ApplicationType') not in (None, 'User'):
        continue
    rows.append((meta.get('CFBundleDisplayName') or meta.get('CFBundleName') or '?', bid))
print(f"probka aplikacji uzytkownika ({len(rows)}):")
for name, bid in sorted(rows)[:20]:
    print(f"  {name[:34]:34} {bid}")
PY
else
  bad "nie udalo sie: $(msg "$OUT/07-apps.err")"
fi

# --------------------------------------------------- 2. procesy
say "7/8  Procesy dzialajace na iPadzie"
if "$PMD" processes ps > "$OUT/08-processes.txt" 2>"$OUT/08-processes.err"; then
  ok "pobrano: $(wc -l < "$OUT/08-processes.txt" | tr -d ' ') wierszy"
  grep -iE 'springboard|gameloft|roblox|minecraft|youtube|tiktok|com\.' "$OUT/08-processes.txt" \
    2>/dev/null | head -12 | sed 's/^/  /'
else
  bad "nie udalo sie: $(msg "$OUT/08-processes.err")"
fi

# ------------------------------- 3. strumienie: zdarzenia i logi SpringBoard
sample_stream() {  # nazwa, plik, komenda...
  local label="$1" file="$2"; shift 2
  info "zbieram $SECONDS_SAMPLE s: $label"
  "$@" > "$file" 2>&1 &
  local pid=$!
  local waited=0
  while [ "$waited" -lt "$SECONDS_SAMPLE" ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1; waited=$((waited + 1))
  done
  # Strumien konczy sie tylko przez przerwanie — to normalne, nie blad.
  kill -INT "$pid" 2>/dev/null
  sleep 1
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  local lines
  lines=$(wc -l < "$file" 2>/dev/null | tr -d ' ')
  if grep -qiE 'password protected|please unlock|ERROR' "$file" 2>/dev/null; then
    bad "$label: BLAD — $(msg "$file")"
  elif [ "${lines:-0}" -gt 0 ]; then
    ok "$label: $lines wierszy"
  else
    warn "$label: PUSTE (nie doszlo do zadnego zdarzenia w tym czasie?)"
  fi
}

say "8/8  Zdarzenia na zywo — TU POTRZEBUJE TWOJEJ POMOCY"
cat <<HOWTO

  Przez najblizsze $((SECONDS_SAMPLE * 2)) sekund, na iPadzie:
    * ZABLOKUJ ekran (przycisk)              <- szukamy zdarzenia blokady
    * ODBLOKUJ (Face ID / kod)               <- szukamy zdarzenia odblokowania
    * ODPAL JAKAS GRE i wroc do ekranu domowego

  Bez tego probki beda puste i nie dowiemy sie, czy te sygnaly istnieja.

HOWTO
if [ -r /dev/tty ] && [ -t 1 ]; then
  printf '  Gotowy? Enter zaczyna. '
  read -r _ </dev/tty
else
  # Bez terminala nie ma kogo pytac — dajemy czas na siegniecie po iPada,
  # zamiast przewijac prompt i zbierac puste probki.
  warn "brak terminala interaktywnego — zaczynam za 15 s, siegnij po iPada"
  for i in 15 12 9 6 3; do printf '  ...%s s\n' "$i"; sleep 3; done
fi

sample_stream "powiadomienia systemowe" "$OUT/09-notifications.txt" \
  "$PMD" notification observe-all
sample_stream "logi SpringBoard"        "$OUT/10-syslog-springboard.txt" \
  "$PMD" syslog live -m SpringBoard

# ------------------------------------------------------------- podsumowanie
{
  echo "kidwatch — probka sygnalow z iPada"
  echo "zebrane: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "host:    $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
  echo "narzedzie: $("$PMD" version 2>/dev/null)"
  echo "probka strumieni: ${SECONDS_SAMPLE}s"
  echo
  echo "=== 1. CZY DZIALA DOSTEP PO Wi-Fi ==="
  echo "urzadzen przez USB/Wi-Fi: $USB_COUNT, tylko po Wi-Fi: $NET_COUNT"
  grep -A2 'Wi-Fi devices' "$OUT/01-doctor.txt" 2>/dev/null || true
  echo
  echo "=== 2. APLIKACJE UZYTKOWNIKA (ile) ==="
  python3 - "$OUT/07-apps.json" <<'PY' 2>/dev/null || echo "(brak danych)"
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("(brak danych)"); raise SystemExit
items = d.items() if isinstance(d, dict) else [(x.get('CFBundleIdentifier','?'), x) for x in d]
user = [(m.get('CFBundleDisplayName') or m.get('CFBundleName') or '?', b)
        for b, m in items if isinstance(m, dict) and m.get('ApplicationType') in (None, 'User')]
print(f"{len(user)} aplikacji uzytkownika")
for name, bid in sorted(user):
    print(f"  {name}  [{bid}]")
PY
  echo
  echo "=== 3. POWIADOMIENIA SYSTEMOWE (unikalne nazwy) ==="
  if [ -s "$OUT/09-notifications.txt" ]; then
    grep -oE '[a-zA-Z0-9_.-]*(lock|Lock|screen|Screen|display|Display|springboard|SpringBoard)[a-zA-Z0-9_.-]*' \
      "$OUT/09-notifications.txt" 2>/dev/null | sort -u | head -40
    echo "--- wszystkie unikalne, pierwsze 60 ---"
    grep -oE 'com\.apple\.[a-zA-Z0-9_.-]+' "$OUT/09-notifications.txt" 2>/dev/null | sort -u | head -60
  else
    echo "PUSTE — albo nie doszlo do blokady/odblokowania w trakcie, albo usluga nie oddaje tych zdarzen"
  fi
  echo
  echo "=== 4. LOGI SPRINGBOARD (probka) ==="
  head -60 "$OUT/10-syslog-springboard.txt" 2>/dev/null || echo "PUSTE"
  echo
  echo "=== 5. PROCESY (probka) ==="
  head -40 "$OUT/08-processes.txt" 2>/dev/null || echo "PUSTE"
} > "$SUMMARY" 2>&1

# ----------------------------------------------------------- zaciemnianie
if [ "$REDACT" -eq 1 ]; then
  python3 - "$SUMMARY" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p, encoding='utf-8', errors='replace').read()
# Dane osobowe wylatuja, bundle ID i nazwy zdarzen ZOSTAJA — bez nich probka
# jest bezuzyteczna.
s = re.sub(r'[\w.+-]+@[\w-]+\.[\w.]+', '[EMAIL]', s)
s = re.sub(r'\b[0-9a-fA-F]{40}\b', '[UDID40]', s)
s = re.sub(r'\b[0-9A-F]{8}-[0-9A-F]{16}\b', '[UDID]', s)
s = re.sub(r'\b(\+?48[ -]?)?\d{3}[ -]?\d{3}[ -]?\d{3}\b', '[TEL]', s)
open(p, 'w', encoding='utf-8').write(s)
PY
fi

say "GOTOWE"
info "surowe pliki:  $OUT"
info "do pokazania:  $SUMMARY"
echo
if [ "$REDACT" -eq 1 ]; then
  info "Adresy e-mail, UDID i numery telefonu zostaly w podsumowaniu zamaskowane."
  info "Nazwy zdarzen i bundle ID zostaly — bez nich probka jest bezuzyteczna."
  info "Chcesz surowe: ./tools/probe_ipad.sh --raw"
fi
echo
info "Wklej mi PODSUMOWANIE.txt albo odpal:"
info "  ! cat '$SUMMARY'"
