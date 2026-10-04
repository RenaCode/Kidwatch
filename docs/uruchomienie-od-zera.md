# Uruchomienie kidwatch od zera

Instrukcja dla kogoś, kto stawia kidwatch pierwszy raz: na własnym klastrze k3s,
z własnymi iPadami i kontami. Zakłada podstawową znajomość `kubectl` i SSH.

**Repo ma być publiczne. Żadnej prawdziwej wartości (klucza, ID profilu, UDID-u,
adresu, imienia dziecka) nie wpisuj do plików śledzonych przez git.** Wszystko
takie idzie do Sekretów klastra albo do plików wymienionych w `.gitignore`
(`config.cluster.yaml`, `*.plist`, `*.mobileconfig`).

## Co powstanie

| warstwa | skąd dane | co daje | kiedy działa |
|---|---|---|---|
| DNS (NextDNS) | logi zapytań z profilu DNS na iPadzie | start i koniec sesji, aplikacje rozpoznane po domenach | zawsze, w każdej sieci |
| odczyt z iPada (lockdown) | iPad w **tej samej sieci lokalnej** co czytający | uruchomione aplikacje, nowe instalacje | domyślnie wyłączony w klastrze (niżej) |
| telewizor (ADB) | Google TV w domowej sieci, po tunelu WireGuard | co gra, sesje oglądania z tytułami | opcjonalnie, krok 10 |
| UniFi | kontroler UDM, po tunelu WireGuard | kto jest w domu; alarm, gdy iPad w domu przesyła dane, a NextDNS milczy | opcjonalnie, krok 11 |
| powiadomienia | bramka RenaCode (`renacode-infra/charts/bramka`) | WhatsApp, a bez podpiętego numeru e-mail | zawsze |
| panel WWW | baza SQLite kidwatch | logowanie (hasło + opcjonalne 2FA), przełącznik dzieci, zakładki Powiadomienia, Użycie (wykres dzienny) i Dzień | pod `https://<twoja-domena>` |

## Czego potrzebujesz

- Klaster k3s z ArgoCD, Traefikiem i cert-managerem (`ClusterIssuer`
  `letsencrypt-prod`) oraz sekret `ghcr-pull` do prywatnych obrazów GHCR.
- Bramkę powiadomień wdrożoną z `renacode-infra` (jej `README.md`).
- Konto NextDNS (darmowe wystarczy do 300 tys. zapytań miesięcznie).
- Domenę, w której możesz dodać rekord A.
- Opcjonalnie, dla telewizora i UniFi: tunel WireGuard VPS ↔ dom (krok 4).
- Opcjonalnie, tylko pod przyszły odczyt iPadów z domowego LAN: Maca z kablem
  USB-C/Lightning, `uv` i `pymobiledevice3` (`uv tool install pymobiledevice3`).

Tailscale **nie jest potrzebny** (sprawdzone 2026-10-02, wyjaśnienie w kroku 4).

Kolejność kroków ma znaczenie: konfiguracja (krok 6) potrzebuje danych z kroków 1–5.

---

## 1. NextDNS: profil i klucz API

1. Załóż konto na <https://my.nextdns.io>. Profil tworzy się sam.
2. **Setup** → zapisz **ID profilu** (6 znaków, np. `abc123`).
3. **Settings → Logs** → **Enable Logs**, retencja co najmniej 1 dzień.
4. **Account → API** → zapisz **klucz API**. To sekret.

ID profilu odczytasz też przez API:

```bash
read -rs 'NX?Klucz API NextDNS: '; echo
curl -s -H "X-Api-Key: $NX" https://api.nextdns.io/profiles
```

### Drugi profil — osobny na dziecko (pod „czas gry”)

Blokady usług w NextDNS dotyczą całego profilu. Żeby „Zablokuj gry” u jednego
dziecka nie blokowało drugiemu, każde dziecko potrzebuje własnego profilu:

1. my.nextdns.io → przełącznik profili (lewy górny róg) → nowy profil.
   Ustaw w nim to samo co w pierwszym (Security, Privacy, Parental Control)
   i **Settings → Logs → Enable Logs** — bez logów kidwatch nie widzi iPada.
2. Zapisz ID nowego profilu (`Setup`). Ten sam klucz API obsługuje wszystkie
   profile konta.
3. Na iPadzie tego dziecka zainstaluj profil DNS z **nowym** ID (krok 3,
   adres `https://apple.dns.nextdns.io/<NOWE_ID>/<nazwa-iPada>`). Stary profil
   DNS z iPada usuń — inaczej iOS używa dowolnego z nich.
4. W konfiguracji (krok 6) przy urządzeniach tego dziecka dopisz
   `nextdns_profile: <NOWE_ID>`. Wszystkie iPady jednego dziecka muszą mieć ten
   sam profil — konfiguracja odrzuci inny układ.

## 2. Parowanie iPadów (opcjonalnie, kabel, jednorazowo)

Potrzebne tylko do odczytu z iPada (lockdown), który w klastrze jest wyłączony
(krok 4). Bez agenta w domowym LAN ten krok możesz pominąć.

Odczyt z iPada wymaga rekordu parowania, czyli tego samego zaufania, które daje
„Ufaj temu komputerowi”. Robi się go raz, po kablu.

Dla każdego iPada:

```bash
pymobiledevice3 usbmux list                       # UDID i nazwa podłączonych urządzeń
pymobiledevice3 lockdown pair --udid <UDID>       # na iPadzie: „Ufaj” + kod
pymobiledevice3 lockdown wifi-connections --udid <UDID> on
pymobiledevice3 apps list --udid <UDID> > /tmp/apps.json   # do awaryjnej listy aplikacji
```

Rekordy lądują w `~/.pymobiledevice3/<UDID>.plist`. **Zawierają klucz prywatny
hosta**: kto je ma, czyta z iPada wszystko. Nie kopiuj ich nigdzie poza Sekret
klastra.

Parowanie trzeba powtórzyć po „Wyzeruj lokalizację i prywatność”, po wymazaniu
iPada i po zmianie Maca.

**Identyfikuj iPady po UDID, nie po nazwie.** Nazwy zawodzą: ten sam iPad
zgłasza się różnie przez USB, Bonjour i NextDNS, a nowy iPad nazywa się po
prostu „iPad”.

## 3. Profil DNS na iPadach

Każdy iPad dostaje **własny** adres DoH z unikalną końcówką. Po niej NextDNS
rozróżnia urządzenia. Wspólny profil oznacza jedno urządzenie w logach.

```bash
uv run python tools/gen_profile.py --name "iPad Dziecka 1" \
  --doh-url "https://dns.nextdns.io/<ID_PROFILU>/iPad-Dziecko1" \
  --out profile/dziecko1.mobileconfig
```

Wyślij plik AirDropem na właściwy iPad, a potem **Ustawienia → Pobrano profil →
Zainstaluj**. Sprawdzenie: w NextDNS → **Logs** pojawiają się zapytania z nazwą
`iPad-Dziecko1`.

Profil zamiast aplikacji NextDNS, bo aplikacja wysyła nazwę urządzenia z iOS,
a tej dziecko może nie zmienić, iOS może ją ukryć albo dwa iPady mogą mieć
identyczną. Bez nadzoru (MDM) dziecko może usunąć profil. Czujka kidwatch zgłosi
to jako ciszę urządzenia, a z UniFi (krok 11) także gdy iPad w domu dalej
przesyła dane.

## 4. Tunel do domu (tylko dla telewizora i UniFi)

**Tailscale nie jest potrzebny.** Miał dawać dostęp do iPadów poza domem, ale
sprawdzone 2026-10-02: iOS przyjmuje lockdown (port 62078) wyłącznie od urządzeń
z tej samej sieci lokalnej. Przez Tailscale i przez tunel WireGuard każde
połączenie jest zrywane (`ConnectionResetError`), także z poprawnym rekordem
parowania. Dlatego w klastrze `device_read` jest wyłączony, a kontener
Tailscale (`tailscale.enabled: false` w chart) nie jest wdrażany. Odczyt iPadów
wymagałby agenta w domowym LAN, którego jeszcze nie ma.

Telewizor (krok 10) i kontroler UniFi (krok 11) są w domowym LAN, więc pod
sięga ich tunelem WireGuard VPS ↔ UDM z `renacode-infra` (jego `README.md`,
sekcja „WireGuard”). Warunki:

- na VPS-ie trasa do domowej podsieci przez `wg0` (`PostUp` w `wg0.conf`),
- pod wychodzi do tunelu z adresem VPS-a w tunelu (`<adres VPS w tunelu>`): k3s maskuje
  ruch podów do sieci spoza klastra,
- na UDM reguła strefowa zapory dla źródła `<sieć tunelu>/24` (np. „Allow VPS to LAN”,
  External → Internal) — bez niej handshake jest, a ruch ginie po cichu.
  Sam UDM (API UniFi, port 443) jest w strefie **Gateway**, nie Internal; jeśli
  `python -m kidwatch unifi --fingerprint` z poda kończy się przekroczeniem
  czasu, brakuje reguły External → Gateway dla tego samego źródła.

## 5. Rekord DNS dla panelu

U operatora domeny dodaj rekord **A** `kidwatch` z adresem publicznym VPS-a.
Jeśli w strefie jest wildcard (`*`), jawny rekord jest konieczny, bo inaczej
cert-manager nie wystawi certyfikatu. Sprawdzenie:

```bash
dig +short kidwatch.<twoja-domena>
```

Domena panelu jest w `charts/kidwatch/values.yaml` (`ingress.host`).

## 6. Konfiguracja

Skopiuj wzorzec do pliku poza gitem i uzupełnij:

```bash
cp charts/kidwatch/files/config.yaml config.cluster.yaml
```

| pole | wartość |
|---|---|
| `source.nextdns.profile_id` | ID profilu z kroku 1 |
| `devices[].display_name`, `child` | nazwa w powiadomieniach, imię dziecka |
| `devices[].source_ids` | końcówka adresu DoH z kroku 3, np. `iPad-Dziecko1` |
| `devices[].unifi_mac` | prywatny adres Wi-Fi iPada w domowej sieci (krok 11, opcjonalnie) |
| `devices[].nextdns_profile` | własny profil NextDNS dziecka (krok 1, „Drugi profil”); puste = `profile_id` |
| `engine.night` | okno alarmu nocnego; domyślnie = `quiet_hours`, przypomnienie co 30 min |
| `engine.weekly_report` | raport tygodnia, domyślnie niedziela (`weekday: 6`) 19:00 |
| `game_time` | przyciski czasu gry w panelu (usługi, kategorie, bonus, harmonogram) |
| `tv.*`, `unifi.*` | kroki 10 i 11 (opcjonalnie) |
| `devices[].udid`, `host`, `known_apps` | tylko pod odczyt iPadów (`device_read`, w klastrze wyłączony); bez agenta w domowym LAN usuń albo zostaw puste |

Wgranie do klastra (Sekret `kidwatch-config`) z walidacją i restartem poda:

```bash
tools/wgraj_konfiguracje.sh config.cluster.yaml <host-ssh>
```

Skrypt najpierw sprawdza plik lokalnie, więc błędny config nie zatrzyma
działającego poda. Ten sam skrypt służy do każdej późniejszej zmiany.

Nowe sekcje w skrócie (pełne opisy w `charts/kidwatch/files/config.yaml`):

```yaml
devices:
  - display_name: "iPad (Dziecko 2)"
    child: "Dziecko 2"
    source_ids: ["iPad-Dziecko2"]
    nextdns_profile: "ZMIEN_MNIE_2"     # własny profil dziecka (opcjonalnie)

engine:
  night: {start: "21:30", end: "06:30", reminder_minutes: 30}   # bez start/end = quiet_hours
  weekly_report: {enabled: true, weekday: 6, time: "19:00"}

game_time:
  enabled: true
  services: [youtube, roblox, minecraft, fortnite, tiktok, twitch]
  categories: [gaming]
  default_bonus_minutes: 30
  # block_schedule: {start: "20:00", end: "07:00"}
```

Odbiorców WhatsApp (do 5, z etykietą i przełącznikiem „aktywny”) i
połączenie numeru bota (QR) ustawisz w panelu:
avatar → **Profil → Powiadomienia / WhatsApp** (wymaga bramki z PVC
`bramka-dane`, patrz `renacode-infra/charts/bramka/README.md`).

Po włączeniu `game_time` pierwszy odczyt z NextDNS (do 5 min) ustawia stan
w panelu na to, co jest w profilu. Sprawdzenie raportu tygodnia bez wysyłki:
`kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch weekly --dry-run`.

## 7. Sekrety

W namespace `default` (na VPS-ie z `sudo`). `read -s` pyta o wartość bez
wyświetlania jej i bez zapisu do historii powłoki.

```bash
# klucz NextDNS, klucze bramki powiadomień i klucz szyfrujący sekrety TOTP panelu.
# Bramka: BRAMKA_KLUCZ = klucz WYSYŁKOWY kidwatcha (BRAMKA_KLUCZ_KIDWATCH
# z bramka-klucze; bramka po nim podpisuje wiadomości), BRAMKA_KLUCZ_ADMIN =
# klucz panelu do zarządzania WhatsAppem. Oba muszą już być w bramka-klucze
# (renacode-infra/charts/bramka/README.md, „Klucze”).
read -rs 'NX?Klucz API NextDNS: '; echo
g() { kubectl -n bramka get secret bramka-klucze -o jsonpath="{.data.$1}" | base64 -d; }
BK=$(g BRAMKA_KLUCZ_KIDWATCH); BA=$(g BRAMKA_KLUCZ_ADMIN)
TK=$(openssl rand -base64 32)
kubectl -n default create secret generic kidwatch-secrets \
  --from-literal=NEXTDNS_API_KEY="$NX" --from-literal=BRAMKA_KLUCZ="$BK" \
  --from-literal=BRAMKA_KLUCZ_ADMIN="$BA" --from-literal=PANEL_TOTP_KEY="$TK"
unset NX BK BA TK

# opcjonalnie: rekordy parowania (krok 2), z Maca — dziś nieużywane w klastrze
cd ~/.pymobiledevice3
kubectl -n default create secret generic kidwatch-pairing \
  --from-file=<UDID_1>.plist --from-file=<UDID_2>.plist
```

Gdy `kubectl` działa tylko na VPS-ie, a pliki są na Macu, przekazuj je przez
stdin, np. `... | ssh vps 'sudo kubectl ... --from-file=x.plist=/dev/stdin'`.

Komplet: `kidwatch-secrets` i `kidwatch-config`; opcjonalnie `kidwatch-adb`
(krok 10), `UNIFI_API_KEY` w `kidwatch-secrets` (krok 11) i `kidwatch-pairing`.
Konto do panelu WWW zakładasz po wdrożeniu (krok 9).

`PANEL_TOTP_KEY` szyfruje sekrety drugiego składnika (TOTP) w bazie panelu.
Bez niego panel działa i logowanie hasłem też, nie da się tylko włączyć 2FA
(w logu: `brak PANEL_TOTP_KEY`). Konto, które ma już 2FA, bez klucza się
nie zaloguje. Zmiana albo utrata klucza unieważnia włączone TOTP — wtedy
`user-reset <login> --totp` i ponowne włączenie w panelu.

## 8. Wdrożenie

1. Push na `main`. CI uruchamia testy, buduje obraz (z frontem panelu) i podbija
   tag w `values.yaml`.
2. Aplikacja w ArgoCD (raz): `kubectl apply -f argocd-apps.yaml` z repo
   `renacode-infra`. Dalej ArgoCD synchronizuje sam.

## 9. Weryfikacja

```bash
kubectl -n default get pods -l app.kubernetes.io/name=kidwatch           # 1/1 Running
kubectl -n default logs deploy/kidwatch -c kidwatch --tail=50
kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch test-notify
```

W logach kidwatcha szukaj:

- `start: zrodlo=nextdns urzadzenia=[...] kanaly=['bramka']`
- `panel WWW na 0.0.0.0:8080`
- z telewizorem: `czujnik TV wlaczony: ...`; z UniFi: `czujka UniFi wlaczona: ...`
  albo `czujka UniFi wylaczona: <powód>`.
- Pojedyncze `NextDNS odpowiedzial 429 — ponawiam` po zamknięciu strumienia
  przez serwer są normalne, o ile kończą się `200 OK`.

### Konto do panelu WWW

Panel ma własne logowanie: hasło (Argon2id) i opcjonalny drugi składnik TOTP,
blokada na 15 minut po 5 nieudanych próbach. Złe hasła liczą się per login
i adres klienta (ostatni wpis `X-Forwarded-For` od Traefika), więc zgadywanie
z zewnątrz nie zamyka rodzica z innego adresu; złe kody drugiego składnika
blokują całe konto. Po wygaśnięciu blokady licznik liczy od nowa.
Konta i sesje leżą w `/data/panel-auth.db` na tym samym wolumenie co baza —
przeżywają restart poda. Konto zakładasz w podzie:

```bash
# hasło losowe, wypisane JEDEN raz — zapisz je od razu w menedżerze haseł
kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch user-add <login>

# albo własne hasło (min. 12 znaków) przez stdin — nie trafia do historii powłoki;
# -i jest konieczne, inaczej kubectl nie podłączy stdin
read -rs 'PW?Hasło do panelu: '; echo
printf '%s\n' "$PW" | kubectl -n default exec -i deploy/kidwatch -c kidwatch -- \
  python -m kidwatch user-add <login> --password-stdin
unset PW
```

**Weryfikacja dwuetapowa (zalecana).** Po zalogowaniu: przycisk „Włącz 2FA”
w nagłówku (odznaka „bez 2FA” / „2FA” mówi, jaki jest stan). Panel pokazuje kod
QR (liczony lokalnie, sekret nie wychodzi poza serwer) i sekret do przepisania
w Google Authenticator, 1Password itp.; potwierdzasz sześciocyfrowym kodem.
Wtedy jednorazowo pojawia się **8 kodów zapasowych** — każdy działa raz zamiast
kodu z aplikacji. Zapisz je w menedżerze haseł; w bazie są tylko ich skróty.
Włączenie 2FA wylogowuje pozostałe sesje konta. Od tej chwili logowanie to
hasło + kod. Wyłączenie w tym samym miejscu wymaga hasła i kodu.

| sytuacja | polecenie (`kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch ...`) |
|---|---|
| zapomniane hasło, zablokowane konto | `user-reset <login>` — nowe hasło, TOTP zostaje |
| zgubiony telefon, zmieniony `PANEL_TOTP_KEY` | `user-reset <login> --totp` — zdejmuje 2FA, hasło zostaje |
| lista kont, stan 2FA, kody zapasowe | `user-list` |
| usunięcie konta | `user-del <login>` |

Każdy reset wylogowuje wszystkie sesje tego konta.

Panel: `https://kidwatch.<twoja-domena>`.

## 10. Telewizor (opcjonalnie): Google TV po ADB

Czujnik co 30 s pyta telewizor, co gra (`dumpsys media_session`), co jest na
ekranie i czy ekran nie śpi. Sesja oglądania zaczyna się, gdy coś gra, kończy
po 10 min bez odtwarzania albo od razu przy uśpieniu. Push idzie na start
(„TV salon: start — Fiksiki: Myjka okien (YouTube)”) i koniec („TV salon:
koniec — 3 tytuły, 55 min”); kolejne tytuły w trakcie są tylko w panelu.
Telewizor jest urządzeniem wspólnym — widać go przy „Wszyscy”, a nie przy
konkretnym dziecku.

1. Na TV: **Ustawienia → System → Informacje → Kompilacja** (7 razy), potem
   **Opcje programisty → Debugowanie USB** i **Debugowanie sieciowe/ADB przez sieć**.
2. Z komputera w domowej sieci, raz: `adb connect <IP-TV>:5555` i na ekranie
   TV **Zezwól** z zaznaczonym **Zawsze zezwalaj z tego komputera**. Klucz,
   który TV właśnie zaakceptował, leży w `~/.android/adbkey` (+ `adbkey.pub`).
3. Sekret z tym kluczem:

   ```bash
   kubectl -n default create secret generic kidwatch-adb \
     --from-file=adbkey=$HOME/.android/adbkey --from-file=adbkey.pub=$HOME/.android/adbkey.pub
   ```

4. W `config.cluster.yaml`: `tv.enabled: true`, `tv.host: <IP-TV>`; wgranie
   `tools/wgraj_konfiguracje.sh`. Pod dochodzi do TV tunelem WireGuard VPS→dom
   (warunki w kroku 4).
5. Sprawdzenie: `kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv`
   (`--raw` wypisuje surowe dumpsys — tak nagrywa się nowe próbki do testów).

Wyłączony z prądu telewizor jest nieosiągalny i to normalne; alarm przychodzi
dopiero po dobie bez jednego udanego odczytu.

Co 15 min (`tv.usage_poll_minutes`) czujnik czyta też `dumpsys usagestats` —
czas aplikacji na pierwszym planie liczony przez Androida. Panel („Wszystkie
ekrany”) i raport tygodnia pokazują go jako „dokładnie, z TV” obok szacunku
z sesji. `python -m kidwatch tv` wypisuje bieżące liczniki; gdy pokazuje
„brak bloku daily”, nagraj `tv --raw` i zgłoś format.

### Pauza monitoringu TV

Na wyjazd z dziećmi (w domu oglądają inni): w panelu na karcie telewizora
**Wstrzymaj monitoring TV** — do terminu albo do odwołania; **Wznów teraz**
na banerze. To samo z CLI:
`kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv-pauza --do 2026-10-10T18:00`
(`--do-odwolania`, `--wznow`, bez opcji — stan). W pauzie telewizor nie jest
odpytywany, nie ma pushy ani minut TV, a czujka TV milczy; iPady bez zmian.
Szczegóły w README, „Pauza monitoringu TV”.

## 11. UniFi (opcjonalnie): „w domu” i czujka usuniętego profilu DNS

Kontroler UniFi wie, które iPady są w domowym Wi-Fi i ile przesłały. Jeśli
iPad w domu przesłał ponad 20 MB w 15 min, a NextDNS nie ma od niego w tym
czasie ani jednego zapytania, przychodzi alarm „profil DNS prawdopodobnie
usunięty” (z przypomnieniami co 15, 30, 60… min, do 8 h).

1. Klucz API: UniFi Network → **Ustawienia → Control Plane → Integrations**
   → utwórz klucz. Do Sekretu:

   ```bash
   read -rs 'UK?Klucz API UniFi: '; echo
   kubectl -n default patch secret kidwatch-secrets --type merge \
     -p "{\"stringData\":{\"UNIFI_API_KEY\":\"$UK\"}}"
   unset UK
   ```

2. Odcisk certyfikatu UDM (samopodpisany — przypinamy go zamiast wyłączać
   weryfikację TLS). Z komputera w domowej sieci:

   ```bash
   openssl s_client -connect <IP-UDM>:443 </dev/null 2>/dev/null \
     | openssl x509 -noout -fingerprint -sha256
   ```

   Ten sam odcisk z poda (nic nie wysyła, tylko czyta certyfikat):
   `kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch unifi --fingerprint`.
   Oba muszą być identyczne — wtedy wpisz go do `unifi.cert_sha256`.
3. MAC-i iPadów: **Ustawienia → Wi-Fi → (i) przy domowej sieci → Adres Wi-Fi**.
   iOS używa prywatnego adresu per sieć — wpisz ten, nie sprzętowy. Do
   `devices[].unifi_mac`. Jeśli iPad ma stałe IP (rezerwacja DHCP na UDM),
   dopisz też `devices[].unifi_ip` — drugi trop, gdy iOS zmieni prywatny MAC.
4. `unifi.enabled: true`, wgranie konfiguracji, restart poda (nowy klucz
   w `kidwatch-secrets` wczytuje się tylko przy starcie).
5. Sprawdzenie: `... python -m kidwatch unifi` — kto jest teraz w domu.

Bez klucza, bez odcisku albo bez żadnego `unifi_mac` czujka się nie uruchamia
(ostrzeżenie w logu), reszta działa. Zmiana certyfikatu UDM (np. po
aktualizacji) zatrzymuje czujkę z błędem „odcisk ... nie zgadza się” — klucz
API nie zostaje wtedy wysłany; trzeba wpisać nowy odcisk.

## Znane ograniczenia

| chcesz | możliwe? |
|---|---|
| kiedy iPad aktywny, jakie usługi, jakie domeny | ✅ zawsze, w każdej sieci |
| lista zainstalowanych aplikacji, co jest uruchomione | ❌ z klastra nie (iOS wpuszcza tylko z domowego LAN); potrzebny agent w LAN, którego nie ma |
| co gra na telewizorze | ✅ z czujnikiem TV (krok 10) |
| gra działająca offline | ❌ niewidzialna dla DNS |
| dokładny czas w aplikacji | ❌ tylko „Czas przed ekranem”, Apple nie ma API |
| adresy stron i treść | ❌ tylko domeny |

**Minuty to dolne oszacowanie.** To liczba różnych minut z zapytaniem DNS do
domen aplikacji. iOS cache'uje odpowiedzi DNS, więc godzina gry może dać
zapytania tylko w kilku minutach.

**Na niektórych iPadach odczyt po sieci jest częściowy** (dotyczy odczytu
z domowego LAN). Lista procesów działa,
ale lista aplikacji i stan ekranu padają na `ConnectionTerminatedError`
(przyczyny nie ustalono). Uruchomienia i tak są nazwane dzięki `known_apps`
w konfiguracji.

**Najmocniejsza rzecz poza kodem:** „Poproś o zakup” w Chmurze rodzinnej
(Ustawienia → [imię] → Chmura rodzinna → dziecko). Każdy zakup wymaga
zatwierdzenia rodzica przed wydaniem pieniędzy.
