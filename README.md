# kidwatch

Powiadomienia na telefon o aktywności iPadów dzieci, na podstawie zapytań DNS.
W klastrze idą przez bramkę RenaCode (WhatsApp, a bez podpiętego numeru e-mail),
lokalnie przez ntfy albo Home Assistant. Do tego panel WWW z historią, wykresem
użycia, widokiem „Wszystkie ekrany” (iPady i TV na jednej osi dnia), trendami
i eksportem CSV oraz opcjonalnie czujnik telewizora (ADB) i czujka UniFi.

Pełna instrukcja wdrożenia na klastrze: [`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md).

**W skrócie**

- **Źródło danych:** logi zapytań DNS z [NextDNS](https://nextdns.io) (strumień
  na żywo) — bez aplikacji na iPadzie, bez MDM, bez jailbreaka.
- **Powiadomienia:** start i koniec sesji, nowe aplikacje, noc, podsumowanie
  dnia i tygodnia — przez ntfy, Home Assistant albo bramkę WhatsApp/e-mail.
- **Panel WWW:** historia, oś dnia wszystkich ekranów, trendy, eksport CSV,
  czas gry z NextDNS, logowanie z 2FA.
- **Opcjonalnie:** telewizor z Androidem (ADB) i ruch z kontrolera UniFi.
- **Stack:** Python 3.12 (asyncio, httpx, SQLite), React + Vite, Docker,
  Helm chart dla k3s/Argo CD.

> **In English:** kidwatch sends phone notifications about kids' iPad activity
> (session start/end, new apps, night use, daily and weekly reports), inferred
> from NextDNS query logs — no app on the device. It includes a web dashboard
> with 2FA, optional Android TV (ADB) and UniFi sensors, and a self-monitoring
> watchdog. Minutes are a lower bound, not real screen time. The docs are in
> Polish; the config is in `config.example.yaml`.

Dostajesz cztery rodzaje wiadomości:

| | kiedy | przykład |
|---|---|---|
| **Start sesji** | aktywność potwierdzona (3 odrębne chwile ruchu rozpięte na ≥1 min w 5 min albo ≥3 min ruchu; pakiet zapytań w jednej sekundzie to jedna chwila) po ≥10 min ciszy | `iPad Kuby aktywny` · `15:12 — Roblox` |
| **Aplikacja** | nowa apka w trwającej sesji — każda raz na sesję (powrót do niej też nie pinguje) | `Kuba` · `YouTube` |
| **Koniec sesji** | 10 min bez aktywności | `iPad Kuby — koniec` · `15:12–15:59, 47 min` |
| **Podsumowanie dnia** | 20:30 | sesje od 20:30 poprzedniego dnia, czas i top aplikacje per dziecko |
| **Telewizor** (opcjonalnie) | start i koniec oglądania | `TV salon: start — <tytuł> (YouTube)` |
| **Noc** | sesja w oknie nocy (start albo trwanie) + przypomnienie co 30 min | `🌙 Kuba używa iPada w nocy` · `23:12, YouTube, w domu` |
| **Raport tygodnia** | niedziela 19:00 | od poprzedniej niedzieli 19:00: minuty vs poprzedni tydzień, sesje, dni, top 5, najdłuższa sesja, noc, TV |
| **Czas gry** (opcjonalnie) | zmiana z panelu, koniec bonusu, harmonogram | `🎮 Czas gry dla Kuba: +30 min (do 18:40)` |

Plus **czujka własnej niesprawności** — patrz [Czujka](#czujka-najważniejsza-część-bez-nadzoru).

---

## Najpierw: czym te liczby NIE są

**To nie jest pomiar czasu przed ekranem.** Liczba minut przy aplikacji to liczba
różnych minut, w których iPad wysłał zapytanie DNS do jej domen. iOS cachuje
odpowiedzi DNS, więc dziecko może grać godzinę, generując zapytania w kilku
minutach. **Każda podana liczba jest dolnym oszacowaniem** i każde powiadomienie
mówi to wprost.

Pełne dane, także z czasu offline, są w **Ustawienia → Czas przed ekranem** na
Twoim iPhonie. Apple nie udostępnia do nich publicznego API i kidwatch nawet nie
próbuje się tam wpinać. Jeśli będziesz porównywał jedno z drugim, kidwatch zawsze
pokaże mniej — i to jest poprawne zachowanie, nie błąd.

Czego jeszcze nie zobaczysz:

- **aplikacji, które nie odpytują własnych domen** (gry offline, zdjęcia, notatki);
- **rozróżnienia YouTube Kids od YouTube** w 100% — YT Kids używa części tych
  samych domen (`googlevideo.com`, `youtubei.googleapis.com`), więc jego ruch
  częściowo trafi na konto „YouTube";
- **treści** — tylko domeny. Nie wiesz, *co* dziecko obejrzało.

---

## Szybki start — bez wymazywania iPada

**Nie musisz nadzorować iPadów ani niczego wymazywać.** Sprawdzone w oficjalnym
schemacie Apple ([`com.apple.dnsSettings.managed.yaml`](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsSettings.managed.yaml)):
cały payload DNS ma `supervised: false` i `allowmanualinstall: true`.

### 1. Profil NextDNS

1. Konto na [my.nextdns.io](https://my.nextdns.io/) → nowy profil. Zapisz **ID profilu**.
2. **Account → API → klucz API.** To sekret, trafia do zmiennej środowiskowej.
3. W profilu włącz logi (**Settings → Logs**) i retencję ≥ 1 dzień.

### 2. DNS na każdym iPadzie — dwie drogi, wybierz jedną

**Droga A: aplikacja NextDNS (najprostsza)**

1. App Store → [NextDNS](https://apps.apple.com/us/app/nextdns/id1463342498) na iPadzie.
2. Wpisz ID profilu.
3. **Włącz wysyłanie nazwy urządzenia** — bez tego wszystkie iPady zlewają się
   w jedno i kidwatch nie rozróżni dzieci.
4. Nazwij urządzenie unikalnie, np. `iPad-Kuby`. Ta nazwa idzie do `source_ids`
   w `config.yaml`.

**Droga B: profil `.mobileconfig` (bez aplikacji)**

```bash
uv run python tools/gen_profile.py \
  --name "iPad Kuby" \
  --doh-url "https://dns.nextdns.io/TWOJE_ID/iPad-Kuby" \
  --out kuba.mobileconfig
```

**Jeden plik na każdy iPad, z inną końcówką adresu.** Rozróżnienie urządzeń
opiera się na ścieżce w adresie DoH — wspólny profil = jedno urządzenie w logach.

Wyślij plik na iPada (AirDrop / mail), potem **Ustawienia → Pobrano profil → Zainstaluj**.

### 3. Utrudnij zdjęcie (bez nadzoru nie da się zablokować)

Screen Time **nie potrafi** zamknąć ustawień DNS — nie ogranicza dostępu do
ekranu Ustawienia → Ogólne, a ustawienia VPN/DNS nie są pozycją, którą kontrola
rodzicielska obejmuje. Co możesz zrobić:

- **Screen Time → Ograniczenia treści i prywatności → App Store → Usuwanie aplikacji: Nie pozwalaj**
  (przy drodze A blokuje usunięcie aplikacji NextDNS);
- kod Screen Time, którego dzieci nie znają;
- **zostaw czujkę włączoną** — ona zgłosi zdjęcie profilu.

### 4. ntfy na Twoim iPhonie

1. App Store → **ntfy**.
2. Zasubskrybuj temat z `config.yaml` (`notifiers.ntfy.topic`).
3. Temat podajesz w zmiennej `NTFY_TOPIC`, nie w pliku (`topic: ""` w
   `config.example.yaml`; bez zmiennej konfiguracja się nie zwaliduje). Wylosuj
   długi: `python3 -c "import secrets;print('kidwatch-'+secrets.token_hex(14))"`.
   **Nazwa tematu na ntfy.sh JEST hasłem** — nie ma tam żadnej kontroli dostępu,
   kto zna nazwę, czyta Twoje powiadomienia. Własny serwer ntfy jest lepszy.

### 5. Uruchom

```bash
cp config.example.yaml config.yaml    # wpisz profile_id i nazwy urządzeń
export NEXTDNS_API_KEY="..." NTFY_TOPIC="kidwatch-..."
uv sync
uv run python -m kidwatch test-notify  # próbny push
uv run python -m kidwatch run
```

---

## Czujka — najważniejsza część bez nadzoru

Na nienadzorowanym iPadzie dziecko **może** wyłączyć DNS. Jego iPad znika wtedy
z logów, co jest **nieodróżnialne od „iPad leży w szufladzie"**. To najgorszy
możliwy cichy błąd: serwis milczy i wygląda na sprawny.

Dlatego szum systemowy ma tu wartość. iPad odpytuje domeny Apple non stop, także
śpiąc. Cisza **licząca szum** znaczy jedno: przestaliśmy widzieć.

Trzy warstwy, każda pilnuje innej awarii:

| warstwa | wykrywa | reakcja |
|---|---|---|
| `stream_silence_minutes` (20) | zero zdarzeń ze **wszystkich** urządzeń — padł token, sieć, konto | push `kidwatch nie widzi ruchu DNS` |
| `device_silence_minutes` (180) | cisza **jednego** iPada, gdy inne raportują — zdjęty profil | push `iPad Kuby nie zgłasza się do DNS` |
| `livenessProbe` / `HEALTHCHECK` | proces **zawisł** — czujka nie zgłosi własnej śmierci, bo alarm wysyła ten sam proces | restart kontenera |
| czujka UniFi (opcjonalna) | iPad w domowym Wi-Fi przesłał > 20 MB w 15 min, a NextDNS nie ma od niego ani jednego zapytania — zdjęty profil DNS | push `<iPad> — profil DNS prawdopodobnie usunięty` |
| `tv.unreachable_alert_hours` (24) | telewizor bez jednego udanego odczytu przez dobę — tunel, ADB, klucz | push `<TV> — odczyt z urzadzenia nie dziala` |

Powtórzenia alarmu idą w rosnących odstępach (20 → 40 → 80 min, sufit 8 h), żeby
jedna awaria nie zrobiła kilkunastu pushy na dobę. Powrót do zdrowia też dostaje
powiadomienie (czujki DNS i UniFi). Każda awaria to osobny epizod — kolejna,
nawet tego samego dnia, znowu daje alarm i „wróciło”. Wyjątek: czujka telewizora
zgłasza brak odczytu najwyżej raz na dobę i nie wysyła „wróciło”.

W cichych godzinach cisza pojedynczego iPada nie alarmuje — nocą ma prawo być
wyłączony (`device_silence_ignore_quiet_hours`).

---

## Jak to działa

```
NextDNS /logs/stream (SSE)  ─┐
                             ├─→ classifier ─→ engine ─→ bramka (WhatsApp / e-mail)
AdGuard /control/querylog   ─┘   (app_map)     (czysty)   ntfy, Home Assistant
                                                  │
Google TV (ADB), UniFi ─────────────────────→  SQLite  ─→ panel WWW
                                     (sesje, kursor, dedup)
```

- **`sources/`** — wspólny interfejs dla źródeł DNS (NextDNS, AdGuard). Obok
  czujniki: `tv.py` (Google TV po ADB), `unifi.py` (obecność w Wi-Fi) i
  `device.py` (odczyt z iPada po lockdown, w klastrze wyłączony). Źródła DNS same ponawiają
  połączenia; błąd sieci nigdy nie przerywa iteracji.
- **`classifier.py`** — domena → szum / aplikacja / nieznane. Dopasowanie
  **najdłuższy wygrywa**, więc kolejność w `app_map.yaml` nie ma znaczenia.
  Plik przeładowuje się na gorąco po mtime; zepsuty YAML zostawia starą mapę.
- **`engine.py`** — wszystkie reguły. Zero I/O sieciowego, czas z wstrzykiwanego
  zegara. Stąd testy silnika bez jednego `sleep`.
- **`store.py`** — SQLite. Trzy rzeczy muszą przeżyć restart: otwarte sesje,
  klucze wysłanych powiadomień (idempotencja) i kursor strumienia.
- **`scheduler.py`** — pętla tików: domykanie sesji, podsumowanie, czujka,
  sprzątanie, tętno.

### Szum nie budzi i nie przedłuża sesji

Gdyby przedłużał, sesja nigdy by się nie skończyła — iPad odpytuje Apple bez
przerwy. Sesja kończy się na ostatniej **niesystemowej** aktywności.

### Restart nie dubluje pushy

Każde powiadomienie ma `dedup_key` zajmowany w SQLite atomowo. Powtórne
przetworzenie tych samych zdarzeń (np. po wznowieniu strumienia) nic nie wyśle.

### Restart nie gubi pushy

Pętle nie wysyłają same — dopisują powiadomienie do tabeli `outbox` w
`kidwatch.db`, a wysyła je osobne zadanie, po kolei. Wiszący kanał nie trzyma
więc tiku ani tętna (liveness).

Wpis znika z kolejki **dopiero, gdy przyjął go co najmniej jeden kanał**
(bramka odpowiedziała 2xx). Jeśli żaden nie przyjął — restart bramki przy
wdrożeniu, 502 z Mailguna — wpis zostaje i jest ponawiany co 30 s, 1, 2, 5,
10 min, potem co 15 min; przeżywa też restart kidwatch. Kolejne powiadomienia
czekają za nim, żeby „koniec sesji” nie przyszedł przed „startem”. Po dobie
(albo 100 próbach) wpis jest porzucany: WARNING w logu, „niedostarczone” w
historii panelu i alarm czujki `kidwatch nie dostarczyl powiadomien` (najwyżej
raz na dobę), który wyjdzie, gdy kanał wróci.

Cena: gdy kanał przyjmie push, a proces padnie, zanim skasuje wpis, po starcie
ten sam push przyjdzie drugi raz. Zgubiony jest gorszy niż zdublowany.

---

## Konfiguracja

Wszystko w `config.yaml` (wzór: `config.example.yaml`). **Sekrety wyłącznie ze
zmiennych środowiskowych:**

| zmienna | do czego | wymagana |
|---|---|---|
| `NEXTDNS_API_KEY` | klucz API NextDNS | przy `source.kind: nextdns` |
| `ADGUARD_PASSWORD` | hasło AdGuard Home | przy `source.kind: adguard` |
| `NTFY_TOKEN` | token ntfy | nie (publiczne tematy go nie wymagają) |
| `HA_WEBHOOK_ID` | webhook Home Assistant | przy włączonym HA |
| `NTFY_TOPIC` | temat ntfy (nazwa tematu jest hasłem, więc nie w pliku) | przy włączonym ntfy |
| `BRAMKA_KLUCZ` | klucz **wysyłkowy** bramki powiadomień RenaCode (w bramce: `BRAMKA_KLUCZ_KIDWATCH`) | przy włączonej bramce |
| `BRAMKA_KLUCZ_ADMIN` | klucz administracyjny bramki — panel: WhatsApp, wiadomość próbna | nie (bez niego panel bierze `BRAMKA_KLUCZ`, co działa tylko ze starym wspólnym kluczem) |
| `PANEL_TOTP_KEY` | szyfruje sekrety 2FA panelu WWW | nie (bez niego 2FA nie da się włączyć) |
| `UNIFI_API_KEY` | lokalne API kontrolera UniFi | przy `unifi.enabled` (bez niego czujka się nie uruchamia) |

Brak sekretu daje czytelny komunikat i kod wyjścia **2**, nie stack trace.

### Ważniejsze progi

| klucz | domyślnie | znaczenie |
|---|---|---|
| `idle_minutes` | 10 | cisza tak długa = koniec sesji |
| `app_cooldown_minutes` | 15 | nierozpoznany ruch: kolejne domeny zbiorczo co tyle minut; nazwana apka i tak raz na sesję (także w nowej sesji nie wcześniej niż po tym czasie) |
| `session_start_merge_seconds` | 20 | apka w tym okienku = wspólny push ze startem |
| `max_notifications_per_hour` | 12 | limit na urządzenie; nadmiar agregowany |
| `quiet_hours` | 21:30–07:00 | brak pushy o apkach, start sesji z priorytetem 5 |
| `night` | = `quiet_hours` | okno alarmu nocnego (`start`/`end`), `reminder_minutes: 30`, `enabled` |
| `weekly_report` | niedziela 19:00 | `weekday` (0=pon … 6=nd), `time`, `enabled` |
| `store.retention_days` | 30 | starsze zdarzenia kasowane (0 = nigdy) |

**Noc i ciche godziny to jeden push, nie dwa.** Start sesji w oknie nocy
dostaje formę nocną (`🌙 Kuba używa iPada w nocy — 23:12, YouTube`, z „w domu”
/ „poza domem”, gdy czujka UniFi ma świeży odczyt) zamiast dopisku „W CICHYCH
GODZINACH”. Sesja zaczęta wieczorem, która trwa w noc, dostaje ten push, gdy
w nocy pojawi się aktywność; potem przypomnienie co `reminder_minutes`.

**Raport tygodnia** (automatyczny, niedziela 19:00) liczy sesje od poprzedniej
niedzieli 19:00 do bieżącej 19:00; czas „dokładnie” z TV (liczniki Androida)
zostaje w tygodniu kalendarzowym pon–nd. Ręcznie liczy się cały tydzień ISO
(pon–nd, bez odcięcia o 19:00; bez `--week` w niedzielę bieżący, w inny dzień
ostatni pełny), bez zajmowania dedupu:
`python -m kidwatch weekly [--week 2026-W40] [--dry-run]` (bez `--dry-run`
wysyła też kanałami).

**Limit godzinowy nie dławi** startu sesji, czujki, nocy, raportów ani czasu gry.
Zdławienie „iPad włączył się o 2 w nocy" zniweczyłoby sens serwisu; start sesji
jest z natury ograniczony przez `idle_minutes`, więc sam nie zrobi lawiny.

### Sesje „w tle” nie istnieją

iPad leżący na biurku też odpytuje DNS: odświeżenie YouTube w tle, OCSP
certyfikatu, powiadomienie gry. Każde takie zapytanie otwierało sesję
„0 min” z pushem start i koniec. Teraz sesja jest **potwierdzona** dopiero,
gdy w oknie `engine.confirm_minutes` (5 min) aktywność (aplikacja albo nieznana
domena) ma:

- co najmniej `engine.confirm_moments` (3) **odrębne chwile** rozpięte na
  minutę lub dłużej — chwila to zapytania w ciągu 10 s od jej pierwszego
  zapytania, więc pakiet kilkunastu zapytań w jednej sekundzie liczy się raz;
- albo rozpiętość co najmniej 3 minut (gra, która z własnym zapleczem gada
  rzadko).

Push startu wychodzi wtedy z godziną faktycznego początku. Niepotwierdzona
sesja zamyka się po cichu i zostaje w bazie (`sessions.confirmed=0`)
wyłącznie do diagnostyki — nie liczy się do podsumowań, raportów, wykresów,
agregatów ani alarmu nocnego. Nie liczymy jej osobno jako „tło”: to minuty
zerowe i liczba bez działania, a rosnące „sesje tła” wyglądałyby jak problem.

Dlaczego chwile, a nie zapytania: odświeżenie YouTube w tle na leżącym iPadzie
(produkcja, 10.2026) to `youtubei.googleapis.com`, `redirector` i kilka
`rr*.googlevideo.com` w tej samej sekundzie, czasem jeszcze jedno `rr*` po 1–2
minutach — i cisza. Dawna reguła „seria 5 zapytań aplikacji w minucie”
potwierdzała taki pakiet, a „≥ 1 min ruchu” — pakiet z jednym spóźnionym
zapytaniem. To dwie chwile, a nie trzy. Oglądanie dociąga segmenty co
kilkanaście sekund i potwierdza się po ~minucie, gra z ruchem co 30–60 s po
1–2 minutach. Stary klucz `engine.confirm_burst_events` jest ignorowany
(zostaje dla zgodności konfiguracji).

Okno 5, nie 3 minuty: gra w trakcie rozgrywki odzywa się co ~3–3,5 min
(nagranie Asphalta w `tests/fixtures/day.jsonl`) i przy 3 minutach prawdziwa
półgodzinna sesja nie potwierdziłaby się nigdy.

### Profil: hasło i WhatsApp

Avatar w nagłówku → **Profil**: weryfikacja dwuetapowa, zmiana hasła (stare +
nowe, min. 12 znaków; wylogowuje inne sesje) i **Powiadomienia / WhatsApp**:
stan kanałów bramki, „Połącz WhatsApp” (QR z WAHA odświeżany co 20 s do
`WORKING`; to tu podpinasz numer bota), „Wyślij test”, „Rozłącz” i lista
**odbiorców WhatsApp**. Panel woła bramkę po stronie serwera kluczem
`BRAMKA_KLUCZ_ADMIN` (wysyłka powiadomień idzie osobnym `BRAMKA_KLUCZ`);
przeglądarka nie zna żadnego z nich.

Odbiorcy (najwyżej 5): numer z kierunkowym, etykieta (≤ 40 znaków) i
przełącznik „aktywny”; „+ Dodaj odbiorcę”, „Usuń”, „Cofnij zmiany”. Zmiany
są lokalne, dopóki nie klikniesz „Zapisz listę” — zapis **całej** listy wymaga
hasła albo kodu 2FA (lista jest wspólna dla wszystkich aplikacji RenaCode,
sama sesja nie wystarcza). Błędne potwierdzenie liczy się do blokady konta;
błąd w liście (zły numer, powtórka) odpada wcześniej, z 400, bez sprawdzania
hasła. „Wyślij test do aktywnych” wysyła próbę tylko WhatsAppem i pokazuje,
do ilu doszła (np. „doszło do 1 z 2”, z zamaskowanym numerem tego, do kogo
nie doszło).

Bramka wysyła do wszystkich aktywnych naraz; gdy dojdzie do części, to
sukces bez maila, a e-mail idzie dopiero, gdy nie doszło do nikogo. Numery
widzi tylko zalogowany właściciel konta w Profilu; logi panelu i bramki mają
wyłącznie trzy ostatnie cyfry (`...200`). Endpoint:
`POST /api/profile/whatsapp/recipients`
`{"recipients": [{"number", "label", "active"}], "confirm": "<hasło albo kod>"}`
(stary `POST /api/profile/whatsapp/recipient` z jednym numerem zostaje).
Wymaga bramki z `POST /v1/whatsapp/odbiorcy` — przy starszej bramce Profil
pokazuje jej jedynego odbiorcę, ale zapis listy kończy się błędem.

### Treść powiadomień

Podsumowanie dnia, raport tygodnia i koniec sesji to sekcje per dziecko
i telewizor, z punktorami; tytuły TV skrócone (bez „ | kanał | tagi”,
najwyżej 5, „+N więcej”). W WhatsAppie nagłówki sekcji są pogrubione
(`*…*`), w mailu bramka zdejmuje gwiazdki. Panel dostaje te same dane w
postaci strukturalnej (`notifications.data`) i rysuje listy z mini-paskami;
stare wpisy pokazuje tekstem.

### Panel: wszystkie ekrany, trendy, archiwum

- **Wszystkie ekrany** — iPady (minuty z DNS) i telewizor (minuty odtwarzania,
  tytuły) na jednej osi dnia, z sumą dnia i tygodnia ISO. Przy wybranym
  dziecku telewizor jest osobnym, wyszarzonym pasem „TV (wspólny)” — da się
  go ukryć i **nie** jest doliczany do dziecka. Pod spodem czas aplikacji TV
  „dokładnie, z TV” (Android `dumpsys usagestats`, odczyt co
  `tv.usage_poll_minutes`) obok szacunku z sesji; ten sam czas trafia do
  raportu tygodnia.
- **Trendy** — tydzień do tygodnia i miesiąc do miesiąca per dziecko (suma,
  średnia dzienna, top aplikacje, minuty nocne) i wykres 12 tygodni.
- **Archiwum** — tabela `daily_rollup`: jeden wiersz na urządzenie i dzień
  (minuty, sesje, top aplikacje, minuty nocne, minuty TV z usagestats).
  Przeliczana co 15 min dla dziś i wczoraj, plus każdy dzień bez agregatu
  (pierwszy start zbiera całą istniejącą historię). Przeżywa
  `store.retention_days`; własna retencja `store.rollup_retention_days`
  (0 = bez limitu, domyślnie).
- **Eksport CSV** — `GET /api/export.csv?from=RRRR-MM-DD&to=RRRR-MM-DD&child=`
  (tylko po zalogowaniu; domyślnie ostatnie 30 dni, najwyżej 3660). Agregaty
  dzienne, UTF-8 z BOM (Excel), komórki zaczynające się od `= + - @`
  poprzedzone apostrofem.

### Czas gry (NextDNS)

Panel ma na karcie iPada przyciski **Zablokuj gry / Odblokuj / +30 min**.
Przełączają usługi i kategorie z `game_time` w kontroli rodzicielskiej
NextDNS (`active: true/false`). Blokady w NextDNS są ustawieniem **profilu**,
więc każde dziecko potrzebuje własnego profilu (`devices[].nextdns_profile`;
bez niego — profil główny). kidwatch czyta wtedy strumienie logów wszystkich
profili, każdy z własnym kursorem.

```yaml
game_time:
  enabled: true
  services: [youtube, roblox, minecraft, fortnite, tiktok, twitch]
  categories: [gaming]            # video-streaming blokuje tez Netflixa i Disney+
  default_bonus_minutes: 30
  block_schedule: {start: "20:00", end: "07:00"}   # opcjonalnie
```

- Kliknięcie tylko **zleca** zmianę (kolejka w `panel-auth.db`); wykonuje ją
  pętla serwisu — jedyny pisarz `kidwatch.db` — i wysyła push.
- Bonus liczy się od końca bieżącego bonusu, z sufitem `max_bonus_minutes`
  (180); po czasie pętla przywraca blokadę.
- Co `sync_minutes` (5) stan jest czytany z NextDNS. Zmiana zrobiona ręcznie
  w my.nextdns.io jest przyjmowana; nieudany zapis kidwatch — ponawiany co minutę.
- Harmonogram blokuje na początku okna i zdejmuje rano **tylko własną**
  blokadę — ręczna blokada z panelu zostaje.
- Id kategorii spoza listy NextDNS (`dating, gambling, gaming, piracy, porn,
  social-networks, video-streaming`) to błąd konfiguracji. Id usługi spoza
  znanej listy to tylko ostrzeżenie w logu — NextDNS dokłada usługi, a id,
  którego nie zna, odrzuci samo API (błąd w panelu i w pushu).

### Pauza monitoringu TV (wyjazd)

Gdy dzieci wyjeżdżają, a w domu telewizję oglądają inni, karta telewizora ma
przycisk **Wstrzymaj monitoring TV** — do daty i godziny (domyślnie za 7 dni)
albo do odwołania. W czasie pauzy panel pokazuje baner „Monitoring TV
wstrzymany do …” z przyciskiem **Wznów teraz**. iPady są monitorowane
normalnie (NextDNS działa poza domem).

- Telewizor w pauzie **nie jest odpytywany wcale** (ani odtwarzacz, ani
  usagestats): zero sesji, pushy i minut TV w sumach dnia i tygodnia. Czujka
  „TV nie odpowiada” milczy, a po pauzie liczy ciszę od jej końca. Pierwszy
  odczyt usagestats po pauzie tylko ustawia punkt odniesienia, żeby czas
  z pauzy nie wpadł do „dokładnie, z TV”.
- Oglądanie trwające w chwili włączenia pauzy kończy się po cichu na ostatnim
  odczycie.
- Push niskim priorytetem przy włączeniu („Monitoring TV wstrzymany do …”),
  przy zmianie terminu i przy końcu pauzy („Monitoring TV wznowiony”).
- Podsumowanie dnia i raport tygodnia dopisują w sekcji TV „monitoring
  wstrzymany od … do …”, a oś „Wszystkie ekrany” kreskuje ten czas.
- Jak czas gry: kliknięcie (sesja + CSRF) tylko **zleca** zmianę w kolejce
  w `panel-auth.db` z loginem; wykonuje ją tik pętli (do ~30 s). Stan i audyt
  (kto i kiedy włączył, kto albo termin zakończył) — tabela `tv_pause`
  w `kidwatch.db`, przeżywa restart.
- Z wiersza poleceń (zleca to samo zadanie, wykonuje je działający `run`):

  ```bash
  kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv-pauza --do 2026-10-10T18:00
  kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv-pauza --do-odwolania
  kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv-pauza --wznow
  kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch tv-pauza   # stan
  ```

  Termin bez strefy to czas lokalny z `timezone`.

### Mapa domen

`app_map.yaml`, przeładowywana na gorąco — lokalnie edytuj bez restartu.
W klastrze plik jest montowany z ConfigMapy przez `subPath`, który się nie
aktualizuje: zmiana idzie przez `checksum/app-map`, czyli restart poda.

```yaml
noise:                    # nie liczy się jako aktywność
  - apple.com
  - apple                 # Apple ma własny gTLD .apple i realnie go używa
apps:
  "Roblox":
    - roblox.com          # domena i wszystkie poddomeny
    - "*.rbxcdn.com"      # to samo, zapis dla czytelności
  "Coś":
    - "=tylko.example.com"  # DOKŁADNIE ta domena, bez poddomen
```

Szum ma pierwszeństwo przy identycznym wzorcu, ale **dłuższy wzorzec wygrywa** —
`music.apple.com` w `apps` bije `apple.com` w `noise`.

Ruch niesystemowy bez dopasowania trafia jako **„Przegladarka / inne"** — do
bazy, sesji i panelu. Osobnego pusha o nim domyślnie **nie ma**
(`engine.notify_unknown: false`): pierwszy dzień na żywo pokazał, że to prawie
wyłącznie zaplecze aplikacji (Google, analityka, reklamy), nie strony.

### Co widać z przeglądania

DNS zna **domenę**, nigdy adresu strony ani treści. To sufit tej metody i nic go
nie podniesie poza serwerem proxy z własnym certyfikatem CA (patrz niżej).

W granicach tego sufitu kidwatch nazywa rzeczy po imieniu, zamiast zlewać je
w „Przegladarka / inne":

```
[START]  iPad Kuby aktywny
         16:20 — super-gierka-online.com
[APKA]   Kuba
         Przegladarka / inne: forum-o-grach.pl, wikipedia.org, jakas-gazeta.pl
[KONIEC] iPad Kuby — koniec
         15:12–15:59, 47 min
         Roblox ~26 min, Przegladarka / inne ~14 min
         strony: forum-o-grach.pl, wikipedia.org, jakas-gazeta.pl
         (czasy szacunkowe — liczba minut z ruchem DNS)
```

Z `notify_unknown: true` push wychodzi przy **pierwszej** nierozpoznanej domenie, a kolejne czekają na
`app_cooldown_minutes` i idą zbiorczo — inaczej każde kliknięcie w przeglądarce
dawałoby osobne powiadomienie. Hosty jednej witryny są zwijane do jednej nazwy
(`a.sklep.pl`, `cdn1.sklep.pl` → `sklep.pl`).

Raport dzienny:

```bash
uv run python -m kidwatch web --days 7
```

```
=== niedziela 27.09.2026 ===

iPad Kuby (Kuba)
  aplikacje: YouTube ~37 min, Roblox ~36 min, Przegladarka / inne ~33 min
  strony (5 domen):
      10x  forum-o-grach.pl
      10x  super-gierka-online.com
       5x  wikipedia.org
```

Nazwy dni są wpisane po polsku na stałe, nie brane z `locale` — w kontenerze jest
`C`, w terminalu co innego, a raport ma wyglądać tak samo wszędzie.

### Czego nie zobaczysz i dlaczego nie warto próbować

Adresów stron, treści, wiadomości, historii w aplikacjach. Jedyna droga to serwer
proxy z własnym CA zainstalowanym na iPadzie. Technicznie możliwe na własnym
urządzeniu dziecka, ale: przypinanie certyfikatów wywala znaczną część aplikacji,
przechwytujesz też hasła i dane prywatne dzieci, a proxy staje się pojedynczym
punktem, którego kompromitacja oddaje wszystko. To kruche i nieproporcjonalne.

Czego DNS nie da nigdy, niezależnie od wysiłku:

| potrzeba | jedyne źródło |
|---|---|
| lista zainstalowanych aplikacji | kabel USB + `ideviceinstaller`, albo Ustawienia → Pamięć iPada |
| subskrypcje i zakupy w grach | paragony Apple w poczcie, Ustawienia → Subskrypcje |
| **zapobieganie** zakupom | „Poproś o zakup" w Chmurze rodzinnej — bije każde monitorowanie po fakcie |
| dokładny czas per apka, też offline | Czas przed ekranem (brak publicznego API) |
| gry działające offline | nic — są dla DNS niewidzialne |

### Trzy sekcje, trzy zachowania — i dlaczego to gry wymusiły

| sekcja | otwiera sesję | przedłuża otwartą | nadaje nazwę |
|---|---|---|---|
| `noise` | nie | **nie** | nie |
| `shared` | nie | **tak**, w oknie `shared_extend_minutes` | nie |
| `apps` | tak | tak | tak |

`shared` istnieje z powodu gier. Asphalt gada z `gameloft.com` raz na kilka minut,
a z CloudFrontem bez przerwy. Gdyby CDN-y były szumem, sesja grania byłaby
sztucznie krótka albo w ogóle by nie powstała; gdyby były aplikacją, reklama
dociągnięta w tle budziłaby Cię pushem w nocy.

Przedłużanie jest **ograniczone** progiem `shared_extend_minutes` (domyślnie 30),
liczonym od ostatniego **rozpoznanego** zdarzenia. Bez tego odświeżanie aplikacji
w tle trzymałoby sesję otwartą bez końca i żaden czas nie miałby sensu.

Czego `shared` celowo **nie** zawiera: `akamaiedge.net` i `akadns.net`. Gry z nich
korzystają, ale na iPadzie dominuje tam ruch Apple w tle — przedłużanie nim sesji
zniweczyłoby ogranicznik.

### Gry to najtrudniejszy przypadek

Gry wykrywa się gorzej niż streaming, z trzech powodów:

1. **Grają offline.** Gra, która nie odpytuje sieci, jest dla DNS niewidzialna.
   Tego nie da się obejść — tylko Czas przed ekranem to pokaże.
2. **Jadą po współdzielonych CDN-ach.** Netify pokazuje, że Gameloft używa
   `gameloft.com` plus Akamai, CloudFront, AWS i Cloudflare. Tylko pierwsze da się
   przypisać.
3. **Wydawcy zmieniają zaplecze.** Każda lista domen napisana z góry gnije.

Dlatego jest komenda, która zamyka lukę z **prawdziwych** danych:

```bash
uv run python -m kidwatch domains --unknown-only
```

```
domena                                 kategoria   zapytan  hostow  aplikacja
----------------------------------------------------------------------------
super-gierka-online.com                unknown          10       2
forum-o-grach.pl                       unknown          10       1
```

Górę tej listy dopisujesz do `app_map.yaml` — plik przeładowuje się na gorąco,
restart zbędny. To jedyny wiarygodny sposób na dobre pokrycie gier.

---

## Wdrożenie

### k3s + ArgoCD (jak inne aplikacje w tym klastrze)

Chart Helm w `charts/kidwatch`. Aplikacja ArgoCD siedzi w prywatnym repo
infrastruktury (`renacode-infra/argocd-apps.yaml`) razem z pozostałymi.
Wdrożenie bez tej infrastruktury (własny obraz, ntfy zamiast bramki, własna
domena) opisuje [`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md),
sekcja „Bez infrastruktury RenaCode". Tutaj ArgoCD obserwuje
`charts/kidwatch/values.yaml`, a CI podbija w nim tag obrazu po każdym pushu na
`main`. Nie ma tu żadnego SSH ani `kubectl apply`.

Sekrety zakładasz **raz, ręcznie** — ArgoCD ich nie synchronizuje. Polecenia
są w [`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md) (krok 7):

| Sekret | zawartość | wymagany |
|---|---|---|
| `kidwatch-secrets` | `NEXTDNS_API_KEY`, `BRAMKA_KLUCZ`, `BRAMKA_KLUCZ_ADMIN`, `PANEL_TOTP_KEY`, opcjonalnie `UNIFI_API_KEY` | tak |
| `kidwatch-config` | prawdziwy `config.yaml` (wgrywa `tools/wgraj_konfiguracje.sh`) | tak |
| `kidwatch-adb` | `adbkey`, `adbkey.pub` zaakceptowane przez telewizor | przy czujniku TV |
| `kidwatch-pairing` | rekordy parowania `<UDID>.plist` | nie (montowany tylko przy `deviceRead.enabled: true`; w klastrze wyłączony) |

Rekord parowania zawiera **klucz prywatny hosta** — kto go ma, jest dla iPada
zaufanym komputerem. `.gitignore` blokuje `*.plist`, żeby nie trafił do repo.

Cztery rzeczy warte wiedzy:

- **`replicas: 1` + `strategy: Recreate` to warunek poprawności.** SQLite ma
  jednego pisarza; dwa pody rozjechałyby stan sesji i zdublowały pushe. Z tego
  samego powodu **odczyt z iPadów jedzie w tym samym procesie co DNS**, nie
  w osobnym kontenerze.
- **`prune: false`** w aplikacji ArgoCD, inaczej niż przy innych aplikacjach
  w tym klastrze.
  PVC z bazą ma `helm.sh/resource-policy: keep`; automatyczne kasowanie mogłoby
  usunąć wolumen razem ze stanem, a wtedy serwis wyśle wszystkie pushe od nowa.
- **`Synced` nie znaczy „proces czyta nową konfigurację".** Pod ma adnotację
  `checksum/config` z sumą `files/config.yaml`, ale prawdziwa konfiguracja
  jest w Sekrecie `kidwatch-config`, którego suma nie obejmuje — po jego
  zmianie restart robi `tools/wgraj_konfiguracje.sh`. `app_map.yaml` jest
  wyjątkiem — przeładowuje się na gorąco.
- **`charts/kidwatch/files/app_map.yaml` to kopia** pliku z korzenia (chart nie
  sięga poza swój katalog). Po zmianie mapy:
  `cp app_map.yaml charts/kidwatch/files/app_map.yaml`. Rozjazd wyłapuje
  `tests/test_deploy.py`.

### Tailscale — wyłączony

Chart ma kontener poboczny Tailscale (`tailscale.enabled`, domyślnie `false`)
z czasów, gdy odczyt iPadów miał iść przez tailnet. Sprawdzone 2026-10-02:
iOS przyjmuje lockdown (port 62078) tylko z tej samej sieci lokalnej, więc ani
Tailscale, ani tunel WireGuard do domu tego nie dają (`ConnectionResetError`).
Tailscale nie jest wdrożony i nie jest potrzebny. Telewizor i UniFi pod sięga
tunelem WireGuard VPS ↔ dom (`docs/uruchomienie-od-zera.md`, krok 4).

### docker compose

```bash
cp config.example.yaml config.yaml
printf 'NEXTDNS_API_KEY=...\nNTFY_TOPIC=...\n' > .env     # .env jest w .gitignore
docker compose up -d --build
```

Baza (`kidwatch.db`, `panel-auth.db`) ląduje na wolumenie `kidwatch-data`
w `/data` — `docker-compose.yml` ustawia `KIDWATCH_STORE_PATH`, które
nadpisuje `store.path` z konfiguracji.

---

## Profil: tryb zwykły a nadzorowany

Zweryfikowane w schemacie Apple. To, do jakich sieci stosuje się profil DNS,
zależy **wyłącznie** od sposobu instalacji:

| sposób | zakres sieci |
|---|---|
| **local install** (ręcznie, Apple Configurator) | **wszystkie** ✅ |
| **supervised** (MDM, urządzenie nadzorowane) | **wszystkie** ✅ |
| **device enrollment** (MDM bez nadzoru) | tylko sieci zarządzane ❌ |

Źródło: [`network.dns-settings.yaml`](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/network.dns-settings.yaml)
(linie 242–249) oraz nota w `com.apple.dnsSettings.managed.yaml` (257–259).

**Wniosek: nie zakładaj organizacji MDM.** Apple Business Manager wymaga podmiotu
prawnego i numeru D-U-N-S, a MDM bez nadzoru daje **gorsze** pokrycie sieci niż
ręcznie zainstalowany profil. Nadzór (Apple Configurator, kabel, **wymazanie
iPada**) to jedyne, co dokłada realne blokady.

Z `--supervised` generator dodaje klucze, które **działają wyłącznie na
urządzeniu nadzorowanym** — na zwykłym iPadzie iOS je zignoruje:

| klucz | od | blokuje |
|---|---|---|
| `ProhibitDisablement` | iOS 14 | wyłączenie DNS w Ustawieniach |
| `PayloadRemovalDisallowed` | iOS 6 | usunięcie profilu |
| `allowCloudPrivateRelay: false` | iOS 15 | Private Relay omijający DNS |
| `allowVPNCreation: false` | iOS 11 | darmowy VPN z App Store |
| `allowUIConfigurationProfileInstallation: false` | iOS 6 | własny profil dziecka |

Dlatego **domyślny tryb ich nie wstawia**. Obecność klucza, który nic nie robi,
dawałaby złudzenie zabezpieczenia — a tu nie ma nic gorszego niż fałszywe
poczucie wglądu.

### Uwaga na przyszłość: payload jest `deprecated`

`com.apple.dnsSettings.managed` jest oznaczony jako **deprecated od OS 27**.
Następca to deklaracja DDM `com.apple.configuration.network.dns-settings`
(wprowadzona w 27.0), dostarczana przez serwer MDM. *Deprecated* nie znaczy
*usunięty* — stary payload działa. Flaga `--also-declaration` zapisuje obok plik
JSON z deklaracją DDM, gotowy na moment, gdy to się zmieni.

---

## Rozwój

```bash
uv sync
uv run pytest              # jedyne testy, ktore otwieraja gniazdo, to test_integration_live_http.py
uv run ruff check .
```

Odtworzenie realistycznego dnia i porównanie ze snapshotem:

```bash
uv run python -m kidwatch --config tests/fixtures/config.yaml \
  replay tests/fixtures/day.jsonl --dry-run
```

### Walidacja profilu przeciw schematowi Apple

`plutil -lint` sprawdza **wyłącznie składnię plista**. Klucz o złej nazwie, w złym
miejscu drzewa albo złego typu przechodzi lint bez mrugnięcia, a iOS **milcząco go
ignoruje** — profil instaluje się „poprawnie", tylko nie robi tego, co obiecuje.
Przy profilu, którego całą rolą jest blokowanie obejść DNS, to najgorszy możliwy
tryb awarii.

Dowód: profil z literówką `allowVPNCreaton` (zamiast `allowVPNCreation`) przechodzi
`plutil -lint` jako **OK**.

`tests/test_profile_schema.py` waliduje każdy emitowany klucz przeciw oficjalnemu
schematowi Apple — nazwa, typ, dozwolone wartości, poziom zagnieżdżenia i wymóg
nadzoru. Lista kluczy wymagających nadzoru jest **liczona ze schematu**, nie pisana
z pamięci. Indeks jest generowany z
[apple/device-management](https://github.com/apple/device-management):

```bash
uv run python tools/fetch_apple_schema.py   # odświeża tools/apple_schema_index.json
```

Ten test wykrył realny błąd: `ProhibitDisablement` był wstawiany do wnętrza
`DNSSettings`, a według schematu jest jego **rodzeństwem** na poziomie payloadu.
W złym miejscu iOS go ignoruje, więc tryb `--supervised` obiecywał blokadę,
której nie było.

### Czego nie da się przetestować wirtualnym iPadem

Nie da się. Apple nie pozwala na wirtualizację iPadOS, więc Parallels jest bez
znaczenia, a symulator iOS w Xcode **nie ma żadnego mechanizmu instalacji profilu
konfiguracyjnego** — `xcrun simctl` nie ma takiej podkomendy (flaga `--profiles`
dotyczy profili typów urządzeń CoreSimulatora, nie `.mobileconfig`).

Profil da się sprawdzić na prawdziwym systemie Apple w maszynie wirtualnej
**macOS** — payload `com.apple.dnsSettings.managed` wspiera macOS 11.0+ — ale to
weryfikuje macOS, nie iPadOS. Poza tym zostaje walidacja przeciw schematowi (wyżej)
i instalacja na prawdziwym iPadzie, która jest odwracalna.

### Testy integracyjne na prawdziwym gniazdku

Reszta testów jedzie na `httpx.MockTransport`, czyli na atrapie transportu —
żadne gniazdo się nie otwiera. To nie dowodzi, że po **faktycznym zerwaniu
połączenia TCP** źródło wznowi strumień od właściwego kursora.

`tests/test_integration_live_http.py` stawia dwa prawdziwe serwery HTTP/1.1 na
efemerycznych portach loopbacka i przepuszcza pełną ścieżkę: gniazdo → SSE →
parser → silnik → HTTP POST → odbiornik. Serwer NextDNS **rozłącza się w połowie
strumienia**, a test sprawdza, że ponowne połączenie przychodzi z `?id=evt-1`.

`replay` **nigdy nie dotyka prawdziwej bazy** (używa `:memory:`) — inaczej jeden
przebieg testowy zająłby klucze dedupu i zablokował prawdziwe powiadomienia.

Zmiana scenariusza dnia: edytuj `tools/gen_fixture_day.py`, potem odśwież
fixture i snapshot (komendy w jego docstringu).

### Decyzja, która odchodzi od oczywistego

**ntfy dostaje JSON, nie nagłówki HTTP.** Nagłówki nie przenoszą UTF-8 — httpx
koduje je kodekiem `ascii`, więc tytuł z polskim znakiem wywala całą wysyłkę
wyjątkiem `UnicodeEncodeError`. Imiona dzieci to dokładnie te napisy, które
wchodzą do tytułu. Test `test_naglowki_http_naprawde_nie_przenosza_polskich_znakow`
utrwala ten powód.

---

## Prywatność

Logi DNS pokazują, z czym łączy się urządzenie. To dane o dzieciach — trzymaj
je u siebie, na własnym profilu NextDNS i własnym serwerze ntfy, i nie dawaj
dostępu nikomu, komu nie musisz. Warto, żeby dzieci wiedziały, że iPady mają
filtr DNS; kidwatch nie jest narzędziem do ukrywania nadzoru.

## Licencja

MIT — patrz [LICENSE](LICENSE). *License: MIT.*
