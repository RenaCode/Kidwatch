# Wiele domów (gospodarstw) w jednym Kidwatchu — projekt

Stan: **projekt zaakceptowany** (decyzje właściciela z 2026-10-11 w §8);
**etap E1 zrealizowany** — model, migracja do Domu 1 i `HomeRuntime`,
kontrakt dla kolejnych etapów w docstringu `src/kidwatch/domy.py` (ustalenia
z realizacji: §7, E1). Podstawa: `main` po #43 i #44 oraz
otwarty #45 (powiadomienia per konto), który zostanie scalony wcześniej
i jest tu traktowany jako punkt wyjścia.

## 0. Cel i granice

Kidwatch obsługuje dziś **jeden dom**: jeden `config.yaml` (Sekret
`kidwatch-config`), jeden zestaw kluczy w Sekrecie `kidwatch-secrets`, jedna
baza `kidwatch.db`, jeden silnik. Wymaganie właściciela:

- **Dom 1** — dom właściciela: UniFi, telewizor (Android TV, ADB + aplikacja
  Kidwatch TV), iPady (NextDNS + `kidwatch-mdm`), docelowo iPhone'y.
- **Dom 2** — dom zaproszonej rodziny (np. szwagra): telefon dziecka
  z Androidem pod Family Link przez Prywatny DNS → NextDNS; zwykle bez UniFi
  i TV.
- Dostęp do domu przez **zaproszenie do zarządzania**. Kto zarządza domem,
  ustawia jego integracje (UniFi, TV, iPad/iPhone/Android, NextDNS).
- **Nic z jednego domu nie jest widoczne ani sterowalne z drugiego**: dane,
  powiadomienia, komendy MDM, telewizor, czas gry, sekrety.

Poza zakresem: rozliczenia, samodzielna rejestracja obcych osób, wiele
instancji Kidwatcha, multi-tenant dla nieznajomych. To narzędzie dla kilku
spokrewnionych domów, prowadzone przez jednego operatora (właściciela
klastra).

**Uczciwa granica izolacji.** Izolacja jest na poziomie aplikacji. Operator
klastra (właściciel) ma `kubectl exec`, klucz szyfrujący i bazę — technicznie
może zajrzeć w dane Domu 2. Tego kod nie zmieni; zaproszony dom musi to
wiedzieć i się na to zgodzić (decyzja 5, §8). Kod gwarantuje natomiast, że
**żadna ścieżka w panelu, API, pushach ani w pętlach** nie przenosi danych
ani poleceń między domami. Jedynym kontem z wglądem w każdy dom jest
**administrator instalacji** (§2.3) — jawnie, z wpisem w dzienniku audytu
przy każdym wejściu do domu, w którym nie jest członkiem. Prywatne konto
właściciela jest zwykłym członkiem Domu 1 i cudzych domów nie widzi.

## 1. Co w obecnym kodzie jest „jednym domem”

Przegląd `main` — miejsca, które trzeba ruszyć, i to, co da się zostawić.

| Miejsce | Dziś | Konsekwencja |
|---|---|---|
| `config.py: Config` | jeden obiekt: `source`, `devices`, `engine`, `watchdog`, `notifiers`, `tv`, `unifi`, `game_time`, `mdm`, `panel`, `store` | trzeba rozdzielić na część **instancji** i część **domu** |
| sekrety | zmienne środowiskowe z `kidwatch-secrets`: `NEXTDNS_API_KEY`, `UNIFI_API_KEY`, `TV_SONY_PSK`, `NTFY_TOPIC`/`NTFY_TOKEN`, `HA_WEBHOOK_ID`, `BRAMKA_KLUCZ(_ADMIN)`, `PANEL_TOTP_KEY`; `MDM_ADMIN_TOKEN`; klucz ADB w `/adb` | jedna wartość na proces, nie da się mieć dwóch kluczy NextDNS ani dwóch UDM |
| `store.py` | tabele kluczowane **nazwą urządzenia** (`sessions.device`, `events.device`, `daily_rollup(day, device)`, `app_cooldown(device, app)`), meta: `cursor:nextdns:<profil>`, `game:<profil>`, `mdm:events`, `wd:*`, `daily_sent:<dzień>` | dwa domy z „iPad Dziecka 1” lub tym samym dniem podsumowania zderzyłyby się w jednej bazie |
| `engine.py` | `Engine(cfg, store, classifier)`; pętle po `cfg.devices`, cisza nocna, podsumowania, czujki | silnik jest **czysty względem domu** — wystarczy dać mu konfigurację jednego domu i jego bazę |
| `__main__.py: cmd_run` | jedno źródło, jeden tik, jeden outbox, opcjonalnie pętle: device, tv, unifi, mdm, game; koniec dowolnego zadania kończy proces | trzeba zgrupować zadania per dom i rozdzielić awarie |
| `panel.py` | `PanelQueries(cfg)` na jednej bazie `mode=ro`; `_wymaga(session, uprawnienie)`; `POST /api/mdm/command` przekazuje **dowolny** UDID z ciała do serwera MDM | brak pojęcia domu w zapytaniu; MDM bez sprawdzenia, czy UDID jest „nasz” |
| `panel_auth.py` + `uprawnienia.py` | `users.rola` (`wlasciciel`/`podglad`), `user_uprawnienia` — globalnie | rola musi zależeć od domu |
| `panel_sso.py` | `Remote-User` == `users.login`, kont nie zakłada się w locie, grupy `wlasciciel`, `rodzina` | zaproszenie to jedyny wyjątek od „nie zakładamy w locie” |
| `gametime.py`, `tvpause.py` | kolejki `game_requests`, `tv_pause_requests` w `panel-auth.db`, bez domu | kolumna `dom_id` |
| `sources/tv_app.py` | singleton `AKTYWNA`, token w `<katalog bazy>/tv-app/token` | rejestr per dom, katalog per dom |
| `mdm.py` + `kidwatch_mdm` | jeden token admina na cały serwer; `enrollments.label` → `policy.devices[label]`; jeden certyfikat APNs | serwer musi znać dom urządzenia i ograniczać token do domu |
| #45 | `user_powiadomienia` (kanały, kategorie, cisza, dzieci) per konto; `powiadomienia_ustawienia.tryb` (`trasy`/`konta`) globalnie; kanały domowe ntfy/HA | kanały zostają per osoba, **preferencje i tryb — per dom** |
| sieć | pod dochodzi do LAN Domu 1 tunelem WireGuard VPS ↔ UDM; NetworkPolicy egress `wDomu` wpuszcza tylko ADB TV i UDM | Dom 2 nie ma tunelu; adres wpisany przez zarządcę Domu 2 nie może trafić w LAN Domu 1 (SSRF, §3.6) |

## 2. Model danych

### 2.1 Decyzja główna: osobna baza zdarzeń na dom

**Każdy dom ma własny plik SQLite z danymi monitoringu** (dzisiejszy schemat
`store.py` bez zmian), a dane wspólne — konta, domy, członkostwa, integracje,
zaproszenia, kolejki zadań — leżą w bazie panelu (`panel-auth.db`).

| | Baza per dom (wybrane) | Kolumna `dom_id` w każdej tabeli |
|---|---|---|
| izolacja | konstrukcyjna: połączenie domu A nie widzi wierszy B | każde zapytanie musi pamiętać o `WHERE dom_id` — jeden brak = wyciek |
| migracja Domu 1 | **zero kopiowania**: `/data/kidwatch.db` staje się bazą Domu 1 | przebudowa tabel z kluczami złożonymi (SQLite 3.40 w produkcji, bez `DROP CONSTRAINT`) |
| wycofanie | stary obraz czyta ten sam plik | stary obraz nie zna `dom_id` w kluczach głównych |
| jeden pisarz | zachowany: pisze tylko środowisko uruchomieniowe danego domu | zachowany, ale wszystkie domy w jednym pliku i jednej blokadzie |
| klucze meta / dedup | bez zmian, nie zderzają się | trzeba prefiksować wszystkie (`wd:*`, `daily_sent:*`, `cursor:*`…) |
| retencja, kopia, usunięcie domu | per plik | `DELETE … WHERE dom_id` w kilkunastu tabelach |

Ścieżki: Dom 1 — `/data/kidwatch.db` (jak dziś), kolejne —
`/data/domy/<id>/kidwatch.db`, obok `tv-app/` i ewentualny klucz ADB
(materializowany z sejfu, §3).

### 2.2 Tabele w bazie panelu (`panel-auth.db`)

Wszystkie przez `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN` — tak samo jak
dziś (produkcja: SQLite 3.40).

```sql
-- Dom (gospodarstwo). id=1 to dom właściciela, zakładany przy migracji.
CREATE TABLE IF NOT EXISTS domy (
    id                  INTEGER PRIMARY KEY,
    nazwa               TEXT NOT NULL,             -- „Dom 1”, wyświetlana
    strefa              TEXT NOT NULL DEFAULT 'Europe/Warsaw',
    -- 'yaml' = konfiguracja z config.yaml (tylko dom 1, etap przejściowy),
    -- 'baza' = z tabel poniżej.
    zrodlo_konfiguracji TEXT NOT NULL DEFAULT 'baza',
    -- Ustawienia domu niebędące sekretami ani urządzeniami: engine, watchdog,
    -- game_time, cisza nocna, podsumowania (JSON walidowany modelem HomeConfig).
    ustawienia          TEXT NOT NULL DEFAULT '{}',
    -- Klucz danych domu (DEK) zaszyfrowany kluczem z Sekretu (KEK), §3.
    dek_zaszyfrowany    BLOB,
    kek_id              TEXT,
    -- Sieci, do których integracje domu mogą się łączyć (CIDR, JSON).
    -- Ustawia WYŁĄCZNIE administrator instancji (CLI), §3.6.
    dozwolone_sieci     TEXT NOT NULL DEFAULT '[]',
    wersja              INTEGER NOT NULL DEFAULT 1, -- +1 przy każdej zmianie: sygnał przeładowania
    zawieszony          INTEGER NOT NULL DEFAULT 0,
    utworzony_at        REAL NOT NULL
);

-- Konto ↔ dom. Brak wiersza = konto nie widzi domu w ogóle (404, nie 403).
CREATE TABLE IF NOT EXISTS czlonkostwa (
    dom_id         INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rola           TEXT NOT NULL,     -- 'wlasciciel-domu' | 'zarzadca' | 'podglad'
    od             REAL NOT NULL,
    zaproszenie_id INTEGER,           -- skąd się wzięło (audyt)
    PRIMARY KEY (dom_id, user_id)
);

-- Odstępstwa od roli W DOMU (następca user_uprawnienia z #44).
CREATE TABLE IF NOT EXISTS czlonkostwa_uprawnienia (
    dom_id      INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    uprawnienie TEXT NOT NULL,
    nadane      INTEGER NOT NULL,
    PRIMARY KEY (dom_id, user_id, uprawnienie),
    FOREIGN KEY (dom_id, user_id) REFERENCES czlonkostwa (dom_id, user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dzieci (
    id        INTEGER PRIMARY KEY,
    dom_id    INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    nazwa     TEXT NOT NULL,          -- jak dziś DeviceConfig.child
    kolejnosc INTEGER NOT NULL DEFAULT 0,
    UNIQUE (dom_id, nazwa)
);

CREATE TABLE IF NOT EXISTS urzadzenia (
    id              INTEGER PRIMARY KEY,
    dom_id          INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    dziecko_id      INTEGER REFERENCES dzieci (id),  -- NULL = wspólne (TV)
    rodzaj          TEXT NOT NULL,     -- 'ipad' | 'iphone' | 'phone-android' | 'tv'
    nazwa           TEXT NOT NULL,     -- = DeviceConfig.display_name = klucz w bazie domu
    source_ids      TEXT NOT NULL DEFAULT '[]',  -- identyfikatory w NextDNS/AdGuard
    nextdns_profile TEXT,              -- NULL = profil główny domu
    unifi_mac       TEXT,
    unifi_ip        TEXT,
    udid            TEXT,              -- iOS: odczyt wprost i MDM
    host            TEXT,              -- iOS: odczyt wprost (IPv4 w LAN domu)
    mdm             INTEGER NOT NULL DEFAULT 0,  -- zapisany w kidwatch-mdm
    ustawienia      TEXT NOT NULL DEFAULT '{}',  -- known_apps, aliasy, dla TV: port, apps…
    UNIQUE (dom_id, nazwa)
);
-- UDID jest globalnie jednoznaczny: jedno urządzenie należy do jednego domu.
CREATE UNIQUE INDEX IF NOT EXISTS ux_urzadzenia_udid ON urzadzenia (udid) WHERE udid IS NOT NULL;

-- Integracja domu: jawne ustawienia osobno, sekrety zaszyfrowane osobno.
CREATE TABLE IF NOT EXISTS integracje (
    dom_id         INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    typ            TEXT NOT NULL,     -- 'nextdns' | 'adguard' | 'unifi' | 'tv' | 'mdm' | 'ntfy' | 'homeassistant'
    wlaczona       INTEGER NOT NULL DEFAULT 0,
    ustawienia     TEXT NOT NULL DEFAULT '{}',  -- np. unifi: url, site, cert_sha256, progi
    sekrety        BLOB,              -- AES-GCM(DEK) z JSON {pole: wartość}, §3
    sekrety_pola   TEXT NOT NULL DEFAULT '[]',  -- jakie pola są ustawione (do panelu, bez wartości)
    zmienione_przez TEXT,
    zmienione_at   REAL,
    PRIMARY KEY (dom_id, typ)
);

CREATE TABLE IF NOT EXISTS zaproszenia (
    id              INTEGER PRIMARY KEY,
    dom_id          INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,   -- SHA-256 tokenu; sam token nigdzie nie leży
    rola            TEXT NOT NULL,
    dla             TEXT,                   -- oczekiwany login SSO (opcjonalnie) lub notatka
    utworzone_przez INTEGER NOT NULL REFERENCES users (id),
    utworzone_at    REAL NOT NULL,
    wygasa_at       REAL NOT NULL,
    przyjete_przez  INTEGER REFERENCES users (id),
    przyjete_at     REAL,
    odwolane_at     REAL,
    proby           INTEGER NOT NULL DEFAULT 0
);

-- Kto co zrobił w domu: zaproszenia, sekrety, komendy MDM, zmiany ról.
CREATE TABLE IF NOT EXISTS audyt (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    dom_id  INTEGER,                  -- NULL = zdarzenie instancji
    login   TEXT,
    akcja   TEXT NOT NULL,
    opis    TEXT NOT NULL             -- bez wartości sekretów, z maskami
);
```

Zmiany istniejących tabel:

- `users`: `+ admin_instancji INTEGER NOT NULL DEFAULT 0` (nadawane
  i odbierane wyłącznie z CLI: `kidwatch user-admin <login> on|off`; nigdy
  z panelu, nigdy z nagłówka SSO, nie przy migracji — §6). `users.rola` zostaje do końca okresu wycofania (§5) jako lustro roli
  w Domu 1 — stary obraz nadal z niej czyta.
- `game_requests`, `tv_pause_requests`: `+ dom_id INTEGER NOT NULL DEFAULT 1`.
- #45: `user_powiadomienia` dzielimy logicznie na
  **kanały osoby** (`whatsapp`, `email`, `kanal` — zostają w
  `user_powiadomienia`, jedno konto = jedna osoba w każdym domu) i
  **preferencje w domu** (`kategorie`, `cisza_*`, `dzieci`, `aktywne`) —
  nowa tabela `czlonkostwa_powiadomienia (dom_id, user_id, …)`.
  `powiadomienia_ustawienia` dostaje klucz z domem: `tryb:<dom_id>`.
- Kanały domowe #45 (ntfy, Home Assistant) stają się integracjami domu
  (`integracje.typ = 'ntfy' | 'homeassistant'`).

### 2.3 Role w domu i uprawnienia (#44 w kontekście domu)

Uprawnienia efektywne liczymy dla pary **(konto, dom)**:
`uprawnienia(rola w domu) + nadane − odebrane`, tą samą funkcją
`uprawnienia.efektywne`. Konto bez członkostwa w domu ma **pusty zbiór** —
z jednym wyjątkiem: **administrator instalacji** (`admin_instancji`,
niżej).

| Uprawnienie | Zakres | wlasciciel-domu | zarzadca | podglad |
|---|---|:-:|:-:|:-:|
| `konto.wlasne` | konto (globalne) | ✔ | ✔ | ✔ |
| `podglad.historia` | dom | ✔ | ✔ | ✔ |
| `mdm.podglad` | dom | ✔ | ✔ | – |
| `mdm.komendy` | dom | ✔ | ✔ | – |
| `czas_gry.zmiana` | dom | ✔ | ✔ | – |
| `tv.pauza` | dom | ✔ | ✔ | – |
| `tv.aplikacja` | dom | ✔ | ✔ | – |
| `powiadomienia.techniczne` (#45) | dom | ✔ | ✔ | – |
| `konta.zarzadzanie` (#45) | dom: członkowie **tego** domu | ✔ | – | – |
| **`dom.urzadzenia`** (nowe) | dzieci i urządzenia domu | ✔ | ✔ | – |
| **`dom.integracje`** (nowe) | ustawienia i sekrety integracji | ✔ | – | – |
| **`dom.zaproszenia`** (nowe) | tworzenie/odwoływanie zaproszeń | ✔ | – | – |
| `whatsapp.konfiguracja` | **instancja** (bot nadawcy) | tylko `admin_instancji` |||

Zasady:

- `whatsapp.konfiguracja` (QR bota, nadawca, test bramki) dotyczy wspólnego
  bota bramki — przechodzi do zakresu instancji. Zarządca Domu 2 nie może
  wylogować bota Domu 1.
- Nie da się zostawić domu bez członka z `konta.zarzadzanie` (reguła #45,
  per dom).
- Zaproszenie nie może nadać roli wyższej niż rola zapraszającego;
  `wlasciciel-domu` zaprasza dowolną rolę.
- **Administrator instalacji** (`users.admin_instancji = 1`, decyzja 5, §8)
  to **osobne konto administracyjne** (w Authelii: grupa `admins`), nie
  prywatne konto właściciela. Prywatne konto właściciela (grupa
  `wlasciciel`) jest zwykłym `wlasciciel-domu` w Domu 1 i nie widzi innych
  domów.
  - **Zakres**: każdy dom, pełny zestaw uprawnień domu (dane, urządzenia,
    integracje i ich sekrety — nadal tylko zapis/maska, nigdy odczyt
    wartości — zaproszenia, członkowie, MDM, czas gry, TV) plus uprawnienia
    instancji: zakładanie i zawieszanie domów, `dozwolone_sieci`,
    `whatsapp.konfiguracja`, alarmy instancji.
  - **Skąd**: wyłącznie flaga w `panel-auth.db`. Nagłówek `Remote-Groups`
    niczego nie nadaje (jak dziś, `panel_sso.py`), ale działa jako
    bezpiecznik: przy sesji `sso` uprawnienia administratora są aktywne
    tylko, gdy `Remote-Groups` zawiera `admins`. Flaga omyłkowo nadana
    prywatnemu kontu (grupa `wlasciciel`) więc nic nie otwiera. Przy
    sesji z hasła (droga awaryjna, port-forward) — tylko z włączonym TOTP.
  - **Audyt**: każde żądanie administratora do `/api/domy/<id>/…` domu,
    w którym nie ma członkostwa, zapisuje wiersz w `audyt`
    (`akcja = 'admin.wglad'` dla GET — najwyżej jeden wiersz na dom
    i sesję na 15 min, żeby przeglądanie nie zalało dziennika;
    `akcja = 'admin.<akcja>'` dla **każdego** POST). Członkowie domu
    z `konta.zarzadzanie` widzą te wpisy w panelu (*Dom → Dziennik*).
  - **Bez członkostwa nie dostaje powiadomień domu** — tylko alarmy
    instancji. W przełączniku domów widzi wszystkie, cudze oznaczone
    „administracja”.
  - Administrator może być jednocześnie członkiem domu (wtedy w tym domu
    działa jak członek, bez wpisów `admin.wglad`), ale rekomendacja jest
    odwrotna: konto administracyjne bez członkostw.

### 2.4 Rodzaje urządzeń

`DeviceKindName` rośnie z `ipad | phone` do `ipad | iphone | phone-android`;
telewizor zostaje osobną ścieżką (`sources/tv*.py`), ale w tabeli
`urzadzenia` ma `rodzaj = 'tv'`, żeby był przypisany do domu.

| Rodzaj | DNS | Odczyt wprost | MDM | Uwagi |
|---|---|---|---|---|
| `ipad` | NextDNS (profil / DDM) | lockdown, tylko z LAN domu | tak | jak dziś |
| `iphone` | NextDNS (profil / DDM) | lockdown, tylko z LAN domu | tak (bez nadzoru: ograniczenia ignorowane) | etap E5 |
| `phone-android` | Prywatny DNS → NextDNS | brak (walidator jak dziś dla `phone`) | brak (Family Link) | `phone` w YAML zostaje aliasem |
| `tv` | opcjonalnie `nextdns_ids` | ADB / aplikacja TV / Sony REST | – | wymaga osiągalności LAN domu |

### 2.5 Konfiguracja: instancja kontra dom

`Config` dzielimy na dwa modele pydantic, nie zmieniając semantyki pól:

- **`InstanceConfig`** — `panel`, `store` (retencja jako domyślna),
  `notifiers.bramka` (adres i klucz wysyłkowy aplikacji), adres serwera MDM,
  `app_map_path`, `device_read.pair_record_dir`.
- **`HomeConfig`** — `timezone`, `source`, `devices`, `engine`, `watchdog`,
  `tv`, `unifi`, `game_time`, `mdm` (progi czujek), `ntfy`/`homeassistant`,
  `device_read` (bez katalogu rekordów). To **dokładnie dzisiejszy `Config`
  bez części instancji** — walidatory (`_profiles_need_nextdns`,
  `_device_ids_unique`, `_tv_name_unique`…) działają per dom bez zmian.

`Engine`, `Store`, `Outbox`, watchery dostają `HomeConfig` zamiast `Config`
— dla nich to ten sam kształt. Sekrety, które dziś pobierają metody
`api_key()`/`token()` z env, w `HomeConfig` pochodzą z **dostawcy sekretów
domu** (`SekretyDomu.get("nextdns", "api_key")`), który dla Domu 1 w trybie
`yaml` czyta env jak dziś.

## 3. Sekrety integracji

### 3.1 Gdzie

Sekrety domu (klucz API NextDNS, klucz UniFi, PSK Sony, klucz ADB, token
aplikacji TV, temat i token ntfy, webhook HA, token MDM domu) trzymamy
**w bazie panelu, zaszyfrowane kopertowo**:

```
KEK  (Key Encryption Key) — 32 B z Sekretu k8s: kidwatch-secrets/KIDWATCH_KEK
 └─ DEK domu (32 B, losowy) — w domy.dek_zaszyfrowany = AES-GCM(KEK, aad="kidwatch:dom:<id>:dek:<kek_id>")
     └─ sekrety integracji — integracje.sekrety = AES-GCM(DEK, aad="kidwatch:dom:<id>:integracja:<typ>")
```

- AES-GCM jak dziś `panel_auth.SecretBox` dla TOTP (ta sama biblioteka,
  ten sam format: nonce + szyfrogram).
- **AAD wiąże szyfrogram z domem i typem.** Skopiowanie bloba z wiersza
  Domu 1 do Domu 2 (błąd w kodzie lub ręczna edycja bazy) kończy się
  `InvalidTag`, a nie cichym użyciem cudzego klucza.
- Panel **nigdy** nie odsyła wartości sekretu: pokazuje `sekrety_pola`,
  maskę (`…a1b2` dla kluczy, długość dla PSK), kto i kiedy zmienił. Zmiana
  sekretu wymaga świeżego potwierdzenia (`require_fresh_reauth`, jak QR bota).
- Sekret odszyfrowuje wyłącznie środowisko uruchomieniowe domu przy
  starcie/przeładowaniu i trzyma go w pamięci. Panel szyfruje przy zapisie,
  odszyfrowuje tylko przy teście połączenia z integracją.
- Klucz ADB i token aplikacji TV są czytane z pliku, więc środowisko domu
  zapisuje je przy starcie do `emptyDir` z `medium: Memory`
  (`/run/kidwatch/domy/<id>/`, prawa `0600`), a nie na wolumen `/data` —
  na dysku leżą tylko zaszyfrowane.
- Brak `KIDWATCH_KEK` przy domach w trybie `baza` = te domy **nie startują**
  (alarm instancji), Dom 1 w trybie `yaml` działa dalej. Fail-closed tylko
  dla tego, co od klucza zależy.

### 3.2 Rotacja

- `KIDWATCH_KEK` + opcjonalny `KIDWATCH_KEK_POPRZEDNI`; `kek_id` = pierwsze
  8 znaków SHA-256 klucza. Odczyt próbuje klucza o pasującym `kek_id`.
- `kidwatch klucze-rotuj` przepakowuje **tylko DEK-i** (kilka wierszy),
  sekrety integracji zostają nietknięte. Po rotacji i restarcie
  `KIDWATCH_KEK_POPRZEDNI` usuwamy z Sekretu.
- `kidwatch dom-klucz-rotuj <dom>` — nowy DEK domu, przeszyfrowanie jego
  integracji (np. po usunięciu zarządcy, który mógł zrobić zrzut bazy).
- Rotacja **sekretów zewnętrznych** (nowy klucz NextDNS itd.) to zwykła
  edycja integracji w panelu.

### 3.3 Kopia

- Kopia `panel-auth.db` zawiera tylko szyfrogramy. **KEK nie może leżeć
  w tej samej kopii** — inaczej szyfrowanie nic nie chroni. KEK: menedżer
  haseł operatora + kopia Sekretów klastra (osobno od kopii PVC).
- Bez KEK kopia bazy panelu odtwarza konta, domy i urządzenia, ale
  integracje trzeba wpisać od nowa — to akceptowalne i opisane
  w runbooku.
- Test odtworzenia (E2): baza z kopii + KEK → `kidwatch domy --sprawdz`
  odszyfrowuje wszystkie integracje i zgłasza każdą, której się nie da.

### 3.4 Czego NIE trzymamy w repo (publicznym)

Bez zmian względem dzisiejszych zasad i `tests/test_repo_prywatnosc.py`:
imiona dzieci, nazwy urządzeń, ID profili NextDNS, UDID-y, numery seryjne,
MAC i IP z sieci domowych, adresy UDM/TV, numery telefonów, e-maile,
loginy SSO, tokeny zaproszeń, klucze, `KIDWATCH_KEK`, nazwy domów
inne niż „Dom 1”/„Dom 2”. Testy i fixture'y używają nazw generycznych
(„Dziecko 1”, „Dom A”) i pul dokumentacyjnych (RFC 5737). Nowe testy
z sekretami generują je w locie (`secrets.token_bytes`), nie wklejają
stałych wartości.

### 3.5 Co zostaje w Sekretach k8s

`KIDWATCH_KEK`, `PANEL_TOTP_KEY`, `BRAMKA_KLUCZ(_ADMIN)` (klucz aplikacji
w bramce — jeden na instancję), `MDM_ADMIN_TOKEN` (token instancji do
zakładania tokenów domów, §4.3), `kidwatch-config` (do czasu przejścia Domu 1
na `baza`). Wszystko, co jest „per dom”, przechodzi do bazy.

### 3.6 Adresy wpisywane przez zarządcę domu (SSRF)

Pod ma trasę do LAN Domu 1 przez tunel WireGuard, a NetworkPolicy egress jest
**jedna na poda** (`wDomu`: TV i UDM Domu 1). Zarządca Domu 2, wpisując jako
„UniFi” albo „TV” adres z LAN Domu 1, dostałby z poda połączenie do sieci
właściciela. Dlatego:

- Każda integracja z adresem (`unifi.url`, `tv.host`, `adguard.base_url`,
  `homeassistant.base_url`) jest sprawdzana względem `domy.dozwolone_sieci`
  **po rozwiązaniu nazwy** i przy każdym połączeniu (nie tylko przy zapisie
  — DNS rebinding). Adres prywatny/tunelowy spoza listy domu = odmowa.
- `dozwolone_sieci` ustawia wyłącznie `admin_instancji` z CLI. Dom 1 dostaje
  przy migracji sieci z obecnych `tv.host`/`unifi.url`; Dom 2 — pustą listę
  (tylko adresy publiczne, a i te dla UniFi/TV nie mają sensu bez tunelu).
- `cert_sha256` UniFi zostaje obowiązkowy — klucz API leci dopiero po
  zgodności odcisku (jak dziś).
- `nextdns.base_url` i `ntfy.server` — tylko z listy dozwolonych hostów
  (`api.nextdns.io`, `ntfy.sh` + ustawione przez admina instancji).

## 4. Izolacja

### 4.1 Zasada: kontekst domu jest jawny i niesiony od wejścia do wyjścia

- **API panelu**: wszystkie trasy danych domu pod `/api/domy/<id>/…`
  (`/api/domy/2/day`, `/api/domy/2/mdm/command`). Dom pochodzi ze ścieżki,
  nie z ciasteczka ani z ciała żądania — karta przeglądarki ze starym domem
  nie wyśle polecenia „do domu z sesji”.
- `_wymaga(session, dom_id, uprawnienie)`: najpierw członkostwo albo
  aktywne uprawnienie administratora instalacji (§2.3; wtedy wpis w `audyt`);
  brak obu = **404** „nie ma takiego domu”, żeby nie zdradzać istnienia
  cudzych domów; potem uprawnienie w tym domu (403).
- `POST_TRASY`/`GET_TRASY` dostają trzeci element: zakres `konto` |
  `dom` | `instancja`. Test przechodzi po wszystkich trasach i pada na trasie
  bez zakresu albo na trasie `dom` poza prefiksem `/api/domy/<id>/`.
- Stare trasy `/api/day` itd. przez jeden etap (E3) działają jako alias
  **tylko dla konta z dokładnie jednym członkostwem**; z dwoma — 409
  „wybierz dom”. W E4 znikają.
- `PanelQueries` per dom: rejestr `{dom_id: PanelQueries(home_cfg, db_path)}`.
  Każde zapytanie otwiera połączenie `mode=ro` do pliku **tego** domu —
  nie istnieje funkcja, która przyjmuje dom i może przeczytać inny plik.
- Walidacja wejścia po stronie domu: `child` w `/api/domy/<id>/game` musi
  należeć do dzieci tego domu, `udid` w `/mdm/*` do urządzeń tego domu
  (dziś: dowolny UDID przechodzi do serwera MDM — to trzeba zamknąć niezależnie
  od domów, §4.3).

### 4.2 Pętle, zdarzenia i powiadomienia

- **Środowisko domu** (`HomeRuntime`): `HomeConfig`, `Store` na pliku domu,
  `Engine`, `Outbox`, źródło DNS, watchery (device, tv, unifi, mdm, game).
  Każde zdarzenie wchodzi do silnika konkretnego domu; nie ma globalnej mapy
  `source_id → urządzenie`. Ten sam identyfikator NextDNS („iPad”) w dwóch
  domach jest dozwolony, bo każdy dom czyta **własne profile własnym kluczem**.
- `Notification` dostaje pole `dom_id`, ustawiane w `HomeRuntime` (nie
  w silniku) — outbox domu odrzuca notkę z innym `dom_id` (asercja + alarm
  instancji). Podwójna bariera na wypadek wspólnego kodu, który zgubi kontekst.
- **Odbiorcy (#45)**: `adresaci(notka, dom)` bierze profile tylko członków
  domu z ich preferencjami w tym domu i uprawnieniami w tym domu.
  Dedup per konto: `<klucz>@<login>` → `<klucz>@<login>@d<dom_id>` (klucz
  i tak żyje w bazie domu, sufiks dla czytelności logu bramki).
- **Tryb `trasy` (#45) jest dozwolony tylko w Domu 1.** W trybie tras
  odbiorców zna bramka (`whatsapp_odbiorcy`, trasy) — notka Domu 2 poszłaby
  do odbiorców Domu 1. Dom ≠ 1 wysyła wyłącznie w trybie `konta`; gdy bramka
  nie deklaruje `funkcje: ["odbiorca"]`, outbox Domu 2 **wstrzymuje wysyłkę**
  (notki czekają w kolejce domu, nie giną) i zgłasza alarm instancji.
- Nadawca WhatsApp: wspólny bot bramki (decyzja 1, §8). Temat/stopka notki
  zawiera nazwę domu tylko, gdy odbiorca jest członkiem więcej niż jednego
  domu.
- **Czujki per dom**: cisza strumienia, cisza urządzenia, „profil DNS
  usunięty” (UniFi), TV/ADB, MDM (iPad cichy, profil zdjęty, nowa aplikacja)
  — idą do członków domu z kategorią `czujka` i `powiadomienia.techniczne`.
  **Czujki instancji** — certyfikat APNs, uzgadnianie serwera MDM, bramka,
  zgubione wpisy outboxa, awaria pętli dowolnego domu, brak KEK — idą tylko do
  `admin_instancji`. Zarządca Domu 2 nie dostaje alarmów o domu 1 i odwrotnie.
- Kolejki zadań z panelu (`game_requests`, `tv_pause_requests`) mają
  `dom_id`; pętla domu bierze tylko swoje wiersze.
- Aplikacja TV: `tv_app.AKTYWNA` → `tv_app.REJESTR[dom_id]`; token
  w katalogu domu.

### 4.3 MDM — wspólny serwer, rozdział po domu

Jeden `kidwatch-mdm` (jeden certyfikat APNs właściciela, jedna CA, jedno
`mdm.renacode.com`), ale z domem na każdym urządzeniu i ograniczonym tokenem:

- `enrollments` i `devices` w bazie MDM: `+ dom_id INTEGER NOT NULL DEFAULT 1`.
  Zapis (`POST /api/enrollments`) przyjmuje dom z **tokenu**, nie z ciała.
  Urządzenie dziedziczy dom z tokenu zapisu przy pierwszym `Authenticate`.
- **Tokeny admina per dom**: `MDM_ADMIN_TOKEN` (instancja) zakłada tokeny
  domów (`POST /api/tokens {dom_id}` → token pokazany raz; serwer trzyma
  SHA-256). Token domu widzi i steruje wyłącznie `devices.dom_id = <dom>`:
  `GET /api/devices` filtruje, `/api/devices/<udid>/*` dla obcego UDID = 404,
  `/api/events` filtruje po domu, `/api/os-update` jest per dom
  (`settings["os_update:<dom>"]`). Token domu leży w sekretach integracji
  `mdm` danego domu.
- Panel Kidwatcha sprawdza dodatkowo, że `udid ∈ urzadzenia(dom)` zanim
  zawoła serwer — dwie niezależne bariery.
- Polityka (`policy.yaml`): klucz urządzenia `<dom>/<etykieta>`
  (Dom 1 zachowuje stare etykiety bez prefiksu — dom 1 domyślnie);
  `restrictions`/`blocked_apps` mogą mieć nadpisania per dom.
- Czujka MDM po stronie Kidwatcha: osobny `MdmWatcher` na dom, z tokenem
  domu i kursorem w bazie domu (`mdm:events`). Alarmy certyfikatu APNs
  i uzgadniania — tylko z watchera instancji (token instancji).

### 4.4 Testy izolacji (obowiązkowe w E3, rozszerzane w każdym etapie)

1. **Bliźniacze domy**: fixture z Domem A i Domem B o **identycznych**
   nazwach dzieci, urządzeń i `source_ids`, ale znacznikach w danych
   (`app = "TYLKO-B"`, tytuł TV `"TYLKO-B"`). Dla każdej trasy GET z zakresem
   `dom` odpowiedź dla A nie zawiera `TYLKO-B` (przeszukanie całego JSON-u
   i CSV).
2. **Macierz członkostwa**: konto z rolą w A, bez członkostwa w B — każda
   trasa `/api/domy/B/…` = 404, w tym POST-y (czas gry, pauza TV, MDM,
   integracje, zaproszenia) — także dla prywatnego konta właściciela
   i dla konta z flagą `admin_instancji`, gdy sesja SSO nie ma grupy
   `admins`. Administrator z grupą `admins`: dostęp do B, a **każde**
   żądanie ma odpowiadający wpis w `audyt` (test liczy wpisy POST 1:1,
   GET — co najmniej jeden na sesję i dom); administrator nie jest
   adresatem żadnej notki domu B.
3. **Kompletność tras**: każda trasa ma zakres; trasa `dom` bez `<id>` w ścieżce
   = błąd testu (wzorem dzisiejszego pilnowania `POST_TRASY`).
4. **MDM**: komenda na UDID z B wysłana przez A → 404 w panelu i 404 na
   serwerze MDM z tokenem A (osobno, każda bariera sama).
5. **Powiadomienia**: zdarzenie w B nie daje adresata spoza członków B;
   tryb `trasy` dla B → wysyłka wstrzymana, alarm instancji, zero żądań
   do bramki.
6. **Sekrety**: blob integracji A wklejony do wiersza B → `InvalidTag`;
   odpowiedzi panelu i log nie zawierają wartości sekretu (sekret-kanarek
   w teście, szukany w całym wyjściu).
7. **SSRF**: `unifi.url` z sieci spoza `dozwolone_sieci` B → odmowa przy
   zapisie i przy połączeniu (nazwa rozwiązywana na adres zabroniony).
8. **Kanarki**: każda z barier z osobna usunięta mutacją w kodzie (brak
   sprawdzenia członkostwa, brak filtra `dom_id` na serwerze MDM, brak
   asercji `dom_id` w outboxie) — test musi to wykryć. Bez tego cisza testu
   niczego nie dowodzi.

## 5. Wydajność i procesy

### 5.1 Jeden pod, jeden proces, środowisko per dom

Zostajemy przy **jednym podzie i jednym procesie** (`replicas: 1`,
`Recreate`), bo panel czyta bazy wszystkich domów, a PVC jest RWO. Wewnątrz:

```
cmd_run
 ├─ panel (wątek, wspólny)                    — rejestr PanelQueries per dom
 ├─ nadzorca domów (asyncio)                  — start/stop/przeładowanie HomeRuntime
 │   ├─ HomeRuntime(dom 1): source, tick, outbox, tv, unifi, mdm, game, device
 │   └─ HomeRuntime(dom 2): source, tick, outbox[, mdm]
 └─ czujka instancji: MDM (APNs, uzgadnianie), stan bramki, stan domów
```

- **Awaria jednego domu nie zabija pozostałych.** Dziś koniec dowolnego
  zadania kończy proces (k8s restartuje cały pod). Z domami: wyjątek w zadaniu
  domu → nadzorca zatrzymuje cały `HomeRuntime` tego domu, restartuje go
  z narastającym odstępem (1, 2, 4… do 30 min), alarm instancji i czujka
  domu. Proces kończy się tylko przy awarii części wspólnej (panel, nadzorca).
- **Przeładowanie** bez restartu poda: zmiana integracji/urządzeń w panelu
  podnosi `domy.wersja`; nadzorca co 10 s porównuje wersje i restartuje tylko
  ten `HomeRuntime`. Kursory, sesje i dedup są w bazie domu, więc restart
  domu nie gubi stanu (ta sama gwarancja co dziś przy restarcie poda).
- **Tętno**: `KIDWATCH_HEARTBEAT` (liveness) dotyczy pętli zdarzeń procesu.
  Tik każdego domu ma własny znacznik czasu; tik stojący dłużej niż
  3× okres = restart tego domu + alarm, nie restart poda.

### 5.2 Limity API i rozkład w czasie

- **NextDNS**: strumienie SSE per profil, zamykane przez serwer co ~minutę,
  429 przy szybkim ponowieniu (`rate_limit_wait_seconds`,
  `ConnectGate`). Bramka połączeń (`ConnectGate`) jest **per klucz API**
  (konto NextDNS): dom z własnym kontem ma własną bramkę, dwa domy na jednym
  koncie — wspólną. Dodatkowo globalny limit liczby jednoczesnych strumieni
  (domyślnie 8) i rozłożenie pierwszych otwarć (losowe 0–30 s na dom).
  429 w Domu 2 nie opóźnia Domu 1, jeśli konta są różne.
- **Czas gry (NextDNS parentalControl)**: `GET` co `sync_minutes` per profil;
  ten sam klient z kluczem domu.
- **UniFi** (60 s), **TV** (30 s, `usagestats` co 15 min), **MDM** (60 s):
  per dom, z przesunięciem fazy startu, żeby domy nie pytały w tej samej
  sekundzie.
- **Kolejki panelu** (`game_requests` co 3 s): jeden czytnik dla wszystkich
  domów z `dom_id`, rozdzielający zadania do `HomeRuntime` — zamiast N pętli
  co 3 s na tej samej bazie.
- **SQLite**: osobny plik = osobna blokada; tik Domu 2 nie czeka na zapis
  Domu 1. `panel-auth.db` ma jak dziś dwóch pisarzy (panel, CLI) + nadzorcę
  (tylko odczyt konfiguracji i kolejek).
- **Pamięć**: limit poda 384 Mi; dom bez TV/UniFi to kilka klientów httpx
  i strumieni — szacunek 10–20 MiB na dom, do zmierzenia w E6
  (`kubectl top` przed/po). Argon2 (64 MiB, jeden slot) bez zmian.

### 5.3 Harmonogram

Podsumowanie dzienne, raport tygodniowy, cisza nocna, alarm nocny, okno
blokady gier — **per dom**, w strefie domu (`domy.strefa`). Retencja:
domyślna z instancji, nadpisywalna w `domy.ustawienia`. Sprzątanie
(`purge`) i agregaty (`rollup`) — w tiku domu, z przesunięciem.

## 6. Migracja: obecna konfiguracja → Dom 1

Cel: bez przerwy dłuższej niż zwykły restart poda (`Recreate`, kilkanaście
sekund), bez utraty historii, z możliwością cofnięcia obrazu w każdym etapie.

1. **Baza zdarzeń**: `/data/kidwatch.db` **zostaje na miejscu** i jest bazą
   Domu 1. Żadnego kopiowania ani przepisywania wierszy. Klucze meta
   (`cursor:nextdns:<profil>`, `mdm:events`, `game:<profil>`) są już
   w dobrej bazie.
2. **Dom 1** w `panel-auth.db`: przy starcie, jeśli `domy` jest puste,
   transakcja zakłada `domy(id=1, nazwa='Dom 1', zrodlo_konfiguracji='yaml')`
   i członkostwa:
   `users.rola = 'wlasciciel'` → `wlasciciel-domu`, `podglad` → `podglad`;
   `user_uprawnienia` → `czlonkostwa_uprawnienia(dom 1)`. Migracja **nie**
   nadaje `admin_instancji` nikomu — robi to operator jednym poleceniem
   `kidwatch user-admin <login konta administracyjnego> on` po założeniu
   tego konta w panelu (`user-add`). Idempotentne (drugi start nic nie
   zmienia).
3. **Konfiguracja przez pierwszy etap**: Dom 1 dalej z `config.yaml` +
   zmienne środowiskowe — `Config.load` działa bez zmian, a z niego powstają
   `InstanceConfig` i `HomeConfig(dom 1)`. **Plik `config.yaml` bez sekcji
   domów jest poprawny na zawsze** (instalacje jednodomowe z publicznego repo
   nic nie muszą robić).
4. **Przejście Domu 1 na bazę** (E2, ręcznie, odwracalne):
   `kidwatch dom-importuj 1 --podglad` pokazuje, co zostanie zapisane
   (sekrety zamaskowane) i porównanie `HomeConfig` z YAML a z bazy (musi być
   identyczne pole w pole); `--zapisz` zapisuje i ustawia
   `zrodlo_konfiguracji='baza'`. Powrót: `kidwatch dom-zrodlo 1 yaml`.
   `config.yaml` w Sekrecie zostaje do końca następnego etapu.
5. **#45**: preferencje z `user_powiadomienia` kopiowane do
   `czlonkostwa_powiadomienia(dom 1)`; tryb `powiadomienia_ustawienia.tryb`
   → `tryb:1`. Dom 1 może zostać w trybie `trasy`.
6. **MDM**: `dom_id DEFAULT 1` na serwerze — wszystkie zapisane iPady są
   w Domu 1 bez żadnej akcji; `MDM_ADMIN_TOKEN` zachowuje pełny zakres
   (instancja) do czasu wydania tokenu Domu 1 w E3.
7. **Wycofanie obrazu**: każdy etap dodaje tylko tabele i kolumny
   z wartościami domyślnymi; stary obraz ich nie czyta. `users.rola`
   i `user_uprawnienia` są aktualizowane równolegle (lustro Domu 1) aż do E4,
   więc cofnięcie do obrazu sprzed E1 zachowuje role.
8. **Weryfikacja bez przerwy**: przed i po każdym etapie — liczba
   powiadomień i sesji z ostatnich 48 h w panelu (z `notifications`,
   `sessions`), `tests/test_e2e_replay.py` z `fixtures/day.jsonl` daje
   **ten sam** wynik (`day.expected.txt`) na ścieżce jednodomowej i na
   ścieżce `HomeRuntime(dom 1)`.

## 7. Plan wdrożenia etapami

Każdy etap = osobny PR, wdrażany (push na `main` → obraz → ArgoCD) i cofany
osobno. Kolejność zależności: **E1 → (E2 ∥ E3a ∥ E5) → E3b → E4 → E6**.

### E1 — model Domu + migracja do Domu 1 (zero zmian zachowania)

- **Pliki**: `src/kidwatch/domy.py` (nowy: schemat, migracja, `HomeRuntime`
  z jednym domem), `config.py` (`InstanceConfig`, `HomeConfig`,
  `Config.split()`), `__main__.py` (`cmd_run` przez nadzorcę z jednym domem;
  CLI `domy`), `panel_auth.py` (członkostwa, lustro `users.rola`),
  `gametime.py`, `tvpause.py` (`dom_id DEFAULT 1`), `models.py`
  (`Notification.dom_id`), `devicekind.py` (`phone-android` + alias `phone`).
- **Ryzyka**: zmiana `cmd_run` — kolejność i obsługa końca zadań; regres
  w restarcie (dziś: koniec zadania = kod 1). W E1 nadzorca **zachowuje**
  zachowanie „koniec zadania = koniec procesu” (izolacja awarii dopiero w E3b).
- **Testy**: replay dnia identyczny; migracja idempotentna; migracja na
  kopii bazy z ról `wlasciciel`/`podglad` + odstępstw; stary schemat czyta
  nową bazę (wycofanie); `HomeConfig` z YAML = dzisiejszy `Config` pole w pole.
- **Gotowe, gdy**: wdrożone, 48 h z tą samą liczbą powiadomień/sesji co
  przed, `kidwatch domy` pokazuje Dom 1 z członkami.
- **Ustalenia z realizacji** (wiążą E2/E3a/E5):
  - Tabele założone w E1: `domy`, `czlonkostwa`, `czlonkostwa_uprawnienia`,
    `dzieci`, `urzadzenia`, `integracje` (bez zapisów), `audyt`; kolumny
    `users.admin_instancji` oraz `dom_id` w `game_requests`
    i `tv_pause_requests`. `zaproszenia` zakłada E4 (jedyny użytkownik),
    `czlonkostwa_powiadomienia` i `tryb:<dom>` — E3a, kiedy preferencje
    stają się per dom (kopia w E1 rozjechałaby się z oryginałem).
  - Prawdą o rolach w Domu 1 jest w E1 `users` (panel liczy uprawnienia jak
    dotąd); każda zmiana konta i każdy start uzgadniają `czlonkostwa(dom 1)`
    z `users`, więc zmiany zrobione starym obrazem po wycofaniu wracają.
    `zarzadca` ma w `users` lustro `podglad` + nadania o tych samych
    uprawnieniach efektywnych. E3a, przełączając odczyt na `czlonkostwa`,
    odwraca kierunek uzgadniania przy starcie.
  - `wlasciciel-domu` ma na razie ten sam zbiór co `wlasciciel` (z
    `whatsapp.konfiguracja`); przeniesienie do zakresu instancji i nowe
    `dom.*` — E3a (`uprawnienia.ROLE_DOMU_UPRAWNIENIA`).
  - Telefon: w konfiguracji `phone-android` = `phone`, ale silnik, API
    i front dalej mówią `phone` (zmiana nazwy razem z frontem w E3a).
    `urzadzenia.rodzaj` w bazie używa `phone-android`
    (`devicekind.RODZAJ_W_BAZIE`).
  - `HomeConfig.store` niesie samą retencję (silnik liczy z niej agregaty);
    ścieżka bazy domu wynika z `domy.sciezka_bazy_domu`.
  - `Notification.dom_id` ustawia kolejka domu (`Outbox(dom_id=…)`); notka
    z cudzym domem jest odrzucana z błędem w logu (alarm instancji — E3b).
  - `domy.dozwolone_sieci` Domu 1 zostaje puste — wypełnia je E2 (właściciel
    strażnika sieci) przy `dom-importuj`.

### E2 — integracje per dom, sekrety w bazie (szyfrowane)

- **Pliki**: `src/kidwatch/sejf.py` (KEK/DEK, AAD, rotacja),
  `domy.py` (integracje, `SekretyDomu`, budowa `HomeConfig` z bazy,
  strażnik sieci §3.6), `config.py` (metody sekretów przez dostawcę),
  `__main__.py` (CLI `dom-importuj`, `dom-zrodlo`, `klucze-rotuj`,
  `dom-klucz-rotuj`, `dom-sieci`), `sources/unifi.py`, `sources/tv*.py`,
  `sources/nextdns.py` (`ConnectGate` per klucz), chart
  (`KIDWATCH_KEK` w `secretName`, `emptyDir` pamięciowy na klucze plikowe),
  `docs/` (runbook kopii i rotacji).
- **Ryzyka**: pomyłka przy imporcie Domu 1 (inny profil, brak klucza) —
  łagodzi `--podglad` z porównaniem i `dom-zrodlo 1 yaml`; utrata KEK.
- **Testy**: AAD (zamiana domów/typów), rotacja KEK z kluczem poprzednim,
  brak KEK = dom w `baza` nie startuje, Dom 1 `yaml` działa; sekret-kanarek
  nie pojawia się w logu ani w odpowiedziach; SSRF (§4.4 p. 7).
- **Gotowe, gdy**: Dom 1 na produkcji w trybie `baza`, 48 h identycznie,
  test odtworzenia z kopii + KEK przeszedł.
- **Równolegle z**: E3a, E5 (inne pliki; `domy.py` — właściciel E2, E3a
  dopisuje tylko w `panel.py`/`uprawnienia.py`).

### E3a — izolacja panelu i API + przełącznik domu w UI

- **Pliki**: `panel.py` (`/api/domy/<id>/…`, `_wymaga(session, dom, upr)`,
  rejestr `PanelQueries`, zakresy tras, aliasy starych tras), `uprawnienia.py`
  (role domowe, nowe uprawnienia, zakresy), `panel_auth.py`
  (`uprawnienia(konto, dom)`, `/api/auth/me` z listą domów i uprawnień
  per dom, rola administratora instalacji z bezpiecznikiem grupy `admins`,
  wpisy `audyt`), `panel_sso.py` + `charts/kidwatch/values.yaml` +
  `tests/test_chart_sso.py` (grupa `admins` wpuszczana — §8, decyzja 5),
  `__main__.py` (CLI `user-admin`), `odbiorcy.py`/`panel_konta.py` z #45 (preferencje per
  członkostwo, tryb per dom, `trasy` tylko Dom 1), `web/src/utils/api.js`
  (prefiks domu), `web/src/components/*` (przełącznik domu w nagłówku,
  zapamiętany w `localStorage`, ukryty przy jednym domu; ekran integracji
  i urządzeń domu), `web/src/utils/uprawnienia.js`.
- **Ryzyka**: pominięta trasa (łagodzi test kompletności tras); front wołający
  stare trasy przy dwóch domach (409 zamiast cichego złego domu).
- **Testy**: §4.4 p. 1–3, 5, 6; testy frontu: przełącznik, prefiks, chowanie
  przycisków per dom.
- **Gotowe, gdy**: na produkcji istnieje **Dom testowy** (dane syntetyczne,
  założony przez `admin_instancji`), konto `podglad` z Domu 1 go nie widzi
  (404), prywatne konto właściciela też nie (404), konto administracyjne
  (grupa `admins`) go widzi, a każde wejście jest w `audyt`; konto członka
  obu domów przełącza się bez przeładowania strony. Reguła Authelii dla
  hosta panelu dopuszcza `admins` w tym samym oknie wdrożenia.

### E3b — MDM per dom + izolacja awarii pętli

- **Pliki**: `kidwatch_mdm/store.py` (`dom_id`, tokeny domów),
  `kidwatch_mdm/server.py` (filtrowanie, 404 dla obcych UDID, `os_update`
  per dom), `kidwatch_mdm/policy.py` (`<dom>/<etykieta>`), chart
  `kidwatch-mdm` (bez zmian sekretów), `mdm.py` (watcher per dom + watcher
  instancji), `panel.py` (`udid ∈ dom`), `domy.py` (nadzorca: restart domu
  z backoffem, tętno per dom).
- **Ryzyka**: serwer MDM steruje prawdziwymi iPadami — błąd w filtrze może
  odciąć komendy Domu 1. Wdrożenie: najpierw serwer z `dom_id DEFAULT 1`
  i starym tokenem jako instancyjnym (zachowanie bez zmian), potem token Domu 1.
- **Testy**: §4.4 p. 4, 8; testy serwera MDM: token domu nie widzi i nie
  steruje obcym; zapis z tokenu domu wiąże urządzenie z domem; awaria pętli
  domu testowego nie przerywa Domu 1 (zadanie rzucające wyjątek).
- **Gotowe, gdy**: Kidwatch używa tokenu Domu 1; `refresh` iPada Domu 1
  działa; komenda na UDID spoza domu = 404 w obu miejscach.
- **Równolegle z**: E2 (różne pliki), po E3a w części `panel.py`.

### E4 — zaproszenia (i konta spoza rodziny)

- **Przepływ** (rekomendowany, SSO włączone):
  1. `wlasciciel-domu` w panelu: *Dom → Członkowie → Zaproś*: rola, ważność
     (domyślnie 72 h, max 7 dni), opcjonalnie oczekiwany login SSO. Panel
     pokazuje **raz** link `https://<panel>/zaproszenie#<token>` (token w
     fragmencie — nie trafia do logów Traefika ani do nagłówka `Referer`).
  2. **Konto w Authelii** zakłada `admin_instancji` (lista użytkowników
     Authelii jest w `renacode-infra`, poza tym repo) i dodaje osobę do
     nowej grupy **`kidwatch-goscie`** — dopisanej do `sso.grupy`
     i do reguły hosta panelu w Authelii, bez dostępu do innych aplikacji.
     Panel pokazuje zapraszającemu tę instrukcję, jeśli oczekiwany login nie
     ma jeszcze konta.
  3. Zaproszony loguje się przez Authelię (jej 2FA), otwiera link; front
     wysyła token w `POST /api/zaproszenia/przyjmij`. Serwer: token istnieje,
     nie wygasł, nie przyjęty, nie odwołany, `dla` (jeśli ustawione) ==
     `Remote-User`. Jeśli konta `users.login == Remote-User` nie ma —
     **zakłada je** (to jedyny przypadek konta z SSO „w locie”, i tylko
     z ważnym tokenem), z losowym hasłem awaryjnym niepokazanym nikomu.
     Dodaje członkostwo z rolą z zaproszenia, oznacza token jako zużyty,
     wpis w `audyt`, powiadomienie do zapraszającego.
  4. Bez SSO (dziś `sso.enabled: false` w chartcie): link otwiera ekran
     „ustaw hasło” (polityka `MIN_PASSWORD_LEN`, Argon2id) + wymagane
     włączenie TOTP przed pierwszym dostępem do danych domu.
- **Zabezpieczenia**: token 32 B z `secrets.token_urlsafe`, w bazie tylko
  SHA-256; jednorazowy; limit 5 nieudanych prób na token i limit per adres
  (jak `ip_failures`); zaproszenie nie podnosi roli istniejącego członka
  (tylko nowy członek); odwołanie w każdej chwili; wygasłe sprzątane po 30
  dniach. Usunięcie członka: zamyka jego sesje, kasuje preferencje w domu,
  `audyt`, sugestia `dom-klucz-rotuj` przy zarządcy z `dom.integracje`.
- **Pliki**: `src/kidwatch/zaproszenia.py`, `panel.py` (trasy zakresu
  `dom` i publiczna `przyjmij` z sesją SSO lub biletem hasła),
  `panel_sso.py` (wyjątek „konto z zaproszenia”), `web` (ekrany Członkowie,
  Przyjmij zaproszenie), chart (`sso.grupy` + `kidwatch-goscie`), README.
  Usunięcie aliasów starych tras i lustra `users.rola`.
- **Testy**: jednorazowość, wygasanie, odwołanie, zły dom, sufit roli,
  `dla` ≠ `Remote-User`, token tylko jako hash, brak tokenu w logu,
  limit prób, zaproszony bez SSO musi włączyć TOTP, przyjęcie nie daje
  dostępu do innych domów zapraszającego.
- **Gotowe, gdy**: konto testowe z grupy `kidwatch-goscie` przyjęło
  zaproszenie do Domu testowego i widzi tylko jego.

### E5 — iPhone (MDM + NextDNS)

- **Pliki**: `devicekind.py` (`iphone`), `config.py`/`domy.py` (rodzaj,
  walidatory jak `ipad`), `tools/gen_profile.py` (profil DNS NextDNS dla
  iPhone'a z nazwą urządzenia), `kidwatch_mdm/profiles.py` + `policy.py`
  (iPhone: ograniczenia obowiązujące bez nadzoru, DDM DNS), `docs/mdm.md`,
  nowy `docs/iphone.md`, front (ikona, teksty).
- **Ryzyka**: iPhone dziecka zwykle **bez nadzoru** (nadzór = wymazanie
  i Apple Configurator) — ograniczenia MDM będą ignorowane, zostaje DNS,
  inwentarz i komendy (blokada, restart). Teksty czujek muszą to mówić.
- **Testy**: walidacja rodzaju, teksty pushy, schemat profilu
  (`test_profile_schema.py`), MDM: polityka iPhone'a bez kluczy „tylko
  pod nadzorem”.
- **Gotowe, gdy**: iPhone testowy w Domu 1 zapisany do MDM, ruch DNS
  liczony jako sesje, czujka ciszy działa.
- **Równolegle z**: E2, E3a (po E1).

### E6 — Dom 2 end-to-end

- **Kroki**: `admin_instancji` zakłada Dom 2 (`kidwatch dom-dodaj`), konto
  Authelii w `kidwatch-goscie`, zaproszenie `wlasciciel-domu`; zaproszony
  zakłada **własne konto NextDNS** i profil, wpisuje klucz API w panelu
  (integracja `nextdns`), dodaje dziecko i telefon `phone-android`
  (instrukcja z `docs/telefon-android.md`), uzupełnia kanały powiadomień;
  weryfikacja trybu `konta` bramki dla Domu 2.
- **Pliki**: `docs/nowy-dom.md` (runbook dla zapraszającego i zaproszonego,
  z informacją o prywatności), poprawki z prób.
- **Ryzyka**: bramka bez `funkcje: ["odbiorca"]` → Dom 2 bez powiadomień
  (wykrywane, alarm instancji); limit 429 przy wspólnym koncie NextDNS (nie
  dotyczy, gdy konto osobne); pamięć poda.
- **Testy**: test e2e z replayem `fixtures/telefon_android.jsonl` w Domu 2
  równolegle z `day.jsonl` w Domu 1 — wyniki jak osobno, zero przecieków
  (§4.4 p. 1 na produkcyjnym kształcie danych); pomiar pamięci.
- **Gotowe, gdy**: zaproszony dostaje sesje/alarm nocny/podsumowanie ze
  swojego telefonu, nie widzi Domu 1, członkowie Domu 1 nie dostają nic
  z Domu 2 (sprawdzone w historii powiadomień obu domów i w logu bramki).
- **UniFi i TV w Domu 2**: poza E6 (brak trasy sieciowej, decyzja 4, §8).

### Podsumowanie i podział na agentów

| Etap | Zależy od | Równolegle z | Wdrożenie / wycofanie |
|---|---|---|---|
| E1 model Domu + Dom 1 | #45 scalony | — | obraz; wycofanie = poprzedni obraz (tylko nowe tabele) |
| E2 integracje + sejf | E1 | E3a, E5 | obraz + `KIDWATCH_KEK`; `dom-zrodlo 1 yaml` |
| E3a panel/API/UI | E1 | E2, E5 | obraz; aliasy starych tras |
| E3b MDM per dom + awarie | E3a (panel), E1 | E2 | najpierw `kidwatch-mdm`, potem kidwatch; token instancji jako zapas |
| E4 zaproszenia | E3a, E3b | E5 | obraz + grupa Authelii w infra |
| E5 iPhone | E1 | E2, E3a, E4 | obraz |
| E6 Dom 2 | E2, E3b, E4, bramka z `odbiorca` | — | operacje + dokumentacja |

Po E1 trzy agenty mogą pracować jednocześnie (każdy we **własnym
`git worktree`**): **A** — E2 (`sejf.py`, `domy.py`, źródła), **B** — E3a
(`panel.py`, `uprawnienia.py`, `web/`), **C** — E5 (`devicekind.py`,
`kidwatch_mdm/profiles.py`, `tools/gen_profile.py`, dokumentacja). Punkt styku
A–B: interfejs `domy.py` (rejestr domów, `uprawnienia(konto, dom)`)
uzgodniony w E1 i zamrożony. E3b i E4 sekwencyjnie po B.

## 8. Decyzje właściciela (2026-10-11)

Wszystkie pytania rozstrzygnięte zgodnie z rekomendacjami projektu.

1. **Nadawca WhatsApp: wspólny bot bramki.** Dom 2 wysyła **wyłącznie
   w trybie `konta`** (#45), nigdy przez trasy bramki. Dopóki bramka nie
   obsługuje pola `odbiorca` (`GET /v1/stan` → `"funkcje": ["odbiorca"]`),
   Dom 2 nie dostaje WhatsAppa — docelowo tylko e-mail na adres konta.
   Uwaga wykonawcza: zapasowy e-mail bramki idzie dziś na `ADRES_DOMYSLNY`
   (adres Domu 1), więc e-mail na adres członka Domu 2 też wymaga pola
   `odbiorca` (`kanal: "email"`). Bez niego outbox Domu 2 wstrzymuje wysyłkę
   i zgłasza alarm instancji (§4.2) — notki czekają, nie trafiają do Domu 1.
2. **MDM: wspólny `kidwatch-mdm` z rozdziałem po domu** (§4.3, etap E3b).
   Dom 2 startuje **bez MDM**; integracja `mdm` Domu 2 pozostaje wyłączona,
   token domu wydawany dopiero przy pierwszym urządzeniu Apple.
3. **Authelia: nowa grupa `kidwatch-goscie`** z dostępem wyłącznie do hosta
   panelu Kidwatcha; dopisana do `sso.grupy` i reguły hosta w Authelii
   (renacode-infra) w etapie E4. Grupa wpuszcza, niczego w panelu nie nadaje.
   Do listy wpuszczanych grup dochodzi też **`admins`** (decyzja 5 po
   korekcie) — patrz niżej.
4. **UniFi i TV w Domu 2: później.** Start Domu 2 to NextDNS w chmurze;
   `domy.dozwolone_sieci` Domu 2 pozostaje puste do czasu decyzji o tunelu.
   E6 nie obejmuje UniFi ani TV.
5. **Prywatność i NextDNS.**
   - **Korekta (2026-10-11): administrator instalacji widzi wszystkie
     domy.** Osobne konto administracyjne (Authelia, grupa `admins`) ma
     w panelu rolę administratora instalacji (§2.3): dane, integracje,
     zaproszenia i członkowie każdego domu, z wpisem w `audyt` przy każdym
     wejściu do domu, w którym nie jest członkiem. Rola pochodzi z flagi
     `users.admin_instancji` w `panel-auth.db`, nie z nagłówka; grupa
     `admins` jest tylko warunkiem koniecznym przy sesji SSO.
   - **Prywatne konto właściciela** (grupa `wlasciciel`) to zwykły członek
     Domu 1 — **nie widzi danych Domu 2** bez członkostwa (§4.4 p. 2).
   - **Konsekwencja dla SSO** (zmiana decyzji z 11.10 zapisanej
     w `panel_sso.py`: „`admins` do Kidwatcha NIE wchodzi”):
     `DEFAULT_GROUPS` i komentarz w `panel_sso.py`, `sso.grupy` w
     `charts/kidwatch/values.yaml` (→ `wlasciciel`, `rodzina`,
     `kidwatch-goscie`, `admins`), test `tests/test_chart_sso.py` oraz
     reguła hosta panelu w Authelii (renacode-infra) muszą dopuścić
     `admins`. Do czasu wdrożenia roli administratora (E3a) konto z grupy
     `admins` bez konta w panelu dostaje 403 jak dziś (`Remote-User` bez
     dopasowania), a z kontem — tylko to, co daje jego członkostwo; dlatego
     zmianę grup wdrażamy **razem z E3a**, nie wcześniej. Zakres plików E3a
     rozszerza się o `panel_sso.py`, chart i CLI `user-admin`.
   - Zaproszony dostaje **pisemną informację**, że **administrator
     instalacji ma wgląd we wszystkie dane domu** w panelu (z dziennikiem
     audytu widocznym dla właściciela domu), a operator klastra ma
     dodatkowo techniczny dostęp do bazy i klucza szyfrującego (§0). Treść w
     `docs/nowy-dom.md` (E6) i pokazywana na ekranie przyjęcia zaproszenia
     (E4) przed utworzeniem członkostwa — przyjęcie = potwierdzenie
     przeczytania.
   - Dom 2 używa **własnego konta NextDNS** zaproszonego (własny klucz API,
     osobna bramka połączeń 429, §5.2).
