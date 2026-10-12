# iPhone dziecka (NextDNS + kidwatch-mdm, bez nadzoru)

Kidwatch widzi iPhone'a tak samo jak iPada: przez zapytania DNS wysyłane do
profilu NextDNS z nazwą urządzenia. Sesje, alarm nocny, czujka „urządzenie
milczy”, czas gry, podsumowania i panel działają jak dla iPada. Dodatkowo
iPhone może być zapisany do `kidwatch-mdm` (lista aplikacji z alarmem
o nowych, blokada ekranu, stan systemu, wymuszenie wersji iOS).

Tak jak u iPada, **minuty to dolne oszacowanie** (minuty z ruchem DNS), nie
czas przed ekranem.

## 1. Bez nadzoru — co działa, a czego nie będzie

iPhone dziecka jest zwykle **bez nadzoru** (supervision). Nadzór wymaga
wymazania telefonu i Apple Configuratora (albo Apple Business), więc Kidwatch
go nie zakłada. Skutki, sprawdzone w schemacie Apple
([apple/device-management](https://github.com/apple/device-management), gałąź
`release`, indeks w `tools/apple_schema_index.json`):

| Co | Bez nadzoru | Źródło w schemacie |
|---|---|---|
| szyfrowany DNS z profilu NextDNS zainstalowanego **ręcznie** | **działa w każdej sieci, także komórkowej** | `com.apple.dnsSettings.managed`: `supervised: false`, „when installed manually, this setting also applies to cellular networks” |
| ten sam DNS wysłany przez MDM (profil albo DDM) | tylko sieci zarządzane — czyli w domu nic | jw.; dlatego serwer **nie** wysyła iPhone'owi DNS |
| profil DNS nie do usunięcia (`ProhibitDisablement`, `PayloadRemovalDisallowed`) | **nie** — dziecko może go usunąć | oba `supervised: true` |
| blokada VPN, Private Relay, cudzych profili, wymazania | **nie** | `com.apple.applicationaccess`: `supervised: true` |
| lista aplikacji (alarm o nowej), stan systemu, profile | działa | `InstalledApplicationList`, `DeviceInformation`: `supervised: false` |
| blokada ekranu z panelu (`DeviceLock`) | działa | `device.lock.yaml`: `supervised: false` |
| restart z panelu (`RestartDevice`) | **nie** — serwer odmawia od razu (409) | `device.restart.yaml`: `supervised: true` |
| wymuszenie wersji iOS do terminu (DDM) | działa | `softwareupdate.enforcement.specific`: zapis urządzenia |
| automatyczna instalacja aktualizacji, odroczenia | **nie** | `AutomaticActions`, `Deferrals`: `allowed-enrollments: [supervised]` |

Wniosek: **dziecko może zdjąć profil DNS i wypisać iPhone'a z MDM.** Kidwatch
tego nie zablokuje, ale to wykryje: czujka ciszy (iPhone przestaje pytać
NextDNS), czujka UniFi (iPhone w domowym Wi-Fi przesyła dane bez DNS)
i alarm MDM „profil MDM zdjęty”. Teksty tych alarmów mówią to wprost.

## 2. Co robi kod

- **Kidwatch** (`kind: iphone` w `devices`): teksty „używa iPhone'a w nocy”,
  podpowiedzi czujek wskazują profil NextDNS na iPhonie i mówią, że bez
  nadzoru da się go usunąć (`src/kidwatch/devicekind.py`). Walidatory jak dla
  iPada: odczyt wprost (`udid` + `host`, tylko IPv4 z LAN domu) jest dozwolony.
  W bazie panelu rodzaj to `iphone` (`devicekind.RODZAJ_W_BAZIE`).
- **kidwatch-mdm** (`kind: iphone` w polityce): iPhone dostaje politykę
  **bez ani jednego klucza „tylko pod nadzorem”** — test liczy to ze schematu
  Apple, także dla deklaracji DDM (`tests/test_mdm_iphone.py`):
  - profil zapisu bez `PayloadRemovalDisallowed`;
  - profil ograniczeń tylko z własnych `restrictions` urządzenia (domyślne
    blokady iPada i wspólne nadpisania go nie dotyczą); serwer odrzuca przy
    starcie klucz wymagający nadzoru i `blocked_apps` dla iPhone'a;
  - deklaracje DDM zawsze w wersji bez nadzoru i **bez deklaracji DNS**, nawet
    gdy telefon zgłosi `IsSupervised` (nadzorowany iPhone to osobna decyzja);
  - `RestartDevice` dla iPhone'a bez nadzoru → 409 z wyjaśnieniem.
  - iPhone zapisany pod etykietą bez `kind: iphone` (albo spoza polityki) jest
    rozpoznawany po `ProductName` i też dostaje politykę bez kluczy nadzoru.
    Profil zapisu powstaje jednak, zanim telefon się przedstawi — dlatego
    `kind: iphone` wpisz w politykę **przed** utworzeniem zaproszenia.
- **iPad bez zmian** — polityka, profile, deklaracje i teksty czujki MDM iPada
  są porównywane bajt w bajt z migawką sprzed E5
  (`tests/fixtures/mdm_ipad_przed_e5.json`).

## 3. Kroki właściciela (zapis iPhone'a testowego w Domu 1)

Prawdziwe nazwy, ID profilu NextDNS i etykiety trzymasz tylko w Sekretach
(`kidwatch-config`, `kidwatch-mdm-policy`) — repo jest publiczne. Poniżej
placeholdery.

1. **Po wdrożeniu** (scalenie PR → obrazy `kidwatch` i `kidwatch-mdm` →
   ArgoCD) sprawdź, że oba pody wstały na nowym obrazie.
2. **Profil DNS** (na Macu, w repo):

   ```sh
   uv run python tools/gen_profile.py --kind iphone \
     --name "iPhone Dziecka 1" \
     --doh-url "https://dns.nextdns.io/<ID profilu>/iPhone-Dziecka-1" \
     --out iphone-dziecka-1.mobileconfig
   ```

   Profil dziecka = ten sam profil NextDNS co jego iPad (`nextdns_profile`;
   konfiguracja odrzuci różne profile jednego dziecka, bo czas gry jest
   ustawieniem profilu). Nazwa w adresie: litery, cyfry i `-`.
3. **Instalacja ręcznie** (nie przez MDM — tylko ręczna obejmuje sieć
   komórkową): AirDrop na iPhone'a → Ustawienia → Pobrany profil →
   Zainstaluj. Sprawdź: Ustawienia → Ogólne → VPN i urządzenia → DNS →
   profil aktywny.
4. **NextDNS → Logi**: na iPhonie wyłącz Wi-Fi, otwórz dowolną stronę.
   W logach ma się pojawić urządzenie (np. `iPhone-Dziecka-1`). Zapisz nazwę
   **dokładnie tak, jak pokazuje ją NextDNS** — to wartość do `source_ids`.
5. **Kidwatch** (`kidwatch-config`, `tools/wgraj_konfiguracje.sh`):

   ```yaml
   devices:
     - display_name: "iPhone Dziecka 1"
       child: "Dziecko 1"
       kind: iphone
       source_ids: ["iPhone-Dziecka-1"]
       # nextdns_profile: "<jak iPad tego dziecka>"
       # unifi_mac: "02:00:00:00:00:05"   # prywatny adres Wi-Fi z Ustawień → Wi-Fi → (i)
   ```

6. **Polityka MDM** (`kidwatch-mdm-policy`), PRZED zaproszeniem:

   ```yaml
   devices:
     iphone1:
       name: iPhone Dziecka 1
       kind: iphone
       # bez dns_url — DNS idzie ręcznym profilem z kroku 3
   ```

   **Sprawdź na sucho przed podmianą Sekretu** (to samo sprawdzenie, które
   robi serwer przy starcie):

   ```sh
   uv run python -m kidwatch_mdm check-policy policy.yaml \
     --schema tools/apple_schema_index.json
   ```

   Kod 0 = można wgrywać. Potem podmień Sekret i zrestartuj `kidwatch-mdm`
   (polityka czyta się przy starcie). Zasada: **żaden błąd w polityce nie
   zdejmuje po cichu ochrony z iPada.**
   - Błąd we wpisie, o którym wiadomo, że to iPhone (`kind: iphone`, bez
     `dns_url`, pod etykietą nie ma zapisanego iPada): serwer **wstaje**
     (iPady dalej zarządzane), a ten wpis idzie do kwarantanny — iPhone traci
     **wszystkie** własne ograniczenia z wpisu, także działające bez nadzoru
     (np. `allowCamera`). Alarm „MDM: wpis … w polityce odrzucony” przychodzi
     raz na zmianę błędów, nie po każdym restarcie.
   - Start zatrzymują, jak dotąd: błąd we wspólnych ustawieniach albo we
     wpisie iPada; błąd we wpisie `kind: iphone` **z `dns_url`** (iPhone go
     nie używa, więc to najpewniej iPad z pomylonym `kind`); błąd we wpisie,
     pod którego etykietą jest zapisany iPad.
   - `kind: iphone` pomyłkowo pod etykietą iPada **bez błędów** we wpisie:
     iPad zostaje iPadem z pełnym wpisem (zgłasza się jako iPad) i jest alarm
     „pomyłka rodzaju”. Jeśli taki wpis jest w kwarantannie, a iPad zapisze się
     dopiero później, nie dostaje ograniczeń z wpisu — alarm mówi to wprost
     (priorytet 5).
7. **Zapis do MDM**: w panelu (zakładka MDM → link do zapisu, etykieta
   `iphone1`) albo `kubectl -n default exec deploy/kidwatch-mdm --
   kidwatch-mdm enroll iphone1`. Link otwórz w Safari **na iPhonie** →
   Ustawienia → Pobrany profil → Zainstaluj (iOS zapyta o zgodę na zdalne zarządzanie).
8. **Sprawdzenie**:
   - push „iPhone Dziecka 1: zapisany do MDM” z tekstem o braku nadzoru;
   - zakładka MDM: iPhone, nadzór „nie”, lista aplikacji;
   - blokada ekranu z panelu działa; przycisk restartu jest nieaktywny
     („Restart wymaga nadzoru urządzenia”), a API odmawia (409).
9. **„Gotowe, gdy”** (§7 E5 w `docs/architektura-domy.md`):
   - iPhone zapisany do MDM (krok 8);
   - ruch DNS liczony jako sesje — kilka minut YouTube na iPhonie daje push
     „iPhone Dziecka 1 aktywny” i sesję w panelu;
   - czujka ciszy działa — iPhone w trybie samolotowym dłużej niż próg
     `watchdog.device_silence_minutes` (domyślnie 180 min; poza cichymi godzinami, gdy inne
     urządzenia pracują) daje alarm „iPhone Dziecka 1 nie zglasza sie do DNS”.

## 4. Czego nie sprawdzono na sprzęcie

- Odczyt wprost (lockdown, `pymobiledevice3`) przetestowano na iPadach.
  iPhone ma te same usługi lockdown, ale parowanie przez Wi-Fi i zachowanie
  w uśpieniu na iPhonie nie były sprawdzane — zacznij bez `udid`/`host`.
- Wygląd nazwy urządzenia w logach NextDNS dla DoH z iPhone'a (krok 4).

## 5. Wycofanie

- Kod: revert PR → nowy obraz. **Najpierw** usuń iPhone'a z konfiguracji
  Domu 1 — stary obraz nie zna `kind: iphone` i Kidwatch nie wystartuje:
  - tryb `yaml` (Sekret `kidwatch-config`): usuń wpis (albo zmień `kind` na
    `ipad`) i wgraj konfigurację;
  - tryb `baza` (E2, `docs/sejf-domow.md`): urządzenia czyta się z tabeli
    `urzadzenia`, więc sam Sekret nie wystarczy. Przełącz dom na YAML bez
    iPhone'a (`kidwatch dom-zrodlo 1 yaml` przy działającym podzie, potem
    restart) albo usuń iPhone'a z bazy ponownym `dom-importuj 1 --zapisz`
    z konfiguracji bez niego — i dopiero wtedy cofaj obraz.
- Stary `kidwatch-mdm` ignoruje `kind` w polityce i wyśle iPhone'owi blokady
  iPada (iOS je zignoruje bez szkody). iPady bez zmian w obie strony.
- Telefon: Ustawienia → Ogólne → VPN i urządzenia → usuń profil zarządzania
  i profil DNS.
