# Telefon z Androidem dziecka (Google Family Link)

Kidwatch widzi telefon z Androidem tak samo jak iPada: przez zapytania DNS
wysylane do profilu NextDNS z nazwa urzadzenia. Nie trzeba roota, opcji
programisty, kabla ani aplikacji na telefonie. Sesje, alarm nocny, czujka
„telefon milczy”, czas gry, podsumowania i panel dzialaja jak dla iPada.

Tak jak u iPada, **minuty to dolne oszacowanie** (minuty z ruchem DNS), nie
czas przed ekranem. Pelne dane ma sam Family Link (aplikacja rodzica → Czas
przed ekranem); Google nie udostepnia ich przez publiczne API.

## 1. Co zbadano (stan na 2026-10-11)

| Droga | Co daje | Odpornosc na obejscie | Prywatnosc | Utrzymanie | Werdykt |
|---|---|---|---|---|---|
| **a) Prywatny DNS → NextDNS** | domeny = aplikacje i strony, w kazdej sieci (Wi-Fi i komorkowa) | dziecko moze wylaczyc Prywatny DNS (Family Link tego nie blokuje), ale cisza wlacza alarm | tylko domeny, bez tresci | zero kodu na telefonie | **wdrozone** |
| b) UniFi (Wi-Fi w domu) | obecnosc w domu i ruch w bajtach | MAC losowy per siec, ale staly | tylko liczniki | juz istnieje | **wdrozone jako dodatek** (czujka „profil DNS usuniety”, „w domu”) |
| c) Aplikacja z UsageStatsManager | prawdziwy czas aplikacji na pierwszym planie | uprawnienie mozna odebrac; instalacja spoza Sklepu wymaga zgody rodzica | czas aplikacji | nowa aplikacja, publiczny endpoint, podpis | **odlozone** (ponizej) |
| d) ADB przez Wi-Fi | to co na TV | wymaga opcji programisty — wlasnie ich nie chcemy dziecku dawac | pelny dostep | ADB gubi zgode po 7 dniach | **odrzucone** |

### a) Prywatny DNS (DNS-over-TLS) z profilem NextDNS

- Android 9+ ma „Prywatny DNS”. W trybie z nazwa hosta **wszystkie** zapytania
  ida szyfrowanym kanalem do tego serwera, a gdy serwer jest nieosiagalny,
  siec dostaje status „Brak dostepu do internetu” — bez cichego powrotu do
  zwyklego DNS ([Android Developers Blog, 2018-04](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html)).
- NextDNS rozpoznaje urzadzenie po przedrostku hosta:
  `Nazwa-<ID profilu>.dns.nextdns.io`; spacje zapisuje sie jako `--`, dozwolone
  sa tylko `a-z A-Z 0-9 -` ([NextDNS: sending device name on Android](https://help.nextdns.io/t/q6hblma/sending-device-name-on-android),
  [NextDNS: identify devices](https://help.nextdns.io/t/35yz6r3/identify-devices)).
- **Blokada zmian:** jedyne systemowe zabezpieczenie to ograniczenie
  `DISALLOW_CONFIG_PRIVATE_DNS` (API 29), ktore moze ustawic **tylko wlasciciel
  urzadzenia (device owner)** albo profil sluzbowy na urzadzeniu firmowym
  ([UserManager](https://developer.android.com/reference/android/os/UserManager#DISALLOW_CONFIG_PRIVATE_DNS)).
  To samo dotyczy `DISALLOW_CONFIG_VPN`. Family Link nie jest wlascicielem
  urzadzenia i w jego pomocy nie ma ani Prywatnego DNS, ani VPN — rodzic zarzadza
  aplikacjami, uprawnieniami aplikacji, czasem przed ekranem, lokalizacja
  i kontami ([Google For Families: co moze rodzic](https://support.google.com/families/answer/7101025),
  [Android: kontrola rodzicielska](https://support.google.com/android/answer/16766047)).
  **Wniosek: na telefonie z Family Link dziecko MOZE wylaczyc Prywatny DNS.**
  Kidwatch tego nie zablokuje, ale to wykryje (czujka ciszy, czujka UniFi).
- Zostanie wlascicielem urzadzenia (wlasny DPC albo Android Management API)
  wymaga wymazania telefonu i provisioningu od zera — to odpowiednik nadzoru
  iPada i osobny projekt, nie czesc tej zmiany.
- **VPN:** aplikacja VPN omija Prywatny DNS. Nowa aplikacja ze Sklepu Play
  wymaga zatwierdzenia rodzica, jesli Family Link tak ustawiono
  ([Zarzadzanie aplikacjami dziecka](https://support.google.com/families/answer/9010408)).
  Dlatego w instrukcji ponizej: zatwierdzanie wszystkich aplikacji.

### b) UniFi — telefon w domowym Wi-Fi

Android od 10 uzywa **losowego, ale stalego** adresu MAC dla kazdej sieci
(zmienia sie dopiero po przywroceniu ustawien fabrycznych albo zapomnieniu
sieci). Losowanie przy kazdym polaczeniu (Android 12+) dotyczy tylko sieci
otwartych i sugestii aplikacji albo opcji programisty
([AOSP: MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior)).
Do `unifi_mac` wpisujesz wiec adres z Ustawien Wi-Fi telefonu dla domowej sieci
(jak u iPada z prywatnym adresem Wi-Fi).

### c) Aplikacja Kidwatch z UsageStatsManager — dlaczego jeszcze nie

Dalaby dokladny czas aplikacji (jak `dumpsys usagestats` na TV), ale:

1. **Instalacja:** poza Sklepem Play telefon pod Family Link domyslnie nie
   instaluje APK — rodzic musi wlaczyc w Family Link „Aplikacje z nieznanych
   zrodel” dla tego urzadzenia (relacje uzytkownikow:
   [F-Droid forum, 2020](https://forum.f-droid.org/t/f-droid-with-family-link-solved/11953),
   [Bark](https://support.bark.us/hc/en-us/articles/360050416571)). To otwiera
   dziecku droge do instalowania dowolnych APK — gorsze niz problem, ktory
   rozwiazuje. Sklep Play = konto deweloperskie, przeglad aplikacji i polityka
   prywatnosci.
2. **Uprawnienie „Dostep do danych o uzyciu”** (`PACKAGE_USAGE_STATS`) nadaje
   sie recznie w Ustawieniach; rodzic moze ustawic, ze tylko on daje
   uprawnienia aplikacjom, ale pomoc Google nie mowi, czy dotyczy to
   specjalnego dostepu ([Uprawnienia aplikacji dziecka](https://support.google.com/families/answer/10436839))
   — do sprawdzenia na telefonie.
3. **Lacznosc:** aplikacja TV jest serwerem w LAN odpytywanym przez Kidwatch.
   Telefon wychodzi z domu i spi, wiec musialby sam wysylac dane do panelu —
   to nowy publiczny endpoint z tokenem urzadzenia, poza SSO. Z kodu TV
   nadaje sie parowanie (kod 6 cyfr → token), nie transport.
4. **Klucz podpisu:** nowa aplikacja nie dostanie klucza w repo (klucz TV jest
   tam swiadomie). Gdy powstanie, CI podpisze ja kluczem z Sekretu
   repozytorium (`ANDROID_PHONE_KEYSTORE_B64` + haslo), budowa bez sekretu =
   APK niepodpisany i bez publikacji.

Proponowana kolejnosc: najpierw tydzien na samym DNS (ocena szumu Androida
i czy dziecko wylacza Prywatny DNS), potem decyzja o aplikacji.

### d) ADB przez Wi-Fi — odrzucone

Bezprzewodowe debugowanie wymaga wlaczenia opcji programisty na telefonie
dziecka. To dokladnie ta furtka, ktorej uzywaja narzedzia do zdejmowania
limitow Family Link przez ADB ([Bitdefender, 2025](https://www.bitdefender.com/en-us/blog/hotforsecurity/family-link-bypass-android-2025)).
Opcje programisty maja zostac wylaczone. Do tego Android cofa zgode ADB po
7 dniach bez polaczenia (to samo zepsulo ADB na TV — `sources/tv_app.py`).

## 2. Instrukcja dla wlasciciela

Potrzebne: ID profilu NextDNS dziecka (ten sam co jego iPad, jesli ma iPada —
konfiguracja odrzuca dwa profile u jednego dziecka, bo czas gry blokuje caly
profil), telefon dziecka w reku, aplikacja Family Link u rodzica.

### Krok 1. Nazwa hosta

Wybierz nazwe telefonu bez polskich znakow, np. `Telefon Dziecka 1`, i zloz
host: spacje → `--`, na koncu `-<ID profilu>.dns.nextdns.io`:

```
Telefon--Dziecka--1-abc123.dns.nextdns.io
```

(`abc123` to przykladowy ID profilu.) W logach NextDNS i w konfiguracji
Kidwatcha nazwa urzadzenia to wtedy `Telefon Dziecka 1`.

### Krok 2. Prywatny DNS na telefonie

Ustawienia → **Siec i internet** (Samsung: Polaczenia → Wiecej ustawien
polaczen) → **Prywatny DNS** → **Nazwa hosta dostawcy prywatnego DNS** →
wpisz host z kroku 1 → Zapisz.

Sprawdzenie na telefonie: otworz w przegladarce `https://test.nextdns.io` —
ma pokazac `"status": "ok"`, protokol `DOT` i ID Twojego profilu. Nazwe
urzadzenia potwierdzisz w logach NextDNS (krok 5).

### Krok 3. Family Link (aplikacja rodzica albo g.co/yourfamily)

Dziecko → Ustawienia / Elementy sterujace:

- **Google Play → Zatwierdzanie przez rodzica: wszystkie aplikacje** — nowa
  aplikacja VPN albo przegladarka z wlasnym DNS nie pojawi sie bez Ciebie.
- **Urzadzenia → ten telefon → Aplikacje z nieznanych zrodel: wylaczone.**
- **Urzadzenia → ten telefon → Dodawanie i usuwanie uzytkownikow: wylaczone**
  ([pomoc Google](https://support.google.com/families/answer/7158477)) — nowy
  uzytkownik albo gosc na telefonie nie bylby pod nadzorem Family Link.
- **Uprawnienia aplikacji → tylko rodzic moze nadawac uprawnienia.**
- Na telefonie: Ustawienia → Informacje o telefonie — sprawdz, ze **Opcje
  programisty** sa wylaczone (jesli Family Link na tym telefonie ma przelacznik
  opcji programisty, wylacz go).

Family Link **nie zablokuje** zmiany Prywatnego DNS — patrz punkt 1a.

### Krok 4. Konfiguracja Kidwatcha (Sekret `kidwatch-config`, nie repo)

W prawdziwym `config.yaml` (lokalnie `config.cluster.yaml`, wgrywany przez
`tools/wgraj_konfiguracje.sh`) dopisz do `devices`:

```yaml
  - display_name: "Telefon Dziecka 1"
    child: "Dziecko 1"          # to samo imie co przy iPadzie tego dziecka
    kind: phone
    source_ids: ["Telefon Dziecka 1"]
    # opcjonalnie, czujka UniFi i znacznik „w domu”:
    # unifi_mac: "<adres z Ustawien Wi-Fi telefonu dla domowej sieci>"
    # nextdns_profile: "<ten sam co iPad dziecka, jesli iPad go ma>"
```

`kind: phone` zmienia teksty („uzywa telefonu w nocy”) i podpowiedzi czujek
(Prywatny DNS zamiast profilu iOS). Pol `udid`, `host`, `known_apps` telefon
nie ma — konfiguracja je odrzuca. Wgraj Sekret i zrestartuj deployment
(skrypt robi to sam).

Adres MAC: telefon → Ustawienia → Wi-Fi → domowa siec (ikona zebatki) →
Adres MAC (przy „Uzyj losowego MAC” — to ten losowy, staly dla tej sieci).

### Krok 5. Weryfikacja

1. `my.nextdns.io` → profil → **Logi**: zapytania z nazwa `Telefon Dziecka 1`.
2. Panel Kidwatcha → Pulpit / Urzadzenia: karta z ikona telefonu.
3. Wlacz na telefonie YouTube na 2-3 minuty: push `Telefon Dziecka 1 aktywny`,
   10 min po zamknieciu `… — koniec`.
4. Test czujki: wylacz na chwile Prywatny DNS na 3+ godziny w dzien (albo
   tymczasowo zmniejsz `watchdog.device_silence_minutes`) — przyjdzie
   `Telefon Dziecka 1 nie zglasza sie do DNS` z podpowiedzia o Prywatnym DNS.
   Wlacz z powrotem — `… znowu widoczny w DNS`.
5. Po tygodniu: `python -m kidwatch domains --unknown-only` — domeny tla
   Androida, ktore budza sesje, dopisz do `noise` w `app_map.yaml`.

## 3. Ograniczenia

- **Dziecko moze wylaczyc Prywatny DNS** (Family Link tego nie blokuje).
  Wykrywa to czujka ciszy (domyslnie po 180 min, poza cichymi godzinami)
  i czujka UniFi w domu (ruch bez zapytan DNS). Poza domem zostaje sama cisza.
- **Cisza ≠ obejscie:** wylaczony telefon, tryb samolotowy i rozladowana
  bateria wygladaja tak samo. Tekst alarmu to wymienia.
- **VPN** (takze wbudowany w niektore przegladarki) omija Prywatny DNS — przed
  tym chroni tylko zatwierdzanie aplikacji w Family Link.
- **Szum Androida** (`app_map.yaml`, sekcja `noise`, wpisy z 2026-10-11) jest
  spisany z dokumentacji i znanych nazw, nie z logow tego domu. Producenci
  (Samsung, Xiaomi, Huawei, Oppo) maja wlasne uslugi tla — pierwszy tydzien
  sprawdz `domains --unknown-only`.
- **Powiadomienia aplikacji w nocy** (np. WhatsApp) to pojedyncze zapytania —
  nie potwierdzaja sesji (3 chwile w 5 min). Dluzsza wymiana wiadomosci w nocy
  potwierdzi sesje tak samo jak u iPada — to celowe.
- Minuty to dolne oszacowanie; dokladny czas aplikacji tylko w Family Link.
