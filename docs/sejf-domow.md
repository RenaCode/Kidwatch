# Sejf integracji domów — runbook

Etap E2 projektu wielu domów (`docs/architektura-domy.md` §3, §6 p. 4).
Sekrety integracji domu (klucz API NextDNS, klucz UniFi, PSK Sony, klucz ADB,
token aplikacji TV, temat i token ntfy, webhook Home Assistant, token MDM)
leżą w `panel-auth.db` **zaszyfrowane kopertowo**:

```
KIDWATCH_KEK (32 B, Sekret k8s kidwatch-secrets)
 └─ klucz danych domu (DEK)      domy.dek_zaszyfrowany
     └─ sekrety integracji       integracje.sekrety
```

Kod: `src/kidwatch/sejf.py` (szyfrowanie), `src/kidwatch/konfiguracja_domu.py`
(import, budowa konfiguracji domu z bazy), `src/kidwatch/straznik.py`
(adresy integracji, SSRF).

Wszystkie polecenia w klastrze uruchamia się w podzie. Runbook jest dla
**zsh** (domyślna powłoka macOS; `read -rs 'ZMIENNA?pytanie'`). W bashu
bloki z kluczem w schowku (pkt 2, pkt 7.1) nie robią nic, a `kp` kończy się
błędem (kod 2), nie fałszywym potwierdzeniem — sprawdzają to testy na
`/bin/bash`.

**Bloki wklejaj w całości do zsh.** Bloki nie mają komentarzy: w zsh bez
`interactivecomments` (domyślnie) `#` w wklejonym tekście nie jest
komentarzem, a polecenie w odwrotnych apostrofach w takim „komentarzu”
zostałoby wykonane. Pierwszy blok i tak włącza tę opcję. Każdy blok jest
w testach wklejany do interaktywnego zsh z atrapami `kubectl`/`pbcopy`
(`tests/test_runbook_sejf.py`).

Pierwszy blok definiuje `k` (polecenie w podzie) i `kp` (`klucze-potwierdz`
z kluczem wklejonym z menedżera haseł na stdin — bez zapisu w historii
powłoki). Kod wyjścia `kp` to kod `klucze-potwierdz` — od tego zależy
`kp && …` niżej. `local K` sprawia, że klucz nie zostaje w powłoce po Ctrl-C
i nie trafia do środowiska `kubectl`.

```sh
setopt interactivecomments
k() { kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch "$@"; }
kp() { local K rc; read -rs 'K?KIDWATCH_KEK z menedżera haseł: '; echo
       printf '%s\n' "$K" | kubectl -n default exec -i deploy/kidwatch -c kidwatch -- \
         python -m kidwatch klucze-potwierdz; rc=$?; return $rc; }
```

Zasady:

- **KEK generuje i przechowuje właściciel.** Nigdy w repozytorium, w czacie,
  w opisie PR ani w tej samej kopii co dane (`/data`): kopia bazy + KEK
  w jednym miejscu = brak szyfrowania.
- KEK trzymaj w **menedżerze haseł** (wpis np. „Kidwatch KIDWATCH_KEK”) **i**
  w kopii Sekretów klastra — osobno od kopii wolumenu `/data`.
- Bez KEK Dom 1 z `config.yaml` działa jak dotąd. Nie startuje tylko dom
  w trybie `baza` (Dom 1 po imporcie — wtedy pod kończy się kodem 2, w logu
  „konfiguracja z bazy nie wystartowała”, i wpada w CrashLoop). Wyjście
  **bez `kubectl exec`**: pkt 4.
- Po przełączeniu Domu 1 na bazę **każde** odtworzenie Sekretu
  `kidwatch-secrets` (`docs/uruchomienie-od-zera.md` §7) musi zawierać
  `KIDWATCH_KEK` z menedżera haseł.

## 1. Wdrożenie obrazu E2

Nic do zrobienia. Dom 1 zostaje w trybie `yaml` (`kidwatch domy` pokazuje
„konfiguracja: config.yaml”). Chart dodaje opcjonalne zmienne
`KIDWATCH_KEK`/`KIDWATCH_KEK_POPRZEDNI` (z `kidwatch-secrets`, `optional: true`)
i wolumen w pamięci `/run/kidwatch` na pliki z sekretami.

## 2. Klucz KEK (właściciel)

Blok wrzuca nowy klucz do schowka (`pbcopy`; na Linuksie `xclip -sel clip`)
i **czeka**: zapisz klucz w menedżerze haseł (wpis „Kidwatch KIDWATCH_KEK”),
dopiero potem Enter. Wtedy schowek jest czyszczony — inaczej `kp` w pkt 3
wkleiłby klucz ze schowka i „potwierdził” wpis, którego w menedżerze nie ma.
Klucz trafia do Sekretu dopiero po zapisaniu w menedżerze.

**Tylko w zsh.** W bashu `read -rs '?…'` nie robi pauzy (bash 3.2 z macOS
nie ma też bracketed paste i połknąłby następną wklejoną linię), więc schowek
zostałby wyczyszczony, a Sekret zmieniony, zanim zapiszesz klucz. Blok
sprawdza powłokę i poza zsh nie robi nic („tylko w zsh”).

Przerwałeś pauzę Ctrl-C? Sekret jest nietknięty, ale klucz został w schowku
(i w zmiennej `KEK`). Jeśli go zapisałeś w menedżerze — albo rezygnujesz —
wyczyść schowek ręcznie: `pbcopy </dev/null; unset KEK`, i zacznij blok od
nowa. Blok celowo nie czyści schowka sam po przerwaniu: skasowałby klucz,
którego może jeszcze nie ma w menedżerze.

```sh
if [ -n "$ZSH_VERSION" ]; then
KEK=$(openssl rand -base64 32)
printf '%s' "$KEK" | pbcopy
read -rs '?Zapisz klucz w menedżerze haseł, potem Enter: '; echo
pbcopy </dev/null
kubectl -n default patch secret kidwatch-secrets --type merge --patch-file /dev/stdin <<EOF
{"stringData": {"KIDWATCH_KEK": "$KEK"}}
EOF
unset KEK
kubectl -n default rollout restart deploy/kidwatch
else echo "Ten blok tylko w zsh - nic nie wykonano"; fi
```

Sprawdzenie (bez wypisywania wartości):

```sh
kubectl -n default exec deploy/kidwatch -c kidwatch -- \
  python -c 'import os; print("KEK jest" if os.environ.get("KIDWATCH_KEK") else "BRAK KEK")'
```

## 3. Dom 1: config.yaml → baza

1. **Podgląd** — nic nie zapisuje (zapis, odczyt i porównanie w transakcji
   wycofywanej na końcu):

   ```sh
   k dom-importuj 1 --podglad
   ```

   Sprawdź:
   - `strefa` = strefa z `config.yaml` (nie domyślna);
   - lista dzieci i urządzeń;
   - przy integracjach: włączona/wyłączona i **maski** sekretów (`…a1b2`,
     `(64 znakow)`) — każdy sekret, którego dziś używasz, musi tu być;
   - `dozwolone_sieci`: adresy TV, UDM, Home Assistant i iPadów z odczytem
     wprost, każdy jako `/32`. Ostrzeżenie „to nazwa” = adres wzięty z dzisiejszego
     DNS; jeśli nazwa zmienia adres, dopisz sieć (`dom-sieci`, pkt 6);
   - na końcu „Porównanie: … identyczna”. Każda różnica (lista ścieżek pól,
     bez wartości) = **nic nie zapisano**, kod wyjścia 1.

2. **Zapis** (to samo + przełączenie Domu 1 na `baza`). `domy --sprawdz`
   ma pokazać „kluczy domow: 1, integracji: N” i „WYNIK: wszystko sie
   odszyfrowuje”. `kp` (klucz wklejony z MENEDŻERA HASEŁ) musi dać
   „POTWIERDZONO” — restart poda jest sklejony z nim przez `&&`:

   ```sh
   k dom-importuj 1 --zapisz
   k domy --sprawdz
   kp && kubectl -n default rollout restart deploy/kidwatch
   ```

   Po restarcie:

   ```sh
   kubectl -n default logs deploy/kidwatch -c kidwatch | grep "Dom 1: konfiguracja z bazy"
   ```

3. **48 h obserwacji**: liczba powiadomień i sesji jak przed przełączeniem
   (zakładka Historia w panelu albo `k summary --date <dzień>` dla kilku dni
   przed i po). `config.yaml` w Sekrecie `kidwatch-config` **zostaje** do
   końca następnego etapu — to droga powrotu.

   `kp` kończy się „ODMOWA” (kod 1), gdy klucz z menedżera haseł nie jest
   bieżącym kluczem albo baza nie ma czym go potwierdzić. Wtedy **nie
   restartuj** — wróć `k dom-zrodlo 1 yaml` i sprawdź wpis w menedżerze.

Uwagi:
- Do E3a panel dalej czyta listę urządzeń z `config.yaml`; zmiany
  konfiguracji Domu 1 rób na razie w obu miejscach albo wróć do `yaml`,
  zmień `config.yaml` i zaimportuj ponownie (`dom-importuj 1 --zapisz`
  nadpisuje dzieci, urządzenia i integracje domu).
- Token MDM Domu 1 to w E2 kopia `MDM_ADMIN_TOKEN`. W trybie `baza` z tokenu
  w bazie korzysta i czujka MDM, i pośrednik MDM w panelu (zakładka MDM,
  komendy) — `MDM_ADMIN_TOKEN` z Sekretu dotyczy wtedy tylko serwera MDM
  i Domu 1 w trybie `yaml`. Zmiana tokenu serwera MDM = wpis w panelu
  (pkt 10) **i** w Sekrecie serwera, ponowny import albo powrót do `yaml`.
- **Ponowny `dom-importuj --zapisz` nadpisuje integracje** wartościami
  z `config.yaml` i Sekretów — także te zmienione w panelu (pkt 10). Po
  zmianach w panelu nie importuj ponownie bez przeniesienia ich do
  `config.yaml`.
- Token aplikacji Kidwatch TV: po imporcie plik leży w pamięci poda,
  a ponowne sparowanie z panelu zapisuje nowy token w bazie (plik na `/data`
  zostaje stary). Ponowny import zachowuje token z bazy, gdy plik na `/data`
  jest starszy albo go nie ma (ostrzeżenie w podglądzie); nowszy plik
  (parowanie po powrocie do `yaml`) wygrywa. Po powrocie do `yaml` TV może
  wymagać ponownego sparowania.

## 4. Cofnięcie

- **Pod w CrashLoop** (brak lub zły `KIDWATCH_KEK`, uszkodzony wiersz) —
  `kubectl exec` nie zadziała, kontener nie żyje. Wymuszenie `config.yaml`
  kluczem w Sekrecie (ArgoCD nim nie zarządza, więc go nie cofnie):

  ```sh
  kubectl -n default patch secret kidwatch-secrets --type merge \
    -p '{"stringData": {"KIDWATCH_DOM_1_ZRODLO": "yaml"}}'
  kubectl -n default rollout restart deploy/kidwatch
  kubectl -n default logs deploy/kidwatch -c kidwatch | grep KIDWATCH_DOM_1_ZRODLO
  ```

  W logu: `KIDWATCH_DOM_1_ZRODLO=yaml: Dom 1 z config.yaml mimo trybu
  baza`. Baza zostaje bez zmian. Po naprawie przyczyny (KEK z menedżera
  haseł z powrotem w Sekrecie, `kp` = „POTWIERDZONO”) usuń klucz
  i zrestartuj:

  ```sh
  kubectl -n default patch secret kidwatch-secrets --type json \
    -p '[{"op": "remove", "path": "/data/KIDWATCH_DOM_1_ZRODLO"}]'
  kubectl -n default rollout restart deploy/kidwatch
  ```

  Inna wartość niż `yaml` jest ignorowana z ostrzeżeniem w logu.
  `k domy` przy ustawionym kluczu pokazuje „WYMUSZONE config.yaml” — zapomniany
  klucz blokuje późniejsze zamierzone przejście na bazę.

  **Uwaga przy cofaniu obrazu:** obraz `sha-c38b19c` (pierwsze wydanie E2)
  i starsze z trybem `baza` **ignorują** `KIDWATCH_DOM_1_ZRODLO`. Pod, który
  żyje tylko dzięki temu kluczowi, po cofnięciu do `sha-c38b19c` znów wpadnie
  w CrashLoop. Wtedy: napraw KEK albo cofnij do obrazu sprzed E2
  (`sha-2723214`, ignoruje tryb `baza` w ogóle).
- Konfiguracja z działającym podem: `k dom-zrodlo 1 yaml` + restart poda.
  Działa bez KEK.
- Obraz: poprzedni obraz (sprzed E2) ignoruje tabele integracji i tryb
  `baza` — czyta `config.yaml` i zmienne środowiskowe jak dawniej.
  Sprawdzone testem na prawdziwym kodzie obrazu `sha-2723214`
  (`tests/test_domy_e2.py`).

## 5. Kopia i test odtworzenia

Kopia `panel-auth.db` zawiera tylko szyfrogramy. Test odtworzenia (raz po
imporcie i po każdej rotacji). Kopia z poda:

```sh
kubectl -n default exec deploy/kidwatch -c kidwatch -- python -c \
  "import sqlite3; s=sqlite3.connect('/data/panel-auth.db'); d=sqlite3.connect('/tmp/kopia.db'); s.backup(d); d.close()"
kubectl -n default cp -c kidwatch "$(kubectl -n default get pod -l app.kubernetes.io/name=kidwatch -o name | head -1 | cut -d/ -f2)":/tmp/kopia.db ./kopia-panel-auth.db
kubectl -n default exec deploy/kidwatch -c kidwatch -- rm -f /tmp/kopia.db
```

Na swoim komputerze, w repozytorium — klucz wklejasz z menedżera haseł:

```sh
read -rs 'KIDWATCH_KEK?KIDWATCH_KEK z menedżera haseł: ' && export KIDWATCH_KEK; echo
uv run kidwatch domy --baza ./kopia-panel-auth.db --sprawdz
unset KIDWATCH_KEK; rm ./kopia-panel-auth.db
```

Wynik to liczby i werdykt, np. „kluczy domow: 1, integracji: 6” i „WYNIK:
wszystko sie odszyfrowuje” = kopia + KEK odtwarzają integracje. „WYNIK: nic
nie potwierdzono” (kod 1) = w kopii nie ma żadnego klucza domu (kopia sprzed
importu, zły plik) — to **nie jest** test klucza, niezależnie od klucza.
Każdy `BLAD:` wskazuje dom i integrację. Kopię można też sprawdzić kluczem
podanym na stdin: `uv run kidwatch klucze-potwierdz --baza ./kopia-panel-auth.db`. Bez KEK kopia odtwarza konta,
domy i urządzenia, a integracje trzeba wpisać od nowa (dla Domu 1:
`dom-zrodlo 1 yaml` i ponowny import z nowym KEK).

## 6. Sieci domu (SSRF)

Adresy wpisywane przy integracjach (UniFi, TV, Home Assistant, AdGuard,
iPady z odczytem wprost) muszą być publiczne albo leżeć w
`domy.dozwolone_sieci`. Sprawdzane po rozwiązaniu nazwy przy zapisie i przy
**każdym** połączeniu. Połączenie idzie tylko na sprawdzone adresy (kolejny,
gdy poprzedni nie odpowiada). Klienci nie śledzą przekierowań; gdyby kiedyś
śledzili, każdy skok przechodzi przez ten sam transport. Hosty API NextDNS i ntfy:
tylko `api.nextdns.io`, `ntfy.sh` i `dozwolone_hosty`. Zmienia je wyłącznie
administrator instancji:

Stan, dodanie sieci (ściśle: adres sieci, nie hosta), usunięcie i własny
host API (rzadko):

```sh
k dom-sieci 1
k dom-sieci 1 --dodaj 192.0.2.0/24
k dom-sieci 1 --usun 192.0.2.0/24
k dom-sieci 2 --host api.example.invalid
```

Działa po restarcie poda. Strażnik nie zastępuje NetworkPolicy (`wDomu`) —
to druga, niezależna bariera.

## 7. Rotacja KEK

Kolejność jest ważna: **najpierw dowód, że nowy klucz z menedżera haseł
otwiera bazę, dopiero potem usuwanie czegokolwiek**. `kp`
(`klucze-potwierdz`) odmawia (kod 1), gdy klucz z menedżera nie jest
bieżącym kluczem procesu albo choć jeden klucz domu jest jeszcze na starym.
Usunięcie klucza poprzedniego jest dlatego sklejone z `kp` w jednym
poleceniu (krok 3). Krok 5 (stary wpis w menedżerze haseł) dzieje się poza
Kidwatchem — tam warunek pilnujesz sam.

1. Nowy klucz obok starego. Blok wrzuca NOWY klucz do schowka i **czeka**:
   zapisz go w menedżerze haseł jako NOWY wpis (stary zostaje), potem Enter.
   Wtedy schowek jest czyszczony — `kp` w kroku 3 ma dowieść, że klucz JEST
   w menedżerze, a nie w schowku. Potem blok pyta o obecny klucz (z menedżera).
   **Tylko w zsh** — jak w pkt 2 blok poza zsh nie robi nic. Po Ctrl-C na
   pauzie Sekret jest nietknięty, a NOWY klucz zostaje w schowku: po
   zapisaniu go w menedżerze (albo rezygnacji) `pbcopy </dev/null; unset NOWY`
   i blok od nowa.

   ```sh
   if [ -n "$ZSH_VERSION" ]; then
   NOWY=$(openssl rand -base64 32)
   printf '%s' "$NOWY" | pbcopy
   read -rs '?Zapisz NOWY klucz w menedżerze haseł, potem Enter: '; echo
   pbcopy </dev/null
   read -rs 'STARY?obecny KIDWATCH_KEK z menedżera haseł: '; echo
   kubectl -n default patch secret kidwatch-secrets --type merge --patch-file /dev/stdin <<EOF
   {"stringData": {"KIDWATCH_KEK": "$NOWY", "KIDWATCH_KEK_POPRZEDNI": "$STARY"}}
   EOF
   unset NOWY STARY
   kubectl -n default rollout restart deploy/kidwatch
   else echo "Ten blok tylko w zsh - nic nie wykonano"; fi
   ```

2. Przepakowanie i sprawdzenie:

   `klucze-rotuj` przepakowuje tylko klucze domów:

   ```sh
   k klucze-rotuj
   k domy --sprawdz
   ```

3. **Dowód z menedżera haseł i dopiero wtedy usunięcie poprzedniego** —
   JEDNO polecenie: `kp` (skopiuj NOWY klucz ze świeżo otwartego wpisu
   w menedżerze — schowek jest pusty po kroku 1, więc innego źródła nie ma)
   przy „ODMOWA” kończy się kodem 1 i `&&` nie wykona usunięcia:

   ```sh
   kp && kubectl -n default patch secret kidwatch-secrets --type json \
     -p '[{"op": "remove", "path": "/data/KIDWATCH_KEK_POPRZEDNI"}]'
   ```

   Ten krok jest odwracalny, dopóki stary klucz jest w menedżerze haseł.

4. Start bez klucza poprzedniego i test odtworzenia (pkt 5) **nowym**
   kluczem z menedżera:

   ```sh
   kubectl -n default rollout restart deploy/kidwatch
   k domy --sprawdz
   ```

5. **Stary klucz w menedżerze haseł zostaje**, dopóki istnieje choć jedna
   kopia bazy sprzed rotacji: jej klucze domów są zapakowane STARYM kluczem
   i nowy ich nie otworzy (`kp` podaje datę ostatniej rotacji: „kopie bazy
   sprzed …”). Usunięcie starego wpisu jest nieodwracalne — wolno dopiero
   po usunięciu ostatniej takiej kopii.

## 8. Nowy klucz danych jednego domu

Po odebraniu komuś dostępu do integracji domu (mógł zrobić zrzut bazy):

```sh
k dom-klucz-rotuj 2
```

Przeszyfrowuje integracje tego domu nowym kluczem danych. Same sekrety
zewnętrzne (klucz NextDNS itd.) zmienia się w ich usługach i w panelu.

## 9. Komunikaty

| Komunikat | Znaczenie | Co zrobić |
|---|---|---|
| `brak KIDWATCH_KEK w srodowisku` | dom w trybie `baza`, a Sekret bez klucza; pod w CrashLoop | pkt 4 (`KIDWATCH_DOM_1_ZRODLO=yaml` bez exec), potem KEK z menedżera haseł |
| `WYNIK: nic nie potwierdzono` | baza/kopia bez kluczy domów — test niczego nie dowodzi | właściwa kopia (po imporcie) |
| `ODMOWA: klucz … NIE jest potwierdzony` | klucz z menedżera haseł nie otwiera bazy albo nie jest bieżący | nie usuwaj żadnego klucza; sprawdź wpis, `klucze-rotuj` |
| `DEK domu N zapakowany kluczem X, a proces zna Y` | KEK zmieniony bez `KIDWATCH_KEK_POPRZEDNI` | pkt 7 (dodaj poprzedni, `klucze-rotuj`) |
| `… nie odszyfrowuja sie (… z innego domu/typu)` | szyfrogram przeniesiony między wierszami albo uszkodzony | wpisz integrację od nowa |
| `adres … jest poza siecią domu` | adres integracji spoza `dozwolone_sieci` | pkt 6, jeśli adres jest właściwy |
| `ROZNICE config.yaml <-> baza` | import niezgodny pole w pole — nic nie zapisano | zgłoś listę ścieżek; nie przełączaj |
| `po tej zmianie dom nie wystartuje — …` (panel) | zapis integracji wyłączyłby jedyne źródło DNS, usunął wymagany klucz itp. — nic nie zapisano | najpierw włącz/uzupełnij to, czego brakuje |
| `Nowa konfiguracja (wersja N) nie wystartowała` (panel) albo `dom N: nowa konfiguracja (wersja N) nie wystartuje` (log) | nadzorca nie przebudował domu; dom działa dalej na poprzedniej wersji | popraw integrację w panelu (kolejny zapis = kolejna próba) |
| `Dom N: start na ostatniej dobrej konfiguracji` (alarm) | bieżąca wersja nie wstała przy starcie poda; dom działa na kopii | popraw integrację w panelu (Ustawienia → Integracje); przeładowanie zrobi resztę |
| `Konfiguracja domu zmieniła się od wczytania ekranu` (panel, 409) | ktoś zapisał dom w międzyczasie | odśwież ekran i wpisz zmianę ponownie |
| `Ten dom ma konfigurację z config.yaml` (panel, 409) | ekran integracji dla domu w trybie `yaml` | zmiany w `config.yaml` albo najpierw pkt 3 |

## 10. Integracje w panelu (administrator instalacji)

Od 2026-10-12 sekrety i ustawienia integracji domu (NextDNS, AdGuard, UniFi,
TV, MDM, ntfy, Home Assistant) wpisuje się w panelu: *Ustawienia →
Integracje* w kontekście wybranego domu. Ekran widzi **tylko aktywny
administrator instalacji** (flaga `user-admin` + grupa `admins` w Authelii
albo hasło z TOTP); `wlasciciel-domu` dostaje 403, cudzy dom — 404.

- Działa tylko dla domów w trybie `baza` (Dom 1 po pkt 3, każdy nowy dom).
  Dom w trybie `yaml` — odmowa 409 z komunikatem.
- Sekrety są **tylko do zapisu**: panel pokazuje maskę (`…a073` albo
  długość), puste pole zostawia sekret bez zmian, usunięcie to osobny
  przycisk. Każda zmiana wymaga hasła albo kodu 2FA i zostawia wpis
  w dzienniku domu (`integracja.zapis`: kto, typ, nazwy zmienionych pól —
  bez wartości; odczyt: `integracje.odczyt`; odrzucona: `integracja.odmowa`).
- Adresy (`unifi.url`, `tv.host`, …) przechodzą przez strażnika sieci domu
  (pkt 6). Odmowa w panelu wskazuje `dom-sieci` — sieci i hosty API dopuszcza
  się wyłącznie z CLI.
- Zapis, po którym działający dom by nie wystartował (wyłączone jedyne
  źródło DNS, usunięty klucz NextDNS…), jest odrzucany w całości.
- Przełączenie źródła DNS: włączenie AdGuarda wyłącza NextDNS (i odwrotnie)
  w tym samym zapisie — dom ma dokładnie jedno źródło.
- Ekran wysyła wersję konfiguracji, którą wczytał; jeśli ktoś w międzyczasie
  zmienił dom (drugi zapis, CLI), zapis dostaje 409 „odśwież”.
- **Przełączenie bez restartu** (architektura §5.1): zapis podbija
  `domy.wersja`, nadzorca co 10 s porównuje wersje i przebudowuje tylko ten
  dom (kursory, sesje i dedup są w bazie domu — jak przy restarcie poda).
  Ekran pokazuje, na której wersji dom działa. Jeśli nowa konfiguracja nie
  wstaje, dom działa dalej na poprzedniej, a ekran i log mówią dlaczego.
  Dom bez przeładowania (dziś: każdy dom poza Domem 1 — uruchamianie
  kolejnych domów to E3b) — ekran mówi wprost „zmiana zadziała po restarcie
  Kidwatcha”.
- **Nieudane przełączenie nie jest ciche**: wpis `dom.przeladowanie.blad`
  w dzienniku domu (raz na wersję, zostaje po restarcie), stan na ekranie
  i alarm instancji przez bramkę — od razu, potem po 1 h, 2 h, 4 h… (najwyżej
  raz na dobę), aż dom wstanie (wtedy jeden alarm „konfiguracja znów
  działa”). Błąd konfiguracji (model, brak sekretu, odmowa strażnika, sejf)
  czeka na następną zmianę; błąd przejściowy (baza zajęta, DNS, sieć)
  nadzorca ponawia sam po 1, 5 i 30 min (potem co 30 min).
- **Kopia ostatniej dobrej konfiguracji** (`domy_kopia`, sekrety nadal
  zaszyfrowane kluczem domu; `dom-klucz-rotuj` przeszyfrowuje też ją, a kopię,
  której nie da się odszyfrować, usuwa z wpisem `dom.kopia.usunieta`;
  `domy --sprawdz` sprawdza też jej odszyfrowanie):
  zapisywana po każdym udanym starcie i przeładowaniu. Gdy przy starcie
  poda bieżąca wersja nie wstaje, Dom 1 startuje na kopii (wpis, alarm,
  stan na ekranie), a panel działa — zamiast CrashLoop, który zabrałby też
  ekran do poprawki. **Kopia to stan z chwili ostatniego udanego startu**:
  sekret usunięty albo zmieniony w panelu PO nim (np. unieważniony klucz)
  zostaje w kopii do następnego udanego startu lub przeładowania — start na
  kopii użyje starej wartości. Klucz, który trzeba unieważnić natychmiast,
  unieważnij u dostawcy (NextDNS, UniFi…), nie tylko w panelu.
  Alarm „Kidwatch nie wystartował” przy CrashLoop idzie z tym samym
  rosnącym odstępem, liczonym z dziennika (`dom.start.alarm`), nie przy
  każdym restarcie poda. Bez kopii (pierwszy start po wdrożeniu, kopia nie
  wstaje) — jak dotąd: log, alarm, kod 2 i pkt 4. To samo w trakcie pracy:
  nowa i poprzednia konfiguracja nie wstają → kopia → dopiero potem koniec
  procesu.
- Pliki z sekretów (klucz ADB, token TV) nadzorca zapisuje dopiero po
  zatrzymaniu starego środowiska — nieudana próba ich nie podmienia.
- Powrót do `yaml` (`dom-zrodlo 1 yaml`) dalej wymaga restartu poda.
