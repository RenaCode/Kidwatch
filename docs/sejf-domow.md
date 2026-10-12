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

Wszystkie polecenia w klastrze uruchamia się w podzie:

```sh
k() { kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch "$@"; }
```

Zasady:

- **KEK generuje i przechowuje właściciel.** Nigdy w repozytorium, w czacie,
  w opisie PR ani w tej samej kopii co dane (`/data`): kopia bazy + KEK
  w jednym miejscu = brak szyfrowania.
- KEK trzymaj w **menedżerze haseł** (wpis np. „Kidwatch KIDWATCH_KEK”) **i**
  w kopii Sekretów klastra — osobno od kopii wolumenu `/data`.
- Bez KEK Dom 1 z `config.yaml` działa jak dotąd. Nie startuje tylko dom
  w trybie `baza` (Dom 1 po imporcie — wtedy pod kończy się kodem 2, w logu
  „konfiguracja z bazy nie wystartowała”).

## 1. Wdrożenie obrazu E2

Nic do zrobienia. Dom 1 zostaje w trybie `yaml` (`kidwatch domy` pokazuje
„konfiguracja: config.yaml”). Chart dodaje opcjonalne zmienne
`KIDWATCH_KEK`/`KIDWATCH_KEK_POPRZEDNI` (z `kidwatch-secrets`, `optional: true`)
i wolumen w pamięci `/run/kidwatch` na pliki z sekretami.

## 2. Klucz KEK (właściciel)

```sh
KEK=$(openssl rand -base64 32)
printf '%s\n' "$KEK"            # skopiuj do menedżera haseł, potem wyczyść ekran
kubectl -n default patch secret kidwatch-secrets --type merge --patch-file /dev/stdin <<EOF
{"stringData": {"KIDWATCH_KEK": "$KEK"}}
EOF
unset KEK
kubectl -n default rollout restart deploy/kidwatch
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

2. **Zapis** (to samo + przełączenie Domu 1 na `baza`):

   ```sh
   k dom-importuj 1 --zapisz
   k domy --sprawdz                       # „wszystko sie odszyfrowuje”
   kubectl -n default rollout restart deploy/kidwatch
   kubectl -n default logs deploy/kidwatch -c kidwatch | grep "Dom 1: konfiguracja z bazy"
   ```

3. **48 h obserwacji**: liczba powiadomień i sesji jak przed przełączeniem
   (zakładka Historia w panelu albo `k summary --date <dzień>` dla kilku dni
   przed i po). `config.yaml` w Sekrecie `kidwatch-config` **zostaje** do
   końca następnego etapu — to droga powrotu.

Uwagi:
- Do E3a panel dalej czyta listę urządzeń z `config.yaml`; zmiany
  konfiguracji Domu 1 rób na razie w obu miejscach albo wróć do `yaml`,
  zmień `config.yaml` i zaimportuj ponownie (`dom-importuj 1 --zapisz`
  nadpisuje dzieci, urządzenia i integracje domu).
- Token MDM Domu 1 to w E2 kopia `MDM_ADMIN_TOKEN`. Zmiana tokenu serwera
  MDM = ponowny import (albo powrót do `yaml`).
- Token aplikacji Kidwatch TV: po imporcie plik leży w pamięci poda,
  a ponowne sparowanie z panelu zapisuje nowy token w bazie.

## 4. Cofnięcie

- Konfiguracja: `k dom-zrodlo 1 yaml` + restart poda. Działa bez KEK.
- Obraz: poprzedni obraz (sprzed E2) ignoruje tabele integracji i tryb
  `baza` — czyta `config.yaml` i zmienne środowiskowe jak dawniej.
  Sprawdzone testem na prawdziwym kodzie obrazu `sha-2723214`
  (`tests/test_domy_e2.py`).

## 5. Kopia i test odtworzenia

Kopia `panel-auth.db` zawiera tylko szyfrogramy. Test odtworzenia (raz po
imporcie i po każdej rotacji):

```sh
kubectl -n default exec deploy/kidwatch -c kidwatch -- python -c \
  "import sqlite3; s=sqlite3.connect('/data/panel-auth.db'); d=sqlite3.connect('/tmp/kopia.db'); s.backup(d); d.close()"
kubectl -n default cp -c kidwatch "$(kubectl -n default get pod -l app.kubernetes.io/name=kidwatch -o name | head -1 | cut -d/ -f2)":/tmp/kopia.db ./kopia-panel-auth.db
kubectl -n default exec deploy/kidwatch -c kidwatch -- rm -f /tmp/kopia.db

# na swoim komputerze, w repozytorium:
read -rs KIDWATCH_KEK && export KIDWATCH_KEK     # wklej z menedżera haseł
uv run kidwatch domy --baza ./kopia-panel-auth.db --sprawdz
unset KIDWATCH_KEK; rm ./kopia-panel-auth.db
```

Wynik „wszystko sie odszyfrowuje” = kopia + KEK odtwarzają integracje.
Każdy `BLAD:` wskazuje dom i integrację. Bez KEK kopia odtwarza konta,
domy i urządzenia, a integracje trzeba wpisać od nowa (dla Domu 1:
`dom-zrodlo 1 yaml` i ponowny import z nowym KEK).

## 6. Sieci domu (SSRF)

Adresy wpisywane przy integracjach (UniFi, TV, Home Assistant, AdGuard,
iPady z odczytem wprost) muszą być publiczne albo leżeć w
`domy.dozwolone_sieci`. Sprawdzane po rozwiązaniu nazwy przy zapisie i przy
**każdym** połączeniu (także przekierowaniu). Hosty API NextDNS i ntfy:
tylko `api.nextdns.io`, `ntfy.sh` i `dozwolone_hosty`. Zmienia je wyłącznie
administrator instancji:

```sh
k dom-sieci 1                                 # stan
k dom-sieci 1 --dodaj 192.0.2.0/24            # ściśle: adres sieci, nie hosta
k dom-sieci 1 --usun 192.0.2.0/24
k dom-sieci 2 --host api.example.invalid      # własny host API (rzadko)
```

Działa po restarcie poda. Strażnik nie zastępuje NetworkPolicy (`wDomu`) —
to druga, niezależna bariera.

## 7. Rotacja KEK

```sh
NOWY=$(openssl rand -base64 32)                 # do menedżera haseł jako nowy wpis
STARY=<obecny KIDWATCH_KEK z menedżera haseł>
kubectl -n default patch secret kidwatch-secrets --type merge --patch-file /dev/stdin <<EOF
{"stringData": {"KIDWATCH_KEK": "$NOWY", "KIDWATCH_KEK_POPRZEDNI": "$STARY"}}
EOF
unset NOWY STARY
kubectl -n default rollout restart deploy/kidwatch
k klucze-rotuj                                  # przepakowuje tylko klucze domów
k domy --sprawdz
kubectl -n default patch secret kidwatch-secrets --type json \
  -p '[{"op": "remove", "path": "/data/KIDWATCH_KEK_POPRZEDNI"}]'
kubectl -n default rollout restart deploy/kidwatch
k domy --sprawdz                                # bez poprzedniego klucza
```

Po rotacji zrób test odtworzenia (pkt 5) i dopiero wtedy usuń stary wpis
z menedżera haseł.

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
| `brak KIDWATCH_KEK w srodowisku` | dom w trybie `baza`, a Sekret bez klucza | pkt 2 albo `dom-zrodlo 1 yaml` |
| `DEK domu N zapakowany kluczem X, a proces zna Y` | KEK zmieniony bez `KIDWATCH_KEK_POPRZEDNI` | pkt 7 (dodaj poprzedni, `klucze-rotuj`) |
| `… nie odszyfrowuja sie (… z innego domu/typu)` | szyfrogram przeniesiony między wierszami albo uszkodzony | wpisz integrację od nowa |
| `adres … jest poza siecią domu` | adres integracji spoza `dozwolone_sieci` | pkt 6, jeśli adres jest właściwy |
| `ROZNICE config.yaml <-> baza` | import niezgodny pole w pole — nic nie zapisano | zgłoś listę ścieżek; nie przełączaj |
