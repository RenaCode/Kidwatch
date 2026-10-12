# Komendy z WhatsAppa

Rodzic (opiekun domu) pisze do bota Kidwatcha na WhatsAppie, a Kidwatch
wykonuje akcję z **zamkniętej listy** — zawsze po potwierdzeniu kodem.
Funkcja jest wyłączona domyślnie (`whatsapp_komendy.enabled: false`).

## Jak to wygląda

```
rodzic:  koniec Dziecko A
bot:     Zrozumiałem: zakończyć: zablokować gry — Dziecko A i ekran (iPad A)?
         Odpowiedz TAK 4821 (ważne 2 min).
rodzic:  TAK 4821
bot:     Zrobione: Dziecko A: gry zablokowane; iPad A: ekran zablokowany.
drugi opiekun dostaje kopię.
```

Można też odpowiedzieć (cytatem) na powiadomienie Kidwatcha — wtedy dom,
dziecko i urządzenie wynikają z powiadomienia — albo napisać zwykłym
zdaniem („niech Dziecko A już kończy”), które rozpoznaje LLM.

| Komenda | Co robi | Uprawnienie w domu | Kierunek |
|---|---|---|---|
| `stan` | kto teraz co robi, ile zostało czasu gry (bez kodu) | `podglad.historia` | odczyt |
| `koniec <dziecko>` | blokada gier w NextDNS + DeviceLock iPada | `czas_gry.zmiana` (+ `mdm.komendy` dla ekranu) | zaostrza |
| `zablokuj ipad <dziecko>` | DeviceLock (bez nadzoru dziecko z PIN-em odblokuje) | `mdm.komendy` | zaostrza |
| `-15 <dziecko>` | skraca **dodany** czas gry | `czas_gry.zmiana` | zaostrza |
| `+15 <dziecko>` | dodaje czas gry, limit dzienny | `czas_gry.zmiana` | **luzuje** |
| `odblokuj <dziecko>` | odblokowuje gry, limit dzienny | `czas_gry.zmiana` | **luzuje** |
| `cisza 2h` | wycisza powiadomienia **własnego** konta | — | tylko siebie |
| `pomoc` | lista komend (bez kodu) | — | — |

Każda komenda wymaga też uprawnienia **`whatsapp.komendy`** w domu. Ma je
rola `wlasciciel-domu`; `zarzadca` tylko pojedynczym nadaniem
(`user-uprawnienia <login> +whatsapp.komendy`), `podglad` nigdy.

Bez zapisu na telewizor, bez głośności, bez restartu i wyłączania iPada.

## Decyzje właściciela (2026-10-12)

- `stan` i `pomoc` odpowiadają **bez kodu** — niczego nie zmieniają.
  Każda inna akcja wymaga `TAK <kod>`.
- Dzienny limit luzowania z WhatsAppa na dziecko: **+30 min** czasu gry
  i **1 odblokowanie** gier (oba konfigurowalne, 0 = wyłączone).
- `zarzadca` **nie ma** komend domyślnie — tylko po pojedynczym nadaniu
  `whatsapp.komendy`; `wlasciciel-domu` ma je z roli, `podglad` nigdy.

## Bezpieczeństwo

- **Nieznany numer: cisza.** Bot nie odpowiada (nie zdradza, że przyjmuje
  komendy, i nie ryzykuje blokady numeru za spam); wpis w dzienniku
  z zamaskowanym numerem.
- **Kod potwierdzenia:** 4 cyfry z `secrets`, jednorazowy, ważny 2 min,
  przypisany do numeru i jednej akcji; nowa komenda unieważnia poprzedni
  kod. 5 złych kodów → numer wstrzymany na 15 min.
- **Przy kodzie wszystko sprawdzane drugi raz:** uprawnienie, wyłącznik,
  limity — odebrane w ciągu tych 2 minut prawo działa od razu.
- **Luzowanie** (`+N`, `odblokuj`): dzienny limit z WhatsAppa na dziecko
  (domyślnie 30 min i 1 odblokowanie, liczone po wszystkich opiekunach),
  zawsze kopia do drugiego opiekuna. Kod nie zatrzyma dziecka z
  odblokowanym telefonem rodzica — zatrzymuje je limit i jawność.
- **Kopia każdej wykonanej komendy** idzie do pozostałych opiekunów domu
  (konta z `whatsapp.komendy`) ich kanałem, niezależnie od ich ciszy.
- **Limit komend:** 10 na godzinę z jednego numeru (potwierdzenia `TAK`
  się nie liczą); po przekroczeniu jedna odpowiedź, potem cisza.
- **Stare wiadomości** (ponad 10 min od wysłania) nie są wykonywane.
- **Wyłącznik awaryjny:** panel → Ustawienia → „Komendy z WhatsAppa —
  wszystkie domy” (administrator instalacji, `whatsapp.konfiguracja`).

### LLM

- LLM **niczego nie wykonuje**: dostaje treść jako DANE (między
  znacznikami) oraz nazwy dzieci i urządzeń domu, a zwraca obiekt w
  schemacie (Gemini `responseSchema`, Anthropic wymuszone narzędzie).
- Wynik jest walidowany po stronie Kidwatcha (`komendy.z_llm`): akcja
  z listy, dziecko i urządzenie **dokładnie** z konfiguracji domu, liczby
  w zakresie, żadnych dodatkowych pól. Cokolwiek innego → „Nie zrozumiałem”.
  Wynik LLM przechodzi tę samą drogę co dokładna komenda: uprawnienia,
  limity, kod.
- Do dostawcy nie idzie numer telefonu, login, nazwa domu ani nic z bazy.
- **Dostawca: na razie sam Gemini** (decyzja 2026-10-12). Anthropic jest
  w kodzie jako opcjonalny drugi dostawca (`llm.dostawcy: [gemini,
  anthropic]` + `KIDWATCH_LLM_ANTHROPIC_KEY`); bez klucza jest pomijany.
- **Klucz Gemini jest dziś wspólny** z Traderem i Dietetykiem — wspólne
  limity, w przeszłości dzienny 429. Docelowo klucz zostanie rozdzielony
  (osobny projekt/klucz dla Kidwatcha). Do tego czasu Kidwatch oszczędza
  wspólny limit:
  - dokładne komendy (`stan`, `koniec`, `+15`, `TAK 1234`…) w ogóle nie
    wołają LLM;
  - dobowy limit wywołań Kidwatcha `llm.wywolan_na_dobe` (domyślnie 100);
  - krótki timeout `llm.timeout_seconds` (domyślnie 6 s);
  - **429 = chwilowa niedostępność**: bez alarmu, czytelna odpowiedź
    („Nie rozumiem teraz swobodnego tekstu, napisz np. …”) i przerwa
    `llm.przerwa_po_429_seconds` (domyślnie 15 min), w której Gemini nie
    jest wołany wcale.
- Inna awaria wszystkich dostawców (zły klucz, brak środków, 5xx, timeout):
  ta sama odpowiedź plus alarm instancji — od razu, potem po 1 h, 2 h,
  4 h… najwyżej raz na dobę. Dokładne komendy działają zawsze.

## Włączenie

1. Bramka z W1 (skrzynka `GET /v1/whatsapp/skrzynka`, `POST
   /v1/whatsapp/skrzynka/potwierdz`, `id` w odpowiedzi wysyłki) i z
   jawnym odbiorcą (`funkcje: ["odbiorca"]`). Bez odbiorcy bot nie pobiera
   skrzynki — odpowiedź poszłaby trasami do wszystkich.
2. Klucz Gemini w Sekrecie `kidwatch-secrets` (envFrom):
   `KIDWATCH_LLM_GEMINI_KEY` — dziś kopia klucza Tradera i Dietetyka. Bez
   niego działają tylko dokładne komendy.
3. W konfiguracji (Sekret `kidwatch-config`): `whatsapp_komendy.enabled: true`,
   restart poda.
4. Opiekunowie muszą mieć numer WhatsApp w swoim profilu (Ustawienia →
   Moje powiadomienia) — numer jest kluczem do konta.

## Dane

Wszystko w `panel-auth.db` (tworzone dopiero przy włączonej funkcji):
dziennik komend (90 dni), kody, limity, id wysłanych powiadomień (7 dni,
do rozpoznania cytatu), wyciszenia, licznik wywołań LLM i wyłącznik.

## Nadzór iPadów (W5)

`lost_mode: true` wysyła `EnableLostMode` zamiast `DeviceLock` do iPadów
**pod nadzorem**. Serwer MDM nie ma jeszcze tej komendy w `API_COMMANDS`
(odrzuci ją 400), więc opcja zostaje wyłączona do czasu nadzoru i zmiany
w `kidwatch-mdm`. `odblokuj` nie zdejmuje dziś Lost Mode.
