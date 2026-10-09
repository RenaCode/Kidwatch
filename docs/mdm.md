# kidwatch-mdm — własny serwer MDM

Osobny kontener obok Kidwatch. Pilnuje na iPadach dzieci:

| Co | Jak | Działa na |
|---|---|---|
| brak VPN | `allowVPNCreation = false` (od iOS 18 także aplikacje z App Store) | nadzorowanym |
| ruch widoczny w DNS | DNS-over-HTTPS z DDM + `ProhibitDisablement`, `allowCloudPrivateRelay = false` | nadzorowanym (bez nadzoru: tylko sieci zarządzane) |
| profil nie do usunięcia | `PayloadRemovalDisallowed` w profilu zapisu | nadzorowanym |
| bez wymazania z Ustawień | `allowEraseContentAndSettings = false` | nadzorowanym |
| bez cudzych profili | `allowUIConfigurationProfileInstallation = false` | nadzorowanym |
| aktualizacje | DDM: automatyczne pobieranie i instalacja + wymuszenie wersji do terminu | instalacja automatyczna: nadzorowanym; wymuszenie: każdym |
| stan iPada | system, bateria, nadzór, lista aplikacji (alarm o nowych), profile | każdym |

Nadzór (supervision) to warunek wszystkich blokad. Bez niego iOS przyjmie profil i zignoruje ograniczenia — dlatego serwer dokłada klucze „tylko pod nadzorem” dopiero, gdy iPad sam zgłosi `IsSupervised = true`.

## Architektura

```
iPad ──HTTPS──▶ Traefik ──/mdm/*──▶ kidwatch-mdm :8080  (checkin, connect, enroll)
                                        │
Kidwatch ──token──▶ kidwatch-mdm-admin :8081  (tylko w klastrze, NetworkPolicy)
                                        │
kidwatch-mdm ──HTTP/2 + cert──▶ api.push.apple.com  (budzenie iPadów)
```

- Każdy iPad dostaje w profilu zapisu **własny certyfikat** od CA serwera. Każda jego wiadomość jest podpisana (`Mdm-Signature`) i sprawdzana: wystawca, podpis treści, powiązanie z UDID.
- Komendy czekają w kolejce. Push mówi iPadowi tylko „połącz się”; nieudany push nie gubi komendy.
- Pętla uzgadniania co 5 min: odświeża stan iPadów (co `refresh_hours`), instaluje profil ograniczeń, gdy go brak albo się zmienił, i wysyła DDM po zmianie polityki.

## Krok 1 — certyfikat push APNs (raz, potem odnowienie co rok)

Apple wydaje certyfikat push MDM tylko na wniosek podpisany przez dostawcę MDM. Dla własnych serwerów robi to mdmcert.download (wymaga konta organizacji z firmowym adresem e-mail).

```sh
kidwatch-mdm apns new --email contact@renacode.com   # klucze i CSR w ~/.kidwatch-mdm/apns
kidwatch-mdm apns send                               # wysyłka do mdmcert.download
# mail z załącznikiem *.plist.b64.p7
kidwatch-mdm apns decrypt ~/Downloads/mdm_signed_request.*.plist.b64.p7
# push.req -> https://identity.apple.com -> pobierz .pem
kidwatch-mdm apns check ~/Downloads/MDM_*.pem        # pasuje do klucza? temat? ważność?
```

**Zapisz, jakim Apple ID logujesz się na identity.apple.com.** Odnowienie musi być z tego samego konta i dla tego samego certyfikatu (przycisk „Renew”), inaczej zmieni się temat i wszystkie iPady trzeba zapisać od nowa. Serwer pokazuje dni do wygaśnięcia w `GET /api/health` (`apns.days_left`).

Zrób kopię `~/.kidwatch-mdm/apns/push.key` (np. w menedżerze haseł). Bez niego certyfikat od Apple jest bezużyteczny.

## Krok 2 — sekrety w klastrze

```sh
kidwatch-mdm init-ca --dir ./mdm-ca      # RAZ. Kopia ca.key obowiązkowa.
kubectl -n default create secret generic kidwatch-mdm-ca \
  --from-file=ca.crt=./mdm-ca/ca.crt --from-file=ca.key=./mdm-ca/ca.key
kubectl -n default create secret generic kidwatch-mdm-apns \
  --from-file=push.pem=<pobrany>.pem --from-file=push.key=$HOME/.kidwatch-mdm/apns/push.key
kubectl -n default create secret generic kidwatch-mdm-admin \
  --from-literal=token=$(openssl rand -hex 32)
cp charts/kidwatch-mdm/files/policy.example.yaml policy.yaml   # uzupełnij NextDNS
kubectl -n default create secret generic kidwatch-mdm-policy --from-file=policy.yaml
```

Repo jest publiczne — prawdziwej polityki (adresy NextDNS, etykiety dzieci) nie commituj.

## Krok 3 — DNS i ArgoCD

1. Rekord `mdm.renacode.com` → adres VPS (tak jak `kidwatch.renacode.com`).
2. W `renacode-infra/argocd-apps.yaml` aplikacja (stosowana ręcznie, `kubectl apply`):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: kidwatch-mdm
  namespace: argocd
spec:
  project: default
  source:
    repoURL: 'git@github.com:RenaCode/Kidwatch.git'
    targetRevision: HEAD
    path: charts/kidwatch-mdm
  destination:
    server: 'https://kubernetes.default.svc'
    namespace: default
  syncPolicy:
    automated:
      prune: false     # PVC z bazą: utrata = ponowny zapis wszystkich iPadów
      selfHeal: true
```

Sprawdzenie: `curl https://mdm.renacode.com/mdm/enroll/x` → 404 (serwer odpowiada), a w podzie `GET :8081/api/health` → `"configured": true`.

## Krok 4 — iPad testowy (bez nadzoru, bez wymazywania)

```sh
kubectl -n default exec deploy/kidwatch-mdm -- kidwatch-mdm enroll test
```

Link otwórz w Safari na iPadzie → Ustawienia → Pobrany profil → Zainstaluj. Profil jest podpisany certyfikatem TLS `mdm.renacode.com` (Let's Encrypt, Sekret `kidwatch-mdm-tls-cert` od cert-managera), więc iOS pokaże go jako „Zweryfikowany”. Gdy certyfikatu brak, serwer poda profil bez podpisu, zapisze zdarzenie `profile_unsigned` i iOS pokaże „Niezweryfikowany” — zapis i tak zadziała.

Co da się sprawdzić bez nadzoru: zapis, push, komendy, lista aplikacji (i alarm o nowej), DDM (status systemu, wymuszona aktualizacja). Czego **nie** da się: blokad (iOS je zignoruje), DNS w domowym Wi-Fi (bez nadzoru serwer NIE wysyła DNS wcale — nie objąłby domowej sieci, a mógłby wyprzeć ręczny profil NextDNS), nieusuwalności profilu.

## Krok 5 — iPady dzieci (nadzór)

Nadzór wymaga wymazania iPada. Dwie drogi:

- **Apple Configurator (bez organizacji):** Mac + kabel, raz. „Przygotuj” → Ręczna konfiguracja → zaznacz „Nadzoruj urządzenia” → serwer MDM: nowy serwer z adresem z `kidwatch-mdm enroll <etykieta>`. **NIE** odznaczaj „Zezwalaj na parowanie z innymi komputerami” — Kidwatch czyta listę procesów przez parowanie. Reset w trybie odzyskiwania (komputer + kabel) zdejmuje nadzór; Kidwatch zauważy to jako ciszę iPada i zdarzenie `checkout`.
- **Apple Business (jeśli wniosek przejdzie):** zapis automatyczny (ADE) bez kabla, nadzór wraca sam po każdym resecie. Wymaga dodatkowo obsługi tokenu ADE — osobny etap.

Plan zachowania zapisów gier („pranie” kopii przez inne urządzenie) jest w notatkach projektu.

## Krok 6 — Kidwatch

W prawdziwej konfiguracji Kidwatch (Sekret `kidwatch-config`, `tools/wgraj_konfiguracje.sh`):

```yaml
mdm:
  enabled: true
```

Token przychodzi sam z Sekretu `kidwatch-mdm-admin` (chart kidwatch, `mdmAdminSecret`). Po restarcie:

- **zakładka MDM w panelu**: iPady (nadzór, system, kontakt, błędy push), odśwież / zablokuj ekran / restart, wymuszona aktualizacja, link do zapisu nowego iPada, dziennik zdarzeń;
- **alarmy** (trasa bramki `kidwatch:czujka`, nie do rodziny): profil zdjęty, utrata nadzoru, zniknięty profil, iPad bez kontaktu > 24 h, odrzucone pushe, certyfikat APNs < 30 dni; nowa/usunięta aplikacja idzie jak dotąd jako `kidwatch:alarm`.

## API dla Kidwatch (port 8081, `Authorization: Bearer <token>`)

| Metoda | Ścieżka | Co |
|---|---|---|
| GET | `/api/health` | bez tokenu; stan certyfikatu APNs, liczba iPadów |
| GET | `/api/devices` | lista iPadów (nadzór, system, ostatni kontakt, błąd push, synchronizacja DDM) |
| GET | `/api/devices/<udid>` | szczegóły: informacje, aplikacje, profile, status DDM, historia komend |
| POST | `/api/devices/<udid>/refresh` | odśwież stan teraz |
| POST | `/api/devices/<udid>/commands` | `{"request_type": "DeviceLock", "Message": "..."}` albo `RestartDevice` |
| POST | `/api/enrollments` | `{"label": "dziecko1"}` → link do profilu zapisu (24 h, jednorazowy) |
| GET/PUT | `/api/os-update` | `{"target_version": "27.1", "deadline": "2026-10-20T20:00:00"}`, `{"clear": true}`, `{"disabled": true}` |
| GET | `/api/events?since=<id>` | dziennik: `checkout`, `profile_missing`, `apps_installed`, `command_error`, `push_token_dead`, `os_update_failed`, `signature_rejected`… |
| GET | `/api/policy` | polityka w użyciu |

## Czego serwer świadomie nie robi

- **Nie wymazuje iPadów ani nie zdejmuje kodu.** API przyjmuje tylko blokadę ekranu i restart; reszta wynika z polityki.
- **Nie instaluje aplikacji.** Ciche instalacje wymagają licencji VPP z Apple Business.
- **Nie przechowuje kluczy prywatnych iPadów.** Klucz żyje tylko w profilu i na urządzeniu.
