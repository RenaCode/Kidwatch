#!/usr/bin/env bash
# Podpis profilu .mobileconfig certyfikatem HTTPS panelu Kidwatch.
#
# Po co: niepodpisany profil iOS pokazuje jako "Niezweryfikowany". Podpisany
# certyfikatem, ktory lancuchem dochodzi do zaufanego urzedu (Let's Encrypt
# z cert-managera, Sekret kidwatch-tls-cert), pokazuje sie jako
# "Zweryfikowany" z nazwa domeny. Podpis NIE blokuje usuniecia profilu - to
# daje tylko tryb nadzorowany (gen_profile.py --supervised).
#
# Uruchamia ROOT (sudo): klucz prywatny certyfikatu czyta tylko kubectl
# z uprawnieniami administratora, laduje w katalogu tymczasowym 0700 i znika
# razem z nim po podpisie - nie przechodzi przez konto `claude` ani przez czat.
#
#   python3 tools/gen_profile.py --name "iPad Franka" \
#       --doh-url "https://dns.nextdns.io/<ID>/iPad-Franek" --out profil/franek.mobileconfig
#   sudo tools/podpisz_profil.sh profil/franek.mobileconfig profil/franek-podpisany.mobileconfig
#
# Certyfikat Let's Encrypt zyje 90 dni. Liczy sie waznosc W CHWILI INSTALACJI
# na iPadzie - zainstalowany profil zostaje, ale plik podpisany dawno temu
# trzeba podpisac ponownie przed kolejna instalacja.
set -euo pipefail

WEJSCIE=${1:?uzycie: sudo $0 WEJSCIE.mobileconfig WYJSCIE.mobileconfig}
WYJSCIE=${2:?uzycie: sudo $0 WEJSCIE.mobileconfig WYJSCIE.mobileconfig}
SEKRET=${KIDWATCH_TLS_SECRET:-kidwatch-tls-cert}
NAMESPACE=${KIDWATCH_NAMESPACE:-default}
KUBECTL=${KUBECTL:-kubectl}

[ -f "$WEJSCIE" ] || { echo "brak pliku $WEJSCIE" >&2; exit 1; }
grep -q "<plist" "$WEJSCIE" || { echo "$WEJSCIE nie wyglada na profil (brak <plist>)" >&2; exit 1; }

umask 077
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

$KUBECTL get secret "$SEKRET" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TMP/cert.pem"
$KUBECTL get secret "$SEKRET" -n "$NAMESPACE" -o jsonpath='{.data.tls\.key}' | base64 -d > "$TMP/key.pem"
[ -s "$TMP/cert.pem" ] && [ -s "$TMP/key.pem" ] || { echo "Sekret $SEKRET bez tls.crt/tls.key" >&2; exit 1; }

# tls.crt to lisc + posrednie. -signer bierze pierwszy (lisc), -certfile
# doklada caly lancuch do podpisu - iPad musi go dostac, bo sam ma tylko
# korzenie.
openssl smime -sign -binary -nodetach -outform der \
    -signer "$TMP/cert.pem" -inkey "$TMP/key.pem" -certfile "$TMP/cert.pem" \
    -in "$WEJSCIE" -out "$WYJSCIE"

# Kontrola: podpis sie sprawdza (bez weryfikacji lancucha - tym zajmie sie
# iPad) i w srodku jest ten sam profil.
openssl smime -verify -noverify -inform der -in "$WYJSCIE" -out "$TMP/tresc" 2>/dev/null
cmp -s "$TMP/tresc" "$WEJSCIE" || { echo "podpisany plik nie zawiera profilu wejsciowego" >&2; exit 1; }

# Plik dla wlasciciela katalogu, nie dla roota (sudo).
if [ -n "${SUDO_USER:-}" ]; then
    chown "$SUDO_USER" "$WYJSCIE"
fi
chmod 0644 "$WYJSCIE"

echo "zapisano $WYJSCIE"
openssl x509 -in "$TMP/cert.pem" -noout -subject -enddate | sed 's/^/  certyfikat: /'
echo "Na iPadzie: usun stary profil, zainstaluj ten - ma byc \"Zweryfikowany\"."
