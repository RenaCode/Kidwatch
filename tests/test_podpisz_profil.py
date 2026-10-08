"""tools/podpisz_profil.sh: podpis profilu certyfikatem z Sekretu.

kubectl podmieniony atrapa (zmienna KUBECTL), certyfikat i klucz
samopodpisane - sprawdzamy, ze wychodzi DER CMS z profilem w srodku
i z certyfikatem podpisujacego, a klucz nie zostaje na dysku.
"""

from __future__ import annotations

import base64
import datetime
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

SKRYPT = Path(__file__).resolve().parents[1] / "tools" / "podpisz_profil.sh"
PROFIL = b'<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key>' \
         b"<string>Configuration</string></dict></plist>\n"

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="brak openssl")


def _sekret(tmp_path: Path) -> Path:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kidwatch.example")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    crt = base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)).decode()
    kpem = base64.b64encode(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode()
    atrapa = tmp_path / "kubectl"
    atrapa.write_text(
        "#!/bin/sh\n"
        f'case "$*" in *tls\\\\.crt*) printf %s "{crt}";;\n'
        f'  *tls\\\\.key*) printf %s "{kpem}";; esac\n')
    atrapa.chmod(0o755)
    return atrapa


def test_podpisany_profil_zawiera_tresc_i_certyfikat(tmp_path):
    wej, wyj = tmp_path / "p.mobileconfig", tmp_path / "p-podpisany.mobileconfig"
    wej.write_bytes(PROFIL)
    env = {**os.environ, "KUBECTL": str(_sekret(tmp_path)), "TMPDIR": str(tmp_path)}
    r = subprocess.run(["bash", str(SKRYPT), str(wej), str(wyj)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    dane = wyj.read_bytes()
    assert dane[:1] == b"\x30"                          # DER, nie PEM
    assert PROFIL in dane                               # -nodetach: profil w srodku
    certy = pkcs7.load_der_pkcs7_certificates(dane)
    assert certy[0].subject.rfc4514_string() == "CN=kidwatch.example"
    assert "kidwatch.example" in r.stdout
    # Katalog tymczasowy z kluczem sprzatniety.
    assert not [p for p in tmp_path.iterdir() if p.is_dir()]


def test_odmawia_pliku_ktory_nie_jest_profilem(tmp_path):
    wej = tmp_path / "x.txt"
    wej.write_text("nie profil")
    r = subprocess.run(["bash", str(SKRYPT), str(wej), str(tmp_path / "y")],
                       env={**os.environ, "KUBECTL": "false"}, capture_output=True, text=True)
    assert r.returncode != 0 and "nie wyglada na profil" in r.stderr
