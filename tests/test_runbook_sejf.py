"""Runbook sejf-domow.md (renacode-infra: docs/projekty/kidwatch/sejf-domow.md)
wklejany do PRAWDZIWEGO interaktywnego zsh.

Właściciel wkleja bloki do zsh, domyślnie bez `interactivecomments`: `#`
nie jest wtedy komentarzem, a polecenie w odwrotnych apostrofach
w „komentarzu” się wykonuje. Test bierze KAŻDY blok ```sh z runbooka
i wkleja go (bracketed paste, jak terminal) do `zsh -f -i` na pty,
z atrapami kubectl/pbcopy/openssl/uv — ZAWSZE po bloku definicji, tak
jak właściciel, więc z `setopt interactivecomments` z tego bloku.
Komentarzy w blokach pilnuje dlatego osobny test statyczny
(`test_runbook_bez_komentarzy_w_blokach`). Sprawdza:

  * brak błędów powłoki (składnia, „command not found”);
  * brak niezamierzonych wywołań `kp` (tylko tam, gdzie blok go woła);
  * schowek: wrzut -> czekanie (`read`) -> czyszczenie, a Sekret dopiero
    po zapisaniu klucza w menedżerze;
  * `kp && …`: dalsze polecenie tylko po POTWIERDZONO (kod 0);
  * w bashu (`/bin/bash`: bez bracketed paste w 3.2, `read -rs '?…'` to
    błąd) bloki ze schowkiem NIC nie robią, a `kp && …` nie wykonuje
    dalszego polecenia.

Bez sieci i bez prawdziwego kubectl/schowka. Bez zsh: w CI błąd, lokalnie
pominięcie (jak test kp w test_domy_e2_uwagi.py). Runbook jest w prywatnym
repo: bez KIDWATCH_DOCS testy są pomijane (conftest.plik_dokumentacji)."""

from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import plik_dokumentacji


def _runbook() -> str:
    return plik_dokumentacji("sejf-domow.md").read_text()


ZNACZNIK = "@@P@@"
KLUCZ = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="

ATRAPY = {
    "kubectl": r'''#!/bin/sh
echo "kubectl $*" >> "$ATRAPY_LOG"
case "$*" in
  *klucze-potwierdz*) read -r linia; echo "kp-stdin:${#linia}" >> "$ATRAPY_LOG"
                      [ -n "$linia" ] || exit 2
                      exit "${KP_RC:-0}";;
  *"--patch-file /dev/stdin"*) cat >/dev/null;;
  *" get pod "*) echo pod/kidwatch-atrapa;;
  *" cp "*) for a; do ostatni=$a; done; : > "$ostatni";;
  *" logs "*) echo "Dom 1: konfiguracja z bazy; KIDWATCH_DOM_1_ZRODLO";;
esac
exit 0
''',
    "pbcopy": r'''#!/bin/sh
dane=$(cat)
if [ -z "$dane" ]; then echo pbcopy-czysc >> "$ATRAPY_LOG"
else echo pbcopy-wrzut >> "$ATRAPY_LOG"; fi
''',
    "openssl": f"#!/bin/sh\necho {KLUCZ}\n",
    "uv": '#!/bin/sh\necho "uv $*" >> "$ATRAPY_LOG"\n',
}


def bloki(tekst: str) -> list[tuple[int, str]]:
    """(numer linii, treść) każdego bloku ```sh — z wcięciem listy usuniętym,
    tak jak widać go po wyrenderowaniu."""
    out, linie = [], tekst.splitlines()
    i = 0
    while i < len(linie):
        m = re.fullmatch(r"(\s*)```sh\s*", linie[i])
        if not m:
            i += 1
            continue
        wciecie, start, tresc = m.group(1), i + 1, []
        i += 1
        while not re.fullmatch(r"\s*```\s*", linie[i]):
            tresc.append(linie[i][len(wciecie):] if linie[i].startswith(wciecie)
                         else linie[i])
            i += 1
        out.append((start, "\n".join(tresc)))
        i += 1
    return out


def oczekiwane_kp(blok: str) -> int:
    """Ile razy blok WOŁA kp (nie definiuje)."""
    return len(re.findall(r"(?m)(?:^|&&|;|\|\|)\s*kp\b(?!\s*\(\))", blok))


class Zsh:
    def __init__(self, katalog: Path, env: dict[str, str],
                 argv: list[str] | None = None) -> None:
        # pty tworzy osobny, jednowątkowy proces (pty.spawn): fork w procesie
        # pytesta (wątki panelu z innych testów) grozi zakleszczeniem dziecka.
        # pty.spawn przekazuje nasze potoki do terminala zsh i z powrotem.
        self.proc = subprocess.Popen(
            [sys.executable, "-c", "import pty, sys; pty.spawn(sys.argv[1:])",
             *(argv or [env["ZSH"], "-f", "-i"])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=katalog, env=env, bufsize=0)
        self.fd = self.proc.stdout.fileno()
        self.bufor = ""
        self._czekaj_cisza(1.0)
        # Znacznik zachęty składany z \x40 — wpisany tekst go nie zawiera.
        self._wyslij("PS1=$'\\x40\\x40P\\x40\\x40 '; PS2=''\r")
        self.do_znacznika(5)

    def _wyslij(self, tekst: str) -> None:
        self.proc.stdin.write(tekst.encode())

    def _czytaj(self, limit: float) -> bool:
        gotowe, _, _ = select.select([self.fd], [], [], limit)
        if not gotowe:
            return False
        try:
            dane = os.read(self.fd, 65536)
        except OSError:
            return False
        self.bufor += dane.decode(errors="replace")
        return True

    def _czekaj_cisza(self, cisza: float) -> None:
        while self._czytaj(cisza):
            pass

    def do_znacznika(self, limit: float) -> bool:
        koniec = time.monotonic() + limit
        start = len(self.bufor)
        while time.monotonic() < koniec:
            if ZNACZNIK in self.bufor[start:]:
                return True
            self._czytaj(0.1)
        return False

    def wklej(self, blok: str, przy_read, limit_read: int = 6) -> str:
        """Bracketed paste + Enter. Gdy zsh czeka na `read` (cisza bez
        znacznika zachęty) — `przy_read(n)` i odpowiedź z klucza."""
        start = len(self.bufor)
        self._wyslij("\x1b[200~" + blok + "\x1b[201~")
        self._czekaj_cisza(0.3)
        poczatek_wykonania = len(self.bufor)
        self._wyslij("\r")
        for n in range(limit_read + 1):
            koniec = time.monotonic() + 0.6
            while time.monotonic() < koniec:
                if ZNACZNIK in self.bufor[poczatek_wykonania:]:
                    return self.bufor[start:]
                if self._czytaj(0.1):
                    koniec = time.monotonic() + 0.6
            if n == limit_read:
                break
            przy_read(n)
            self._wyslij(KLUCZ + "\r")
            poczatek_wykonania = len(self.bufor)
        raise AssertionError(f"blok nie skończył się: {self.bufor[start:][-500:]!r}")

    def wpisz(self, blok: str, proby: int = 6) -> str:
        """Bez bracketed paste (bash 3.2): linie jak z terminala, potem
        znacznik końca złożony z dwóch połówek (echo wpisu go nie zawiera).
        `read` w bashu czeka na linię nawet z błędną nazwą zmiennej — wtedy
        połyka znacznik, więc wysyłamy go ponownie."""
        start = len(self.bufor)
        self._wyslij(blok.replace("\n", "\r") + "\r")
        for _ in range(proby):
            # Po ciszy: readline basha potrafi skasować znaki wpisane
            # z wyprzedzeniem, gdy przestawia terminal.
            self._czekaj_cisza(0.8)
            self._wyslij("printf '%s%s\\n' '@@KON' 'IEC@@'\r")
            koniec = time.monotonic() + 2
            while time.monotonic() < koniec:
                if "@@KONIEC@@" in self.bufor[start:]:
                    return self.bufor[start:]
                self._czytaj(0.1)
        raise AssertionError(f"bash nie skończył bloku: {self.bufor[start:][-500:]!r}")

    def zamknij(self) -> None:
        self.proc.kill()
        self.proc.wait(timeout=10)
        self.proc.stdin.close()
        self.proc.stdout.close()


@pytest.fixture
def srodowisko(tmp_path):
    zsh = shutil.which("zsh")
    if zsh is None:
        if os.environ.get("CI"):
            pytest.fail("brak zsh — workflow CI musi go instalowac (apt-get install zsh)")
        pytest.skip("brak zsh")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nazwa, tresc in ATRAPY.items():
        (bin_ / nazwa).write_text(tresc)
        (bin_ / nazwa).chmod(0o755)
    return {"tmp": tmp_path, "bin": bin_, "zsh": zsh}


def _uruchom(srodowisko, blok: str, *, kp_rc: int = 0, przy_read=None):
    log = srodowisko["tmp"] / f"atrapy-{time.monotonic_ns()}.log"
    log.write_text("")
    (srodowisko["tmp"] / "kopia-panel-auth.db").write_text("")
    env = {"PATH": f"{srodowisko['bin']}:/usr/bin:/bin", "HOME": str(srodowisko["tmp"]),
           "TERM": "xterm", "ATRAPY_LOG": str(log), "KP_RC": str(kp_rc),
           "ZSH": srodowisko["zsh"], "LANG": "C.UTF-8"}
    definicje = bloki(_runbook())[0][1]
    sesja = Zsh(srodowisko["tmp"], env)
    try:
        wyjscie = sesja.wklej(definicje, lambda n: None, limit_read=0)
        wyjscie += sesja.wklej(blok, (lambda n: przy_read(n, log.read_text()))
                               if przy_read else (lambda n: None))
    finally:
        sesja.zamknij()
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", wyjscie), log.read_text().splitlines()


def _uruchom_bash(srodowisko, blok: str, *, kp_rc: int = 0):
    bash = "/bin/bash" if Path("/bin/bash").exists() else shutil.which("bash")
    log = srodowisko["tmp"] / f"atrapy-bash-{time.monotonic_ns()}.log"
    log.write_text("")
    env = {"PATH": f"{srodowisko['bin']}:/usr/bin:/bin", "HOME": str(srodowisko["tmp"]),
           "TERM": "xterm", "ATRAPY_LOG": str(log), "KP_RC": str(kp_rc),
           "ZSH": srodowisko["zsh"], "LANG": "C.UTF-8"}
    sesja = Zsh(srodowisko["tmp"], env, [bash, "--norc", "--noprofile", "-i"])
    try:
        wyjscie = sesja.wpisz(bloki(_runbook())[0][1])
        wyjscie += sesja.wpisz(blok)
    finally:
        sesja.zamknij()
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", wyjscie), log.read_text().splitlines()


def test_bloki_ze_schowkiem_w_bashu_nic_nie_robia(srodowisko):
    """W bashu `read -rs '?…'` nie czeka (błąd), a bash 3.2 nie ma bracketed
    paste — blok musi to wykryć i nie wrzucać klucza do schowka ani do
    Sekretu."""
    ze_schowkiem = [(n, b) for n, b in bloki(_runbook()) if "| pbcopy" in b]
    assert len(ze_schowkiem) == 2
    for linia, blok in ze_schowkiem:
        wyjscie, log = _uruchom_bash(srodowisko, blok)
        assert "tylko w zsh" in wyjscie, (linia, wyjscie[-400:])
        assert not [w for w in log if w.startswith(("pbcopy", "kubectl"))], (linia, log)


def test_kp_and_w_bashu_nie_wykonuje_dalszego(srodowisko):
    for linia, blok in [(n, b) for n, b in bloki(_runbook())
                        if re.search(r"(?m)^kp &&", b)]:
        polecenie = re.search(r"(?m)^kp && kubectl -n default (\w+)", blok).group(1)
        _, log = _uruchom_bash(srodowisko, blok, kp_rc=0)
        assert not [w for w in log if w.startswith(f"kubectl -n default {polecenie}")], (
            linia, log)


def _bez_bledow_powloki(wyjscie: str, gdzie: str) -> None:
    for wzorzec in ("zsh:", "command not found", "parse error", "bad pattern",
                    "no such file"):
        assert wzorzec not in wyjscie.lower(), f"{gdzie}: {wzorzec!r} w {wyjscie[-600:]!r}"


def test_kazdy_blok_runbooka_w_interaktywnym_zsh(srodowisko):
    wszystkie = bloki(_runbook())
    assert len(wszystkie) >= 10
    for linia, blok in wszystkie:
        gdzie = f"sejf-domow.md:{linia}"
        stany_przy_read: list[list[str]] = []
        wyjscie, log = _uruchom(srodowisko, blok,
                                przy_read=lambda n, tekst, s=stany_przy_read: s.append(
                                    tekst.splitlines()))
        _bez_bledow_powloki(wyjscie, gdzie)
        wywolania_kp = [w for w in log if "klucze-potwierdz" in w]
        assert len(wywolania_kp) == oczekiwane_kp(blok), (gdzie, log)
        if "| pbcopy" in blok:
            # Pierwsze czekanie: klucz w schowku, schowek jeszcze nie wyczyszczony,
            # Sekret jeszcze nie zmieniony — właściciel ma czas zapisać klucz.
            assert stany_przy_read, f"{gdzie}: brak czekania (read) po wrzuceniu do schowka"
            pierwszy = stany_przy_read[0]
            assert "pbcopy-wrzut" in pierwszy, gdzie
            assert "pbcopy-czysc" not in pierwszy, f"{gdzie}: schowek czyszczony przed read"
            assert not any(w.startswith("kubectl -n default patch") for w in pierwszy), gdzie
            assert log.index("pbcopy-czysc") > log.index("pbcopy-wrzut"), gdzie


def test_kp_and_tylko_po_potwierdzeniu(srodowisko):
    z_and = [(n, b) for n, b in bloki(_runbook()) if re.search(r"(?m)^kp &&", b)]
    assert len(z_and) >= 2  # przełączenie Domu 1 (restart) i rotacja (remove)
    for linia, blok in z_and:
        m = re.search(r"(?m)^kp && kubectl -n default (\w+)", blok)
        assert m, f"sejf-domow.md:{linia}: `kp && …` nie jako polecenie"
        polecenie = m.group(1)
        for kod, ma_byc in ((1, False), (0, True)):
            wyjscie, log = _uruchom(srodowisko, blok, kp_rc=kod)
            _bez_bledow_powloki(wyjscie, f"sejf-domow.md:{linia}")
            i_kp = next(i for i, w in enumerate(log) if "klucze-potwierdz" in w)
            po = [w for w in log[i_kp + 1:] if w.startswith(f"kubectl -n default {polecenie}")]
            assert bool(po) is ma_byc, (linia, kod, log)


def test_runbook_bez_komentarzy_w_blokach():
    """Statycznie: żadnego `#`-komentarza w bloku (poza cudzysłowem/JSON)."""
    for linia, blok in bloki(_runbook()):
        for wiersz in blok.splitlines():
            bez_cudzyslowow = re.sub(r"'[^']*'|\"[^\"]*\"", "", wiersz)
            assert not re.search(r"(^|\s)#", bez_cudzyslowow), (linia, wiersz)
