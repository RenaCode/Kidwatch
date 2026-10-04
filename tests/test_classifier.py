"""Testy klasyfikacji domen."""

from __future__ import annotations

import pytest

from kidwatch.classifier import UNKNOWN_LABEL, Classifier, normalize_domain
from kidwatch.models import Kind


# ================================================================ dopasowanie
@pytest.mark.parametrize(
    ("domain", "app"),
    [
        ("youtube.com", "YouTube"),
        ("www.youtube.com", "YouTube"),
        ("rr1---sn-abc.googlevideo.com", "YouTube"),
        ("www.youtubekids.com", "YouTube Kids"),
        ("ecsv3.roblox.com", "Roblox"),
        ("api.minecraft.net", "Minecraft"),
    ],
)
def test_sufiks_dopasowuje_domene_i_poddomeny(classifier, domain, app):
    verdict = classifier.classify(domain)
    assert verdict.kind is Kind.APP
    assert verdict.app == app


@pytest.mark.parametrize(
    "domain",
    ["gsp-ssl.ls.apple.com", "apple.com", "p50-content.icloud.com", "settings.crashlytics.com"],
)
def test_szum_jest_rozpoznawany(classifier, domain):
    assert classifier.classify(domain).kind is Kind.NOISE


@pytest.mark.parametrize("domain", ["jakas-strona.pl", "example.org", "cokolwiek.dev"])
def test_nieznane_domeny_sa_nieznane(classifier, domain):
    assert classifier.classify(domain).kind is Kind.UNKNOWN


def test_gwiazdka_z_kropka_znaczy_to_samo_co_goly_sufiks(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text('noise: []\napps:\n  "Cos":\n    - "*.przyklad.pl"\n', encoding="utf-8")
    c = Classifier(p)
    assert c.classify("a.b.przyklad.pl").app == "Cos"
    assert c.classify("przyklad.pl").app == "Cos"


def test_prefiks_rownosci_dopasowuje_tylko_dokladna_domene(classifier):
    assert classifier.classify("tylko.example.com").app == "Dokladnie ta"
    # Poddomena NIE wpada pod wzorzec z '='.
    assert classifier.classify("sub.tylko.example.com").kind is Kind.UNKNOWN


# ============================================================== pierwszenstwo
def test_szum_wygrywa_przy_identycznym_wzorcu(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text(
        'noise:\n  - sporne.pl\napps:\n  "Aplikacja":\n    - sporne.pl\n', encoding="utf-8"
    )
    c = Classifier(p)
    assert c.classify("sporne.pl").kind is Kind.NOISE
    assert c.classify("a.sporne.pl").kind is Kind.NOISE


def test_dluzszy_wzorzec_wygrywa_z_krotszym(classifier):
    """apple.com jest szumem, ale music.apple.com to konkretna aplikacja.

    Bez tej reguly kazda usluga Apple bylaby niewidoczna, bo apple.com pochlania
    wszystko."""
    assert classifier.classify("apple.com").kind is Kind.NOISE
    assert classifier.classify("gsp.apple.com").kind is Kind.NOISE
    assert classifier.classify("music.apple.com").app == "Muzyka Apple"
    assert classifier.classify("cdn.music.apple.com").app == "Muzyka Apple"


# ============================================================== normalizacja
@pytest.mark.parametrize(
    ("raw", "expected"),
    [("WWW.YouTube.COM.", "www.youtube.com"), ("  roblox.com  ", "roblox.com"), ("A.PL.", "a.pl")],
)
def test_normalizacja_domeny(raw, expected):
    assert normalize_domain(raw) == expected


def test_klasyfikacja_ignoruje_wielkosc_liter_i_kropke_koncowa(classifier):
    assert classifier.classify("WWW.YOUTUBE.COM.").app == "YouTube"


def test_pusta_domena_jest_nieznana(classifier):
    assert classifier.classify("").kind is Kind.UNKNOWN
    assert classifier.classify("   ").kind is Kind.UNKNOWN


# ==================================================================== etykieta
def test_etykieta_szumu_to_none(classifier):
    assert classifier.label("gsp-ssl.ls.apple.com") is None


def test_etykieta_nieznanego_to_przegladarka(classifier):
    assert classifier.label("jakas-strona.pl") == UNKNOWN_LABEL


# ================================================================ przeladowanie
def test_zmiana_pliku_jest_wychwytywana_po_mtime(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text('noise: []\napps:\n  "Stara":\n    - example.com\n', encoding="utf-8")
    c = Classifier(p, reload_check_seconds=0.0)
    assert c.classify("example.com").app == "Stara"

    p.write_text('noise: []\napps:\n  "Nowa":\n    - example.com\n', encoding="utf-8")
    import os  # noqa: PLC0415

    # mtime musi sie faktycznie roznic, inaczej test bada nic.
    st = p.stat()
    os.utime(p, (st.st_atime, st.st_mtime + 10))

    assert c.classify("example.com").app == "Nowa"


def test_zepsuty_yaml_nie_zabija_serwisu_i_zostawia_stara_mape(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text('noise: []\napps:\n  "Dobra":\n    - example.com\n', encoding="utf-8")
    c = Classifier(p, reload_check_seconds=0.0)
    assert c.classify("example.com").app == "Dobra"

    p.write_text("apps: [to nie jest: poprawny] yaml: ::", encoding="utf-8")
    import os  # noqa: PLC0415

    st = p.stat()
    os.utime(p, (st.st_atime, st.st_mtime + 10))

    # Stara mapa dalej dziala.
    assert c.classify("example.com").app == "Dobra"
    # I nie probujemy przeladowywac w kolko przy kazdym zapytaniu.
    assert c.classify("example.com").app == "Dobra"


# ========================================================= ruch wspoldzielony
def test_ruch_wspoldzielony_ma_wlasna_kategorie(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text(
        'noise:\n  - apple.com\nshared:\n  - cloudfront.net\napps:\n'
        '  "Gra":\n    - gameloft.com\n',
        encoding="utf-8",
    )
    c = Classifier(p)
    assert c.classify("d123.cloudfront.net").kind is Kind.AMBIGUOUS
    assert c.classify("asphalt.gameloft.com").app == "Gra"
    assert c.classify("gsp.apple.com").kind is Kind.NOISE


def test_ruch_wspoldzielony_nie_ma_nazwy_aplikacji(tmp_path):
    """Nie wolno mu nadac nazwy: CloudFront obsluguje pol App Store'a."""
    p = tmp_path / "m.yaml"
    p.write_text('noise: []\nshared:\n  - cloudfront.net\napps: {}\n', encoding="utf-8")
    assert Classifier(p).label("d1.cloudfront.net") is None


def test_szum_wygrywa_nad_wspoldzielonym_a_wspoldzielony_nad_aplikacja(tmp_path):
    """Przy identycznym wzorcu wygrywa kategoria, ktora NIE otworzy sesji."""
    p = tmp_path / "m.yaml"
    p.write_text(
        'noise:\n  - a.example\nshared:\n  - a.example\n  - b.example\n'
        'apps:\n  "X":\n    - b.example\n',
        encoding="utf-8",
    )
    c = Classifier(p)
    assert c.classify("a.example").kind is Kind.NOISE
    assert c.classify("b.example").kind is Kind.AMBIGUOUS


# ================================================== zwijanie do domeny czytelnej
@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("rr1---sn-abc.googlevideo.com", "googlevideo.com"),
        ("www.wykop.pl", "wykop.pl"),
        ("wykop.pl", "wykop.pl"),
        ("pl", "pl"),
        # Sufiksy dwuczlonowe: bez nich zwinelo by sie do bezuzytecznego "com.pl"
        ("a.b.firma.com.pl", "firma.com.pl"),
        ("forum.example.co.uk", "example.co.uk"),
        ("WWW.Example.COM.", "example.com"),
    ],
)
def test_zwijanie_domeny(host, expected):
    from kidwatch.classifier import registrable  # noqa: PLC0415

    assert registrable(host) == expected
