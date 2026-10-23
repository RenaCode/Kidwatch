"""Konfiguracja domu z bazy panelu: HomeConfig <-> tabele (etap E2).

Projekt: renacode-infra: docs/projekty/kidwatch/architektura-domy.md §2.5, §3, §6 p. 4. Runbook:
renacode-infra: docs/projekty/kidwatch/sejf-domow.md.

  * `plan_z_home` — HomeConfig (dzis: Dom 1 z config.yaml) + jego sekrety
    -> PlanDomu: `domy.ustawienia`, `dzieci`, `urzadzenia`, `integracje`.
  * `home_z_danych` — odwrotnie: wiersze z bazy + odszyfrowane sekrety ->
    HomeConfig walidowany tymi samymi walidatorami co config.yaml.
  * `importuj` — `kidwatch dom-importuj`: zapis planu, odczyt z powrotem,
    porownanie z YAML pole w pole (i sekret w sekret) w JEDNEJ transakcji;
    roznica albo `--podglad` = ROLLBACK.
  * `zbuduj_dom` — srodowisko domu w trybie `baza`: HomeConfig + dostawca
    sekretow + straznik sieci + pliki z sekretow w pamieci poda.

Zaden komunikat ani raport nie zawiera wartosci sekretu (tylko maski).
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from . import config as cfgmod
from .config import KONTEKST_Z_BAZY, SEKRETY_ZE_SRODOWISKA, HomeConfig
from .devicekind import ALIASY
from .domy import (
    POLA_SEKRETOW,
    ZRODLO_BAZA,
    DaneDomu,
    PlanDomu,
    RejestrDomow,
    SekretyDomu,
    _audyt,
    dane_domu_conn,
    katalog_sekretow_domu,
    sekrety_domu_conn,
    zapisz_dane_domu_conn,
)
from .sejf import Sejf, SejfError, maska
from .straznik import HOSTY_API, OdmowaSieci, Straznik, adres_literalny, rozwiaz_systemowo

#: Pola HomeConfig niesione przez integracje albo kolumny — reszta idzie
#: do `domy.ustawienia` (engine, watchdog, device_read, store, game_time i
#: wszystko, co dojdzie pozniej).
_POZA_USTAWIENIAMI = {"timezone", "source", "devices", "notifiers", "tv", "unifi", "mdm"}
#: Kolumny `urzadzenia` <- pola DeviceConfig; reszta pol do `ustawienia`.
_KOLUMNY_URZADZENIA = {
    "display_name": "nazwa", "child": "dziecko", "kind": "rodzaj", "source_ids": "source_ids",
    "nextdns_profile": "nextdns_profile", "unifi_mac": "unifi_mac", "unifi_ip": "unifi_ip",
    "udid": "udid", "host": "host",
}
#: Port lockdown iPada (pymobiledevice3 po TCP).
PORT_LOCKDOWN = 62078
_ADB = "<katalog klucza ADB>"


# ===================================================================== plan
def _bez(d: dict, *klucze: str) -> dict:
    return {k: v for k, v in d.items() if k not in klucze}


def plan_z_home(home: HomeConfig, sekrety: Mapping[str, Mapping[str, str]]) -> PlanDomu:
    """HomeConfig -> wiersze. `sekrety`: typ -> {pole: wartosc} (patrz
    `sekrety_z_yaml`). Dla integracji, ktorych dom nie ma, sekrety odpadaja."""
    d = home.model_dump(mode="json")
    ustawienia = {k: v for k, v in d.items() if k not in _POZA_USTAWIENIAMI}
    integracje: dict[str, tuple[bool, dict]] = {}
    for typ in ("nextdns", "adguard"):
        if d["source"].get(typ) is not None:
            integracje[typ] = (d["source"]["kind"] == typ, d["source"][typ])
    for typ in ("ntfy", "homeassistant"):
        sekcja = d["notifiers"].get(typ)
        if sekcja is not None:
            integracje[typ] = (bool(sekcja["enabled"]), _bez(sekcja, "enabled", "topic"))
    integracje["tv"] = (bool(d["tv"]["enabled"]), _bez(d["tv"], "enabled", "adb_key_dir"))
    integracje["unifi"] = (bool(d["unifi"]["enabled"]), _bez(d["unifi"], "enabled"))
    integracje["mdm"] = (bool(d["mdm"]["enabled"]), _bez(d["mdm"], "enabled"))

    dzieci = list(dict.fromkeys(dev["child"] for dev in d["devices"]))
    urzadzenia = []
    for dev in d["devices"]:
        wiersz = {kol: dev.get(pole) for pole, kol in _KOLUMNY_URZADZENIA.items()}
        wiersz["ustawienia"] = {k: v for k, v in dev.items() if k not in _KOLUMNY_URZADZENIA}
        urzadzenia.append(wiersz)
    if home.tv.enabled:
        # Telewizor tez nalezy do domu (§2.4); jego ustawienia sa w integracji `tv`.
        urzadzenia.append({"nazwa": home.tv.name, "dziecko": None, "rodzaj": "tv",
                           "source_ids": list(home.tv.nextdns_ids), "host": home.tv.host,
                           "unifi_mac": home.tv.unifi_mac, "ustawienia": {}})
    czyste = {typ: {p: v for p, v in pola.items() if v}
              for typ, pola in sekrety.items() if typ in integracje}
    return PlanDomu(strefa=home.timezone, ustawienia=ustawienia, dzieci=dzieci,
                    urzadzenia=urzadzenia, integracje=integracje,
                    sekrety={t: p for t, p in czyste.items() if p})


def _czytaj(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def sekrety_z_yaml(home: HomeConfig, katalog_domu_1: Path,
                   env: Mapping[str, str] | None = None) -> dict[str, dict[str, str]]:
    """Sekrety Domu 1 tam, gdzie leza w trybie `yaml`: zmienne srodowiskowe
    (SEKRETY_ZE_SRODOWISKA), temat ntfy (z config.yaml albo NTFY_TOPIC — juz
    w HomeConfig), klucz ADB z `tv.adb_key_dir`, token aplikacji TV
    z `<katalog bazy>/tv-app/token`."""
    env = os.environ if env is None else env
    out: dict[str, dict[str, str]] = {}
    for (typ, pole), nazwa in SEKRETY_ZE_SRODOWISKA.items():
        wartosc = (env.get(nazwa) or "").strip()
        if wartosc:
            out.setdefault(typ, {})[pole] = wartosc
    if home.notifiers.ntfy is not None and home.notifiers.ntfy.topic:
        out.setdefault("ntfy", {})["topic"] = home.notifiers.ntfy.topic
    adb = Path(home.tv.adb_key_dir).expanduser()
    for pole, plik in (("adb_key", "adbkey"), ("adb_key_pub", "adbkey.pub")):
        wartosc = _czytaj(adb / plik)
        if wartosc:
            out.setdefault("tv", {})[pole] = wartosc
    token = _czytaj(katalog_domu_1 / "tv-app" / "token")
    if token:
        out.setdefault("tv", {})["app_token"] = token
    return out


# ================================================================ HomeConfig
def home_z_danych(dane: DaneDomu, sekrety: SekretyDomu, *,
                  katalog_plikow: Path | str) -> HomeConfig:
    """Wiersze domu + sekrety -> HomeConfig (bez siegania do env).
    `katalog_plikow`: tam srodowisko domu zapisuje klucz ADB."""
    integ = {i.typ: i for i in dane.integracje}
    d: dict[str, Any] = json.loads(json.dumps(dane.dom.ustawienia))
    d["timezone"] = dane.dom.strefa
    zrodla = [t for t in ("nextdns", "adguard") if t in integ and integ[t].wlaczona]
    if len(zrodla) != 1:
        raise ValueError(f"dom {dane.dom.id}: musi byc wlaczone dokladnie jedno zrodlo DNS "
                         f"(nextdns albo adguard), jest: {zrodla or 'zadne'}")
    d["source"] = {"kind": zrodla[0], **{t: dict(integ[t].ustawienia)
                                         for t in ("nextdns", "adguard") if t in integ}}
    d["devices"] = []
    for u in dane.urzadzenia:
        if u["rodzaj"] == "tv":
            continue
        dev = {pole: u[kol] for pole, kol in _KOLUMNY_URZADZENIA.items()}
        dev["kind"] = ALIASY.get(u["rodzaj"], u["rodzaj"])
        dev.update(u["ustawienia"])
        d["devices"].append(dev)
    notifiers: dict[str, Any] = {}
    if "ntfy" in integ:
        notifiers["ntfy"] = {**integ["ntfy"].ustawienia, "enabled": integ["ntfy"].wlaczona,
                             "topic": sekrety.get("ntfy", "topic") or ""}
    if "homeassistant" in integ:
        notifiers["homeassistant"] = {**integ["homeassistant"].ustawienia,
                                      "enabled": integ["homeassistant"].wlaczona}
    d["notifiers"] = notifiers
    for typ in ("tv", "unifi", "mdm"):
        if typ in integ:
            d[typ] = {**integ[typ].ustawienia, "enabled": integ[typ].wlaczona}
    # Zawsze katalog domu: domyslne /adb to klucz ADB Domu 1 z Sekretu k8s.
    d.setdefault("tv", {})["adb_key_dir"] = str(Path(katalog_plikow) / "adb")
    try:
        return HomeConfig.model_validate(d, context=KONTEKST_Z_BAZY)
    except ValidationError as exc:
        raise ValueError(f"dom {dane.dom.id}: konfiguracja w bazie niepoprawna: "
                         f"{_bledy(exc)}") from exc


def _bledy(exc: ValidationError) -> str:
    """Bledy walidacji BEZ wartosci wejscia (moglby tam byc temat ntfy)."""
    return "; ".join(f"{'.'.join(str(x) for x in e['loc']) or '-'}: {e['msg']}"
                     for e in exc.errors())


def sprawdz_hosty_api(home: HomeConfig, straznik: Straznik) -> None:
    """nextdns.base_url i ntfy.server tylko z listy hostow (§3.6)."""
    adresy = []
    if home.source.nextdns is not None:
        adresy.append(("nextdns", home.source.nextdns.base_url))
    if home.notifiers.ntfy is not None and home.notifiers.ntfy.enabled:
        adresy.append(("ntfy", home.notifiers.ntfy.server))
    for typ, url in adresy:
        host = (urlsplit(url).hostname or "").lower()
        if host not in HOSTY_API[typ] | straznik.hosty:
            raise OdmowaSieci(f"dom {straznik.dom_id}: {typ}: host {host} spoza listy "
                              f"dozwolonych (kidwatch dom-sieci --host)")


def _zapisz_plik(path: Path, tresc: str | None) -> None:
    if tresc is None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(tresc if tresc.endswith("\n") else tresc + "\n")
    os.chmod(path, 0o600)


def materializuj_pliki(sekrety: SekretyDomu, katalog: Path) -> None:
    """Klucz ADB i token aplikacji TV do plikow 0600 w pamieci poda
    (emptyDir medium: Memory, §3.1). Usuniety sekret = usuniety plik."""
    katalog.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(katalog, 0o700)
    _zapisz_plik(katalog / "adb" / "adbkey", sekrety.get("tv", "adb_key"))
    _zapisz_plik(katalog / "adb" / "adbkey.pub", sekrety.get("tv", "adb_key_pub"))
    _zapisz_plik(katalog / "tv-app" / "token", sekrety.get("tv", "app_token"))


def zbuduj_dom(rejestr: RejestrDomow, dom_id: int, sejf: Sejf, *,
               resolver: Callable[[str, int], list[str]] | None = None,
               katalog: str | Path | None = None, materializuj: bool = True) -> HomeConfig:
    """HomeConfig domu w trybie `baza`, gotowy dla build_home_runtime:
    dostawca sekretow, straznik sieci, pliki z sekretow w pamieci poda.
    Kazdy blad (brak KEK, zly szyfrogram, adres spoza sieci) = wyjatek:
    dom nie startuje z polowa konfiguracji."""
    return _home_domu(rejestr.dane_domu(dom_id), rejestr.sekrety_domu(dom_id, sejf),
                      resolver=resolver, katalog=katalog, materializuj=materializuj)


def _home_domu(dane: DaneDomu, sekrety: SekretyDomu, *,
               resolver: Callable[[str, int], list[str]] | None,
               katalog: str | Path | None, materializuj: bool) -> HomeConfig:
    dom_id = dane.dom.id
    kat = katalog_sekretow_domu(dom_id, katalog)
    home = home_z_danych(dane, sekrety, katalog_plikow=kat)
    straznik = Straznik(dom_id, dane.dom.dozwolone_sieci, dane.dom.dozwolone_hosty,
                        resolver=resolver)
    sprawdz_hosty_api(home, straznik)
    if materializuj:
        materializuj_pliki(sekrety, kat)
    return home.ustaw_srodowisko(sekrety, straznik)


def zbuduj_dom_z_kopii(rejestr: RejestrDomow, dom_id: int, sejf: Sejf, *,
                       resolver: Callable[[str, int], list[str]] | None = None,
                       katalog: str | Path | None = None,
                       materializuj: bool = False) -> tuple[int, HomeConfig] | None:
    """Ostatnia konfiguracja, na ktorej dom WSTAL (RejestrDomow.zapamietaj_dobra):
    (wersja, HomeConfig) albo None, gdy kopii nie ma. Te same kontrole co
    `zbuduj_dom` plus wymagane sekrety."""
    kopia = rejestr.kopia_domu(dom_id, sejf)
    if kopia is None:
        return None
    wersja, dane, sekrety = kopia
    home = _home_domu(dane, sekrety, resolver=resolver, katalog=katalog,
                      materializuj=materializuj)
    sprawdz_wymagane_sekrety(home)
    return wersja, home


def sprawdz_wymagane_sekrety(home: HomeConfig) -> None:
    """Sekrety, bez ktorych dom nie wystartuje (zrodlo DNS, wlaczony
    webhook HA) — MissingSecretError z nazwa pola, bez wartosci. Temat ntfy
    sprawdza juz model (NtfyConfig)."""
    if home.source.kind == "nextdns" and home.source.nextdns is not None:
        home.source.nextdns.api_key()
    if home.source.kind == "adguard" and home.source.adguard is not None:
        home.source.adguard.password()
    ha = home.notifiers.homeassistant
    if ha is not None and ha.enabled:
        ha.webhook_id()


#: Sekret, bez ktorego zrodlo DNS nie ruszy.
SEKRET_ZRODLA = {"nextdns": "api_key", "adguard": "password"}


def czego_brakuje(dane: DaneDomu) -> str | None:
    """Dom NIESKONFIGUROWANY — normalny stan po `dom-dodaj`, zanim ktos wpisze
    integracje w panelu: brak wlaczonego zrodla DNS, brak jego sekretu albo
    brak urzadzenia. Zwraca, czego brakuje, albo None (dom ma wstac, a blad
    startu to awaria). Tylko obecnosc wierszy i pol — bez sejfu i sieci;
    zle wartosci (walidacja, straznik, szyfrogram) to blad, nie „czeka”."""
    integ = {i.typ: i for i in dane.integracje}
    zrodla = [t for t in SEKRET_ZRODLA if t in integ and integ[t].wlaczona]
    if not zrodla:
        return "brak wlaczonego zrodla DNS (integracja NextDNS)"
    if len(zrodla) == 1 and SEKRET_ZRODLA[zrodla[0]] not in integ[zrodla[0]].sekrety_pola:
        return f"brak sekretu {zrodla[0]}.{SEKRET_ZRODLA[zrodla[0]]}"
    if not [u for u in dane.urzadzenia if u["rodzaj"] != "tv"]:
        return "brak urzadzenia dziecka"
    return None


def blad_startu_conn(conn, dom_id: int, sejf: Sejf) -> str | None:
    """Dlaczego dom NIE wystartowalby na konfiguracji widocznej na `conn`
    (takze niezatwierdzonej — panel pyta w transakcji zapisu), albo None.
    To samo co `zbuduj_dom` bez sieci i bez plikow: model, szyfrogramy,
    hosty API, wymagane sekrety. Komunikat bez wartosci sekretow."""
    try:
        dane = dane_domu_conn(conn, dom_id)
        sekrety = sekrety_domu_conn(conn, dom_id, sejf)
        home = home_z_danych(dane, sekrety, katalog_plikow=_ADB)
        straznik = Straznik(dom_id, dane.dom.dozwolone_sieci, dane.dom.dozwolone_hosty)
        sprawdz_hosty_api(home, straznik)
        home.ustaw_srodowisko(sekrety, straznik)
        sprawdz_wymagane_sekrety(home)
    except (SejfError, OdmowaSieci, ValueError, LookupError, cfgmod.MissingSecretError) as exc:
        return str(exc)
    return None


# ================================================================ walidacja
#: Model konfiguracji kazdej integracji — te same walidatory co config.yaml
#: (panel buduje z nich tez formularz: panel_integracje.pola_ustawien).
MODELE_INTEGRACJI: dict[str, type[cfgmod._ZSekretami]] = {
    "nextdns": cfgmod.NextDnsConfig, "adguard": cfgmod.AdGuardConfig,
    "unifi": cfgmod.UnifiConfig, "tv": cfgmod.TvConfig, "mdm": cfgmod.HomeMdmConfig,
    "ntfy": cfgmod.NtfyConfig, "homeassistant": cfgmod.HomeAssistantConfig,
}


def waliduj_integracje(typ: str, ustawienia: dict, straznik: Straznik, *,
                       wlaczona: bool = True) -> None:
    """Zapis integracji z panelu: model konfiguracji (te same walidatory co
    config.yaml) i adresy przez straznika domu (§3.6). ValueError z opisem."""
    if typ not in POLA_SEKRETOW:
        raise ValueError(f"nieznany typ integracji {typ!r}")
    jawne_sekrety = sorted(set(ustawienia) & set(POLA_SEKRETOW[typ]))
    if jawne_sekrety:
        raise ValueError(f"integracja {typ}: {jawne_sekrety} to sekrety — nie w ustawieniach")
    modele = MODELE_INTEGRACJI
    dane = dict(ustawienia)
    if typ in ("unifi", "tv", "mdm", "homeassistant"):
        dane["enabled"] = wlaczona
    if typ == "ntfy":
        dane["enabled"] = False  # temat to sekret; jego obecnosc sprawdza start domu
    try:
        model = modele[typ].model_validate(dane, context=KONTEKST_Z_BAZY)
    except ValidationError as exc:
        raise ValueError(f"integracja {typ}: {_bledy(exc)}") from exc
    if not wlaczona:
        return
    try:
        if typ == "nextdns":
            straznik.sprawdz_url(model.base_url, pole="nextdns.base_url", schematy=("https",),
                                 typ_api="nextdns")
        elif typ == "ntfy":
            straznik.sprawdz_url(model.server, pole="ntfy.server", schematy=("https",),
                                 typ_api="ntfy")
        elif typ == "adguard":
            straznik.sprawdz_url(model.base_url, pole="adguard.base_url")
        elif typ == "homeassistant":
            straznik.sprawdz_url(model.base_url, pole="homeassistant.base_url")
        elif typ == "unifi":
            if not model.cert_sha256:
                raise ValueError("unifi.cert_sha256 jest obowiazkowy — bez przypietego "
                                 "certyfikatu klucz API nie zostanie wyslany")
            straznik.sprawdz_url(model.url, pole="unifi.url", schematy=("https",))
        elif typ == "tv":
            straznik.sprawdz_host(model.host, model.port, pole="tv.host")
    except OdmowaSieci as exc:
        raise ValueError(str(exc)) from exc


# =================================================================== import
def _adresy(home: HomeConfig) -> list[tuple[str, str, int]]:
    """(pole, host, port) — adresy wpisywane recznie, z ktorymi laczy sie dom."""
    out: list[tuple[str, str, int]] = []

    def url(pole: str, adres: str) -> None:
        cz = urlsplit(adres)
        if cz.hostname:
            out.append((pole, cz.hostname, cz.port or (443 if cz.scheme == "https" else 80)))

    if home.tv.enabled and home.tv.host:
        out.append(("tv.host", home.tv.host, home.tv.port))
    if home.unifi.enabled:
        url("unifi.url", home.unifi.url)
    ha = home.notifiers.homeassistant
    if ha is not None and ha.enabled:
        url("homeassistant.base_url", ha.base_url)
    if home.source.kind == "adguard" and home.source.adguard is not None:
        url("adguard.base_url", home.source.adguard.base_url)
    if home.device_read.enabled:
        for dev in home.devices:
            if dev.host:
                out.append((f"{dev.display_name}.host", dev.host, PORT_LOCKDOWN))
    return out


def sieci_i_hosty(home: HomeConfig, *, resolver: Callable[[str, int], list[str]] | None = None
                  ) -> tuple[list[str], list[str], list[str]]:
    """Co Dom 1 musi miec w `dozwolone_sieci`/`dozwolone_hosty`, zeby po
    przejsciu na baze laczyl sie tam, gdzie dzis (§3.6: „Dom 1 dostaje przy
    migracji sieci z obecnych tv.host/unifi.url”). Kazdy niepubliczny adres
    jako /32 (/128) — najwezej, jak sie da. (sieci, hosty, ostrzezenia)."""
    rozwiaz = resolver or rozwiaz_systemowo
    pusty = Straznik(0)
    sieci: list[str] = []
    ostrzezenia: list[str] = []
    for pole, host, port in _adresy(home):
        literal = adres_literalny(host)
        try:
            adresy = [str(literal)] if literal is not None else rozwiaz(host, port)
        except OSError:
            ostrzezenia.append(f"{pole}: nazwa {host} nie rozwiazuje sie — nie dodana")
            continue
        for a in adresy:
            ip = adres_literalny(a)
            if ip is not None and not pusty.dozwolony(ip):
                sieci.append(f"{ip}/{ip.max_prefixlen}")
        if literal is None:
            ostrzezenia.append(f"{pole}: {host} to nazwa — dodane adresy z dzisiejszego DNS "
                               f"({', '.join(adresy)}); zmiana DNS wymaga dom-sieci")
    hosty = []
    if home.source.nextdns is not None:
        h = (urlsplit(home.source.nextdns.base_url).hostname or "").lower()
        if h and h not in HOSTY_API["nextdns"]:
            hosty.append(h)
    if home.notifiers.ntfy is not None and home.notifiers.ntfy.enabled:
        h = (urlsplit(home.notifiers.ntfy.server).hostname or "").lower()
        if h and h not in HOSTY_API["ntfy"]:
            hosty.append(h)
    return list(dict.fromkeys(sieci)), list(dict.fromkeys(hosty)), ostrzezenia


def _plaski(d: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(d, dict):
        out: dict[str, Any] = {}
        for k, v in d.items():
            out.update(_plaski(v, f"{prefix}.{k}" if prefix else str(k)))
        return out or {prefix: {}}
    if isinstance(d, list) and d and any(isinstance(x, dict) for x in d):
        out = {}
        for i, v in enumerate(d):
            out.update(_plaski(v, f"{prefix}[{i}]"))
        return out
    return {prefix: d}


def porownaj(yaml_home: HomeConfig, baza_home: HomeConfig) -> list[str]:
    """Sciezki pol, ktore sie roznia — BEZ wartosci (temat ntfy to sekret).
    Katalog klucza ADB rozni sie z zalozenia (pamiec poda zamiast /adb)."""
    def norm(h: HomeConfig) -> dict[str, Any]:
        d = h.model_dump(mode="json")
        d["tv"]["adb_key_dir"] = _ADB
        return _plaski(d)

    a, b = norm(yaml_home), norm(baza_home)
    return [f"{k}: rozne" if k in a and k in b else
            f"{k}: {'tylko w config.yaml' if k in a else 'tylko w bazie'}"
            for k in sorted(set(a) | set(b)) if a.get(k, ...) != b.get(k, ...)]


def porownaj_sekrety(yaml: Mapping[str, Mapping[str, str]], baza: SekretyDomu,
                     typy: set[str]) -> list[str]:
    out = []
    for typ in sorted(typy):
        for pole in POLA_SEKRETOW[typ]:
            a, b = (yaml.get(typ) or {}).get(pole), baza.get(typ, pole)
            if a != b:
                stan = ("brak w bazie" if b is None else "brak w config.yaml/env"
                        if a is None else "rozne wartosci")
                out.append(f"sekret {typ}.{pole}: {stan}")
    return out


def _nowszy_token_tv(rejestr: RejestrDomow, dom_id: int, sejf: Sejf,
                     sekrety_yaml: Mapping[str, Mapping[str, str]], plik: Path | None
                     ) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Ponowny import nie cofa tokenu aplikacji TV: po sparowaniu w trybie
    `baza` nowy token jest tylko w bazie, a plik na /data zostaje stary.
    Token z bazy wygrywa, gdy pliku nie ma albo jest starszy niz ostatni
    zapis SAMEGO tokenu w bazie (audyt; zmiana innego pola integracji `tv`
    sie nie liczy); nowszy plik (parowanie po powrocie do yaml) — wygrywa
    plik."""
    wynik = {t: dict(p) for t, p in sekrety_yaml.items()}
    dom = rejestr.dom(dom_id)
    tv = rejestr.integracja(dom_id, "tv")
    if plik is None or dom is None or not dom.ma_dek or tv is None \
            or "app_token" not in tv.sekrety_pola:
        return wynik, []
    w_bazie = rejestr.sekrety_domu(dom_id, sejf).get("tv", "app_token")
    z_pliku = wynik.get("tv", {}).get("app_token")
    if not w_bazie or w_bazie == z_pliku:
        return wynik, []
    zmiana_tokenu = rejestr.czas_zmiany_sekretu(dom_id, "tv", "app_token")
    if zmiana_tokenu is None:
        zmiana_tokenu = tv.zmienione_at or 0
    try:
        plik_nowszy = plik.stat().st_mtime > zmiana_tokenu
    except OSError:
        plik_nowszy = False
    if z_pliku and plik_nowszy:
        return wynik, []
    wynik.setdefault("tv", {})["app_token"] = w_bazie
    powod = "starszy niz ostatnia zmiana tokenu w bazie" if z_pliku else "nie istnieje"
    return wynik, [f"token aplikacji TV: zostaje token z bazy ({plik} {powod})"]


@dataclass
class RaportImportu:
    dom_id: int
    strefa: str
    dzieci: list[str]
    urzadzenia: list[str]
    #: typ -> (wlaczona, {pole: maska})
    integracje: dict[str, tuple[bool, dict[str, str]]]
    dozwolone_sieci: list[str]
    dozwolone_hosty: list[str]
    ostrzezenia: list[str] = field(default_factory=list)
    roznice: list[str] = field(default_factory=list)
    zapisano: bool = False


def importuj(rejestr: RejestrDomow, dom_id: int, home: HomeConfig, sekrety_yaml:
             Mapping[str, Mapping[str, str]], *, sejf: Sejf, zapisz: bool,
             kto: str | None = None,
             resolver: Callable[[str, int], list[str]] | None = None,
             plik_tokenu_tv: Path | None = None) -> RaportImportu:
    """`dom-importuj`: zapis -> odczyt -> porownanie w jednej transakcji.
    `zapisz=False` (podglad) albo jakakolwiek roznica = ROLLBACK, baza bez
    zmian. Strefa domu ZAWSZE z HomeConfig (Dom 1 zalozony przez PanelAuth
    ma domyslne Europe/Warsaw niezaleznie od config.yaml)."""
    dom = rejestr.dom(dom_id)
    if dom is None:
        raise LookupError(f"nie ma domu {dom_id}")
    sekrety_yaml, ostrzezenie_tv = _nowszy_token_tv(rejestr, dom_id, sejf, sekrety_yaml,
                                                    plik_tokenu_tv)
    plan = plan_z_home(home, sekrety_yaml)
    sieci, hosty, ostrzezenia = sieci_i_hosty(home, resolver=resolver)
    ostrzezenia += ostrzezenie_tv
    plan.dozwolone_sieci = list(dict.fromkeys([*dom.dozwolone_sieci, *sieci]))
    plan.dozwolone_hosty = list(dict.fromkeys([*dom.dozwolone_hosty, *hosty]))
    raport = RaportImportu(
        dom_id=dom_id, strefa=plan.strefa, dzieci=list(plan.dzieci),
        urzadzenia=[u["nazwa"] for u in plan.urzadzenia],
        integracje={t: (w, {p: maska(v) for p, v in sorted(plan.sekrety.get(t, {}).items())})
                    for t, (w, _) in sorted(plan.integracje.items())},
        dozwolone_sieci=plan.dozwolone_sieci, dozwolone_hosty=plan.dozwolone_hosty,
        ostrzezenia=ostrzezenia,
    )
    with rejestr._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            zapisz_dane_domu_conn(conn, dom_id, plan, sejf=sejf, kto=kto)
            dane = dane_domu_conn(conn, dom_id)
            sekrety_bazy = sekrety_domu_conn(conn, dom_id, sejf)
            try:
                z_bazy = home_z_danych(dane, sekrety_bazy, katalog_plikow=_ADB)
                raport.roznice = porownaj(home, z_bazy)
            except ValueError as exc:
                raport.roznice = [str(exc)]
            raport.roznice += porownaj_sekrety(sekrety_yaml, sekrety_bazy,
                                               set(plan.integracje))
            if zapisz and not raport.roznice:
                conn.execute("UPDATE domy SET zrodlo_konfiguracji = ? WHERE id = ?",
                             (ZRODLO_BAZA, dom_id))
                _audyt(conn, time.time(), dom_id, kto, "dom.zrodlo",
                       "konfiguracja domu: baza (dom-importuj)")
                conn.execute("COMMIT")
                raport.zapisano = True
            else:
                conn.execute("ROLLBACK")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return raport

