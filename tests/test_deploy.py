"""Testy artefaktow wdrozeniowych (chart Helm, konwencja jak Trader i Dietetyk).

Chart nie moze siegac po pliki spoza swojego katalogu, wiec app_map.yaml istnieje
w repo dwa razy. Dwie kopie jednej prawdy zawsze sie w koncu rozjada, a rozjazd
mapy domen jest cichy: serwis dziala, tylko klasyfikuje inaczej na produkcji niz
w testach. Ten plik na to nie pozwala.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "kidwatch"


def test_kopia_app_map_dla_chartu_jest_identyczna_z_korzeniem():
    source = (ROOT / "app_map.yaml").read_bytes()
    deployed = (CHART / "files" / "app_map.yaml").read_bytes()
    assert source == deployed, (
        "charts/kidwatch/files/app_map.yaml rozjechal sie z app_map.yaml w korzeniu.\n"
        "Odswiez:  cp app_map.yaml charts/kidwatch/files/app_map.yaml"
    )


def test_konfiguracja_dla_klastra_trzyma_baze_na_wolumenie():
    """Sciezka poza /data znaczy baze w warstwie kontenera — czyli utrate calego
    stanu przy kazdym restarcie poda."""
    cfg = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["store"]["path"].startswith("/data/")


def test_konfiguracja_dla_klastra_nie_zawiera_zadnego_sekretu():
    """Sprawdzamy WARTOSCI, nie komentarze. Komentarz wymieniajacy nazwy
    zmiennych (NEXTDNS_API_KEY) jest pozadany — to instrukcja, nie sekret."""
    raw = (CHART / "files" / "config.yaml").read_text(encoding="utf-8")
    values = "\n".join(
        line.split("#", 1)[0] for line in raw.splitlines() if not line.lstrip().startswith("#")
    ).lower()
    for forbidden in ("api_key", "apikey", "password", "token:", "webhook_id", "tskey-"):
        assert forbidden not in values, f"{forbidden!r} nie moze trafic do pliku w gicie"


def test_rekordy_parowania_ida_z_sekretu_nie_z_repo():
    """Rekord parowania zawiera klucz prywatny hosta. W repo go byc nie moze."""
    cfg = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["device_read"]["pair_record_dir"] == "/pairing"
    assert not list(ROOT.rglob("*.plist")), "plik .plist w repo — to moze byc rekord parowania"


def test_identyfikacja_urzadzen_po_UDID_nie_po_nazwie():
    """Nazwy zwodza: te same iPady zglaszaly sie jako "Jan Kowalski's iPad"
    i "iPad (2)", a przez bonjour jako "iPad (Dziecko 1)" i "iPad (Dziecko 2)"."""
    cfg = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    for dev in cfg["devices"]:
        assert dev.get("udid"), f"{dev['display_name']} bez UDID"
        assert dev.get("host"), f"{dev['display_name']} bez host"
    udids = [d["udid"] for d in cfg["devices"]]
    assert len(udids) == len(set(udids))


# ============================================================ szablony chartu
def rendered(*sets: str) -> list[dict]:
    args = [a for kv in sets for a in ("--set", kv)]
    out = subprocess.run(
        ["helm", "template", "kidwatch", str(CHART), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


pytestmark_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm niedostepny")


@pytestmark_helm
def test_chart_sie_renderuje_i_daje_potrzebne_obiekty():
    kinds = {d["kind"] for d in rendered()}
    assert {"ConfigMap", "PersistentVolumeClaim", "Deployment", "Service", "Ingress"} <= kinds


@pytestmark_helm
def test_deployment_wyklucza_dwa_pody_na_jednej_bazie_sqlite():
    """SQLite ma jednego pisarza. RollingUpdate albo replicas>1 rozjezdza stan."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    assert dep["spec"]["replicas"] == 1
    assert dep["spec"]["strategy"]["type"] == "Recreate"


@pytestmark_helm
def test_pliki_tymczasowe_sqlite_ida_na_wolumen_danych_a_nie_do_tmp():
    """/tmp to emptyDir 16Mi; sortowanie SQLite ponad limit eksmitowalo pod."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    main = dep["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e.get("value") for e in main["env"]}
    assert env["SQLITE_TMPDIR"].startswith("/data/")


def test_store_zaklada_katalog_plikow_tymczasowych(tmp_path, monkeypatch):
    from kidwatch.store import Store  # noqa: PLC0415

    monkeypatch.setenv("SQLITE_TMPDIR", str(tmp_path / "data" / "tmp"))
    Store(tmp_path / "data" / "k.db").close()
    assert (tmp_path / "data" / "tmp").is_dir()


@pytestmark_helm
def test_odczyt_ipadow_jedzie_w_TYM_SAMYM_kontenerze_co_dns():
    """Dwa procesy na jednej bazie SQLite rozjechalyby stan. Kontener aplikacji
    musi byc jeden, a `run` uruchamia obie petle."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    app = [c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "kidwatch"]
    assert len(app) == 1
    assert app[0]["args"] == ["run"]


@pytestmark_helm
def test_tailscale_jest_w_trybie_jadrowym_i_NIE_przejmuje_dns():
    """W trybie userspace Tailscale daje tylko proxy SOCKS5, a pymobiledevice3
    otwiera surowe gniazda asyncio i nie przejdzie przez nie.

    --accept-dns=false jest krytyczne: bez tego Tailscale przejmuje DNS poda i
    psuje rozwiazywanie nazw uslug oraz api.nextdns.io.
    """
    dep = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Deployment")
    ts = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "tailscale")
    env = {e["name"]: e.get("value") for e in ts["env"]}
    assert env["TS_USERSPACE"] == "false"
    assert "--accept-dns=false" in env["TS_EXTRA_ARGS"]
    assert ts["securityContext"]["capabilities"]["add"] == ["NET_ADMIN"]


@pytestmark_helm
def test_tailscale_trzyma_stan_w_sekrecie_zeby_nie_zmieniac_adresu():
    """Bez trwalego stanu pod po restarcie dolacza do tailnetu jako NOWE
    urzadzenie i zmienia adres — a adres jest tym, po czym siegamy iPadow."""
    dep = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Deployment")
    ts = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "tailscale")
    env = {e["name"]: e.get("value") for e in ts["env"]}
    assert env["TS_KUBE_SECRET"]

    role = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Role")
    named = [r for r in role["rules"] if r.get("resourceNames")]
    assert named, "Role musi byc zawezona do JEDNEGO sekretu"
    assert env["TS_KUBE_SECRET"] in named[0]["resourceNames"]


@pytestmark_helm
def test_tailscale_ma_PINOWANA_wersje_a_nie_ruchomy_tag():
    """Ruchomy tag zmienia zachowanie sieci poda przy przypadkowym restarcie —
    najgorsze miejsce na taka niespodzianke."""
    dep = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Deployment")
    ts = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "tailscale")
    tag = ts["image"].rsplit(":", 1)[-1]
    assert tag not in ("latest", "stable"), f"ruchomy tag Tailscale: {tag}"
    assert tag.startswith("v")


@pytestmark_helm
def test_aplikacja_dziala_jako_nie_root_z_tylko_czytelnym_korzeniem():
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    app = next(c for c in pod["containers"] if c["name"] == "kidwatch")
    assert app["securityContext"]["readOnlyRootFilesystem"] is True
    assert app["securityContext"]["allowPrivilegeEscalation"] is False
    mounts = {m["mountPath"] for m in app["volumeMounts"]}
    # Korzen tylko do czytania wymaga zapisywalnego /tmp na tetno.
    assert {"/tmp", "/data"} <= mounts


@pytestmark_helm
def test_zmiana_konfiguracji_restartuje_poda():
    """Bez sumy kontrolnej ArgoCD zsynchronizuje ConfigMap i zaraportuje Synced,
    a proces bedzie dalej chodzil na starej tresci."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    ann = dep["spec"]["template"]["metadata"]["annotations"]
    assert ann.get("checksum/config")


@pytestmark_helm
def test_zmiana_mapy_domen_restartuje_poda():
    """Regresja: app_map.yaml jest montowany przez subPath, a kubelet NIE
    odswieza plikow z subPath po zmianie ConfigMapy — przeladowanie na goraco
    nigdy go nie widzialo, a bez sumy kontrolnej nie bylo tez restartu. Nowa
    domena w mapie trafiala do poda dopiero przy przypadkowym restarcie."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    ann = dep["spec"]["template"]["metadata"]["annotations"]
    assert ann.get("checksum/app-map")
    mount = next(
        m for m in dep["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        if m["mountPath"] == "/app/app_map.yaml"
    )
    assert mount.get("subPath") == "app_map.yaml"


@pytestmark_helm
def test_bez_tailscale_pod_nie_dostaje_tokenu_API_kubernetesa():
    """Proces z publicznym panelem nie potrzebuje tokenu konta uslugi — bez
    Tailscale nic w podzie nie rozmawia z API klastra."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"]["automountServiceAccountToken"] is False
    dep = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Deployment")
    assert dep["spec"]["template"]["spec"].get("automountServiceAccountToken") is not False


@pytestmark_helm
def test_wolumen_z_baza_przezywa_odinstalowanie():
    pvc = next(d for d in rendered() if d["kind"] == "PersistentVolumeClaim")
    assert pvc["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]


# ============================================= logowanie panelu bez bramki
@pytestmark_helm
def test_chart_NIE_ma_bramki_na_Traefiku_tylko_przekierowanie_na_HTTPS():
    """Logowanie (haslo + opcjonalny TOTP) robi panel. Druga bramka na
    Traefiku to drugie okno logowania bez blokady prob i bez wylogowania —
    usunieta decyzja wlasciciela, takze jako wylacznik awaryjny."""
    docs = rendered()
    middlewares = [d for d in docs if d["kind"] == "Middleware"]
    # Dozwolone tylko przekierowania (na HTTPS i z aliasow na glowny adres)
    # i limity polaczen (K-8). Zadnego basicAuth/forwardAuth ani innej bramki.
    assert sorted(m["metadata"]["name"] for m in middlewares) == [
        "kidwatch-alias-redirect", "kidwatch-redirect-https", "kidwatch-tempo",
        "kidwatch-w-toku"]
    for m in middlewares:
        assert set(m["spec"]) <= {"redirectScheme", "redirectRegex", "inFlightReq",
                                  "rateLimit"}, m["spec"]
    https = next(d for d in docs if d["kind"] == "Ingress" and d["metadata"]["name"] == "kidwatch")
    ann = https["metadata"].get("annotations") or {}
    assert ann["traefik.ingress.kubernetes.io/router.middlewares"] == (
        "default-kidwatch-w-toku@kubernetescrd,default-kidwatch-tempo@kubernetescrd")
    assert https["spec"]["tls"]
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert "basicAuth" not in values["ingress"]


def test_baza_logowania_panelu_lezy_na_wolumenie():
    """Konta i sesje poza /data znikalyby przy kazdym restarcie poda."""
    from kidwatch.config import Config  # noqa: PLC0415

    raw = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    cfg = Config.model_validate(raw)
    assert cfg.panel_auth_path.startswith("/data/")
    assert cfg.panel.cookie_secure is True


@pytestmark_helm
def test_klucz_TOTP_dociera_do_kontenera_z_sekretu():
    """PANEL_TOTP_KEY jest w kidwatch-secrets; kontener musi brac ten sekret
    w calosci (envFrom), inaczej panel startuje z wylaczonym logowaniem."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    app = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "kidwatch")
    refs = [e["secretRef"]["name"] for e in app["envFrom"] if "secretRef" in e]
    assert "kidwatch-secrets" in refs


# ============================= poprawki z audytu (blokery w klastrze)
@pytestmark_helm
def test_sidecar_tailscale_MOZE_wstac_jako_root():
    """Pod ma runAsNonRoot: true, a Tailscale musi byc rootem. Bez jawnego
    runAsNonRoot: false kubelet odrzuca kontener przy tworzeniu i sidecar wpada
    w trwaly CreateContainerConfigError — aplikacja wstaje, ale BEZ tailnetu,
    wiec kazdy odczyt z iPada pada i wyglada jak spiacy iPad."""
    dep = next(d for d in rendered("tailscale.enabled=true") if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    assert pod["securityContext"]["runAsNonRoot"] is True
    ts = next(c for c in pod["containers"] if c["name"] == "tailscale")
    assert ts["securityContext"]["runAsUser"] == 0
    assert ts["securityContext"]["runAsNonRoot"] is False


def test_host_we_wzorcu_jest_adresem_IPv4_a_nie_nazwa():
    """Odczyt iPada chodzi tylko w sieci lokalnej (iOS odrzuca lockdown przez
    VPN). Nazwa hosta zalezy od DNS miejsca uruchomienia — wzorzec pokazuje
    adres IPv4 z rezerwacji DHCP."""
    import ipaddress  # noqa: PLC0415

    cfg = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    for dev in cfg["devices"]:
        assert ipaddress.ip_address(dev["host"]).version == 4, dev["display_name"]


def test_temat_ntfy_NIE_jest_w_repozytorium():
    """Nazwa tematu na ntfy.sh JEST haslem — ntfy.sh nie ma kontroli dostepu.
    Kto zna nazwe, czyta powiadomienia o dzieciach i moze wysylac falszywe."""
    cfg = yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["notifiers"]["ntfy"]["topic"] == "", "temat idzie z NTFY_TOPIC, nie z repo"

    # I nigdzie w repo nie moze byc ciagu wygladajacego na temat kidwatch.
    import re  # noqa: PLC0415

    wzor = re.compile(r"kidwatch-[a-z0-9]{20,}")
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git/" in str(path) or ".venv" in str(path):
            continue
        if path.suffix not in (".yaml", ".yml", ".md", ".py", ".sh", ".toml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert not wzor.search(text), f"{path.relative_to(ROOT)} zawiera temat ntfy"


# =========================== wzorzec konfiguracji nie moze sie rozjechac
def test_config_example_WALIDUJE_SIE(monkeypatch):
    """Wzorzec, ktory ludzie kopiuja, musi dzialac. Po usunieciu tematu ntfy
    z repo przestal sie walidowac i nikt by tego nie zauwazyl."""
    from kidwatch.config import Config  # noqa: PLC0415

    monkeypatch.setenv("NTFY_TOPIC", "kidwatch-test")
    cfg = Config.load(ROOT / "config.example.yaml")
    assert cfg.devices
    assert cfg.notifiers.ntfy.topic == "kidwatch-test"


def test_config_example_BEZ_NTFY_TOPIC_mowi_co_brakuje(monkeypatch):
    """Blad ma wskazywac zmienna srodowiskowa, a nie tylko "brak pola"."""
    from kidwatch.config import Config  # noqa: PLC0415

    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    with pytest.raises(Exception, match="NTFY_TOPIC"):
        Config.load(ROOT / "config.example.yaml")


def test_config_example_POKAZUJE_warstwe_odczytu_z_iPadow():
    """Wzorzec bez sekcji device_read ukrywalby polowe funkcji projektu."""
    raw = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    for pole in ("device_read:", "udid:", "host:", "known_apps:", "process_aliases:"):
        assert pole in raw, f"brak {pole} w config.example.yaml"

    cfg = yaml.safe_load(raw)
    # Domyslnie WYLACZONA: wymaga jednorazowego parowania po kablu, wiec nie moze
    # byc wlaczona we wzorcu, ktory ktos skopiuje i uruchomi.
    assert cfg["device_read"]["enabled"] is False


def test_wzorzec_ostrzega_ze_host_musi_byc_IPv4():
    """Bonjour zglasza iPady po IPv6, a wtedy dwa z trzech odczytow padaja."""
    raw = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    assert "IPv4" in raw
    assert "IPv6" in raw


# ========================== repo jest publiczne: zero danych osobowych
def test_wzorzec_konfiguracji_NIE_zawiera_prawdziwych_identyfikatorow():
    """Prawdziwy config.yaml idzie z Sekretu kidwatch-config. Wzorzec w repo ma
    placeholdery — UDID w postaci Apple (8 cyfr hex, myslnik, 16 hex) albo
    prawdziwe ID profilu NextDNS (6 hex) oznacza wyciek do publicznego repo."""
    import re  # noqa: PLC0415

    raw = (CHART / "files" / "config.yaml").read_text(encoding="utf-8")
    assert not re.search(r"\b[0-9A-F]{8}-[0-9A-F]{16}\b", raw), "prawdziwy UDID we wzorcu"
    cfg = yaml.safe_load(raw)
    assert cfg["source"]["nextdns"]["profile_id"] == "ZMIEN_MNIE"


def test_chart_bierze_konfiguracje_z_SEKRETU():
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    vols = {v["name"]: v for v in dep["spec"]["template"]["spec"]["volumes"]}
    assert vols["config-secret"]["secret"]["secretName"] == "kidwatch-config"
    cm = next(d for d in rendered() if d["kind"] == "ConfigMap")
    assert "config.yaml" not in cm["data"], "prawdziwy config nie moze isc z repo"


def test_prywatne_pliki_sa_w_gitignore():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for wzor in ("/config.cluster.yaml", "/LISTA-ZADAN.md", "*.mobileconfig", "*.plist"):
        assert wzor in ignore, f"{wzor} musi byc w .gitignore"


# ================================================= telewizor i UniFi w charcie
@pytestmark_helm
def test_klucz_ADB_z_sekretu_opcjonalnego_tylko_do_odczytu():
    """Bez Sekretu kidwatch-adb pod ma wstac (czujnik TV wylacza sie z bledem
    w logu), a klucz prywatny nie moze byc czytelny dla wszystkich."""
    dep = next(d for d in rendered() if d["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    vol = next(v for v in pod["volumes"] if v["name"] == "adb")
    assert vol["secret"]["secretName"] == "kidwatch-adb"
    assert vol["secret"]["optional"] is True
    assert vol["secret"]["defaultMode"] == 0o440
    app = next(c for c in pod["containers"] if c["name"] == "kidwatch")
    mount = next(m for m in app["volumeMounts"] if m["name"] == "adb")
    assert mount["mountPath"] == "/adb" and mount["readOnly"] is True


def test_wzorzec_TV_i_UniFi_bez_prawdziwych_adresow_i_odcisku():
    """Repo jest publiczne: adres TV, MAC-i iPadow i odcisk certyfikatu UDM
    ida z Sekretu kidwatch-config. We wzorcu tylko placeholdery."""
    from kidwatch.config import Config  # noqa: PLC0415

    cfg = Config.model_validate(
        yaml.safe_load((CHART / "files" / "config.yaml").read_text(encoding="utf-8"))
    )
    assert cfg.tv.adb_key_dir == "/adb"
    assert cfg.unifi.cert_sha256 == ""
    for dev in cfg.devices:
        assert dev.unifi_mac.startswith("02:00:00:00:00:"), dev.unifi_mac


# ============================================= NetworkPolicy (2026-10-03)
@pytestmark_helm
def test_panel_przyjmuje_ruch_WYLACZNIE_od_Traefika_na_porcie_poda():
    """Bez polityki kazdy pod w klastrze mogl pukac do panelu z pominieciem
    Traefika. Port to port PODA (8080), nie Service'u (80) - polityka dziala
    po DNAT, wiec 80 zablokowaloby takze Traefika."""
    docs = rendered()
    pol = [d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "kidwatch"]
    assert len(pol) == 1
    spec = pol[0]["spec"]
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert spec["podSelector"]["matchLabels"] == dep["spec"]["selector"]["matchLabels"]
    assert spec["policyTypes"] == ["Ingress"] and "egress" not in spec
    port_poda = dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]["containerPort"]
    traefik = {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}},
    }
    assert spec["ingress"] == [{
        "from": [traefik],
        "ports": [{"protocol": "TCP", "port": port_poda}]}]


@pytestmark_helm
def test_bez_panelu_pod_nie_przyjmuje_niczego():
    pol = next(d for d in rendered("panel.enabled=false")
               if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "kidwatch")
    assert pol["spec"]["policyTypes"] == ["Ingress"] and not pol["spec"].get("ingress")


@pytestmark_helm
def test_polityka_domyslnie_wlaczona_i_flaga_ja_wylacza():
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert values["networkPolicy"]["enabled"] is True
    assert not [d for d in rendered("networkPolicy.enabled=false") if d["kind"] == "NetworkPolicy"]


# Adresy z puli dokumentacyjnej (RFC 5737) - prawdziwe sa tylko w prywatnym
# repo infrastruktury, ktore wstrzykuje je przez Argo CD.
DOM = (
    "networkPolicy.egress.siecDomowa={192.0.2.0/24,198.51.100.0/24}",
    "networkPolicy.egress.wDomu[0].cidr=192.0.2.10/32",
    "networkPolicy.egress.wDomu[0].port=5555",
    "networkPolicy.egress.wDomu[1].cidr=192.0.2.1/32",
    "networkPolicy.egress.wDomu[1].port=443",
)


def _egress(*sets: str) -> tuple[dict, dict]:
    docs = rendered(*sets)
    eg = next(d for d in docs
              if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "kidwatch-egress")
    return eg["spec"], next(d for d in docs if d["kind"] == "Deployment")


@pytestmark_helm
def test_egress_dom_TYLKO_TV_i_UniFi_reszta_bez_zmian():
    """Audyt 03.10: kazdy pod dochodzil tunelem do calego domowego LAN.
    Kidwatch potrzebuje z domu dokladnie dwoch rzeczy: ADB telewizora i UniFi."""
    spec, dep = _egress(*DOM)
    assert spec["podSelector"]["matchLabels"] == dep["spec"]["selector"]["matchLabels"]
    assert spec["policyTypes"] == ["Egress"] and "ingress" not in spec
    dns, klaster, swiat, *dom = spec["egress"]
    assert {(x["protocol"], x["port"]) for x in dns["ports"]} == {("UDP", 53), ("TCP", 53)}
    assert klaster == {"to": [{"namespaceSelector": {}}]}
    blok = {"cidr": "0.0.0.0/0", "except": ["192.0.2.0/24", "198.51.100.0/24"]}
    assert swiat == {"to": [{"ipBlock": blok}]}
    tv = {"to": [{"ipBlock": {"cidr": "192.0.2.10/32"}}],
          "ports": [{"protocol": "TCP", "port": 5555}]}
    udm = {"to": [{"ipBlock": {"cidr": "192.0.2.1/32"}}],
           "ports": [{"protocol": "TCP", "port": 443}]}
    assert dom == [tv, udm]


@pytestmark_helm
def test_egress_bez_adresow_domu_niczego_nie_wycina():
    """Repo jest publiczne: domyslne values nie zawieraja adresow domu."""
    spec, _ = _egress()
    swiat = spec["egress"][2]
    assert swiat == {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}
    assert len(spec["egress"]) == 3
    values = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "192.168." not in values and "10.13.13" not in values


@pytestmark_helm
def test_flaga_egress_wylacza_tylko_egress():
    nazwy = [d["metadata"]["name"] for d in rendered("networkPolicy.egress.enabled=false")
             if d["kind"] == "NetworkPolicy"]
    assert nazwy == ["kidwatch"]


@pytestmark_helm
def test_alias_przekierowuje_301_na_glowny_adres_ze_sciezka():
    """kidswatch.renacode.com (literowka/alias) ma prowadzic do tego samego
    panelu - przekierowaniem, nie druga kopia (sesja i CSRF na jednej domenie)."""
    docs = rendered()
    mw = next(d for d in docs if d["kind"] == "Middleware"
              and d["metadata"]["name"] == "kidwatch-alias-redirect")
    r = mw["spec"]["redirectRegex"]
    assert r["permanent"] is True
    assert r["replacement"] == "https://kidwatch.renacode.com/${1}"
    aliasy = [d for d in docs if d["kind"] == "Ingress" and "aliasy" in d["metadata"]["name"]]
    assert {a["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.entrypoints"]
            for a in aliasy} == {"web", "websecure"}
    for a in aliasy:
        assert [x["host"] for x in a["spec"]["rules"]] == ["kidswatch.renacode.com"]


# ============================================= przeglad 04.10: K-7, K-8, K-12
def _volumes(docs):
    dep = next(d for d in docs if d["kind"] == "Deployment")
    spec = dep["spec"]["template"]["spec"]
    mounts = {m["name"] for c in spec["containers"] for m in c.get("volumeMounts", [])}
    return {v["name"]: v for v in spec["volumes"]}, mounts


@pytestmark_helm
def test_rekordy_parowania_montowane_tylko_przy_odczycie_ipadow():
    """Rekord parowania to klucz prywatny hosta zaufanego przez iPada. Przy
    wylaczonym odczycie iPadow nie ma go w podzie z publicznym panelem."""
    volumes, mounts = _volumes(rendered())
    assert "pairing" not in volumes and "pairing" not in mounts
    volumes, mounts = _volumes(rendered("deviceRead.enabled=true"))
    assert "pairing" in mounts
    assert volumes["pairing"]["secret"]["defaultMode"] == 0o440


@pytestmark_helm
def test_limity_polaczen_panelu_per_adres():
    docs = rendered()
    mw = {d["metadata"]["name"]: d["spec"] for d in docs if d["kind"] == "Middleware"}
    assert mw["kidwatch-w-toku"]["inFlightReq"]["amount"] == 20
    assert mw["kidwatch-w-toku"]["inFlightReq"]["sourceCriterion"] == {"ipStrategy": {"depth": 0}}
    rl = mw["kidwatch-tempo"]["rateLimit"]
    assert (rl["average"], rl["burst"]) == (30, 60)
    assert rl["sourceCriterion"] == {"ipStrategy": {"depth": 0}}
    # Wylacznik: bez limitow nie ma ani middleware, ani annotacji.
    docs = rendered("ingress.limity.enabled=false")
    assert not [d for d in docs if d["kind"] == "Middleware"
                and {"inFlightReq", "rateLimit"} & set(d["spec"])]
    https = next(d for d in docs if d["kind"] == "Ingress" and d["metadata"]["name"] == "kidwatch")
    assert "traefik.ingress.kubernetes.io/router.middlewares" not in (
        https["metadata"].get("annotations") or {})


def test_timeout_bramki_dluzszy_niz_najgorszy_czas_bramki():
    from kidwatch.config import BramkaConfig  # noqa: PLC0415

    # sendText 15 s + zapasowy mail 15 s + status 3 s (K-12).
    assert BramkaConfig().timeout_seconds == 40.0
