"""CLI `summary` nie moze zjadac prawdziwego podsumowania dnia."""

from __future__ import annotations

from pathlib import Path

import yaml

from conftest import local, zatrzymaj_run_po_restarcie
from kidwatch.__main__ import main
from kidwatch.classifier import Classifier
from kidwatch.config import Config
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.store import Store

FIXTURE = Path(__file__).parent / "fixtures" / "config.yaml"
APP_MAP = Path(__file__).parent.parent / "app_map.yaml"


def test_summary_z_CLI_nie_zajmuje_klucza_dedupu_podsumowania(tmp_path, capsys):
    """Regresja: `kidwatch summary` (np. przez kubectl exec po poludniu) szedl
    przez _emit i zajmowal klucz `daily:<dzien>`. O 20:30 silnik ustawial
    daily_sent, _emit trafial na zajety klucz i podsumowanie dnia przepadalo
    bez sladu — w logu, w panelu i na telefonie."""
    data = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "k.db")
    data["app_map_path"] = str(APP_MAP)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    assert main(["--config", str(cfg_path), "summary", "--date", "2026-10-02"]) == 0
    assert "Podsumowanie dnia 02.10" in capsys.readouterr().out
    # Drugie wywolanie dziala tak samo — CLI daje sie wolac wielokrotnie.
    assert main(["--config", str(cfg_path), "summary", "--date", "2026-10-02"]) == 0
    assert "Podsumowanie dnia 02.10" in capsys.readouterr().out

    cfg = Config.load(cfg_path)
    with Store(cfg.store.path) as store:
        engine = Engine(cfg, store, Classifier(cfg.app_map_path))
        notes = engine.tick(local(2026, 10, 2, 20, 31))
        assert [n.kind for n in notes if n.kind is NotifyKind.DAILY] == [NotifyKind.DAILY]


def test_run_restartuje_dom_gdy_padnie_zadanie(tmp_path, monkeypatch):
    """Regresja: koniec petli zrodla konczyl proces z kodem 0 — w k8s
    wygladalo to jak czyste zatrzymanie, nie awaria. Od E3b (izolacja awarii,
    renacode-infra: docs/projekty/kidwatch/architektura-domy.md §5.1) koniec petli to awaria DOMU:
    nadzorca
    planuje restart tego domu, a proces (panel, inne domy) zyje dalej; tetno
    procesu dotyka nadzorca. Bez izolacji (E1) — kod 1: test_domy.py."""
    import kidwatch.__main__ as cli  # noqa: PLC0415

    data = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "k.db")
    data["app_map_path"] = str(APP_MAP)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    class EmptySource:
        name = "atrapa"

        async def events(self):
            return
            yield  # pragma: no cover

        async def aclose(self):
            pass

    monkeypatch.setattr(cli, "build_source", lambda cfg, store: EmptySource())
    hb = tmp_path / "hb"
    monkeypatch.setattr("kidwatch.scheduler.HEARTBEAT_PATH", hb)
    zaplanowane = zatrzymaj_run_po_restarcie(monkeypatch)
    assert main(["--config", str(cfg_path), "run"]) == 0
    assert zaplanowane == [(1, "petla source zakonczyla sie bez bledu")]
    assert hb.exists()
