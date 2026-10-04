"""CLI `summary` nie moze zjadac prawdziwego podsumowania dnia."""

from __future__ import annotations

from pathlib import Path

import yaml

from conftest import local
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


def test_run_konczy_sie_kodem_bledu_gdy_padnie_zadanie(tmp_path, monkeypatch):
    """Regresja: koniec petli zrodla konczyl proces z kodem 0 — w k8s
    wygladalo to jak czyste zatrzymanie, nie awaria."""
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
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    assert main(["--config", str(cfg_path), "run"]) == 1
