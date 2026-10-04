#!/usr/bin/env python3
"""Generuje tests/fixtures/day.jsonl — realistyczny dzien dwoch iPadow.

Deterministyczny (ziarno ustalone), zeby snapshot E2E byl stabilny. Uruchom
ponownie tylko wtedy, gdy celowo zmieniasz scenariusz — potem odswiez snapshot:

    uv run python tools/gen_fixture_day.py
    uv run python -m kidwatch --config tests/fixtures/config.yaml \\
        replay tests/fixtures/day.jsonl --dry-run > tests/fixtures/day.expected.txt
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Warsaw")
DAY = (2026, 9, 26)
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "day.jsonl"

KUBA, ZOSIA = "iPad-Kuby", "iPad-Zosi"

# Domeny, ktore iPad odpytuje w tle non stop — takze z wygaszonym ekranem.
NOISE = [
    "gsp-ssl.ls.apple.com",
    "p50-content.icloud.com",
    "configuration.apple.com",
    "gateway.push.apple.com",
    "init.itunes.apple.com",
    "iphone-ld.apple.com",
    "captive.apple.com",
    "settings.crashlytics.com",
    "token.safebrowsing.apple",
]
APPS = {
    "youtube": ["www.youtube.com", "youtubei.googleapis.com", "rr3---sn-4g5e6nez.googlevideo.com",
                "i.ytimg.com", "yt3.ggpht.com"],
    "youtubekids": ["www.youtubekids.com", "youtubei.googleapis.com",
                    "rr1---sn-8xgp1vo.googlevideo.com"],
    "roblox": ["www.roblox.com", "ecsv3.roblox.com", "clientsettings.roblox.com",
               "rbxcdn.com", "assetgame.roblox.com"],
    "tiktok": ["www.tiktok.com", "api16-normal-c-useast1a.tiktokv.com", "p16-sign.tiktokcdn.com"],
    "minecraft": ["api.minecraft.net", "sessionserver.mojang.com"],
    # Ruch nierozpoznany — u nas ladnie wpada w "Przegladarka / inne".
    "przegladarka": ["www.wikipedia.org", "sklep-modelarski.pl", "www.jakas-gazeta.pl",
                     "forum-o-grach.pl"],
    # Gra rozpoznana po domenie wydawcy.
    "asphalt": ["asphalt.gameloft.com", "ingame.gameloft.com", "gameloft.net"],
    # Gra NIEROZPOZNANA — dokladnie to, co ma wylapac `kidwatch domains`.
    "nieznana_gra": ["api.super-gierka-online.com", "cdn.super-gierka-online.com"],
}

# Ruch wspoldzielony: CDN-y i SDK reklamowe. Nie otwiera sesji, ale ja przedluza.
# W grach to wieksza czesc gadaniny po sieci niz domeny wydawcy.
SHARED = [
    "d2k4q26owzy373.cloudfront.net",
    "auction.unityads.unity3d.com",
    "prod.api.applovin.com",
    "s3.eu-central-1.amazonaws.com",
    "rt.helpshift.com",
]


def at(hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(*DAY, hour, minute, second, tzinfo=TZ)


class Writer:
    def __init__(self) -> None:
        self.rows: list[tuple[datetime, str, str]] = []
        self.rng = random.Random(20260926)

    def add(self, when: datetime, device: str, domain: str) -> None:
        self.rows.append((when, device, domain))

    def noise(self, device: str, start: datetime, end: datetime, every_minutes: int) -> None:
        """Tlo systemowe. To ono dowodzi, ze potok danych zyje."""
        when = start
        while when < end:
            self.add(when, device, self.rng.choice(NOISE))
            when += timedelta(minutes=every_minutes, seconds=self.rng.randint(-40, 40))

    def session(
        self,
        device: str,
        start: datetime,
        minutes: int,
        apps: list[str],
        every_seconds: int = 70,
        shared_every: int = 0,
    ) -> None:
        """Sesja uzytkowania: ruch aplikacji przemieszany z tlem systemowym.

        `shared_every` > 0 wtraca ruch wspoldzielony (CDN, reklamy) co tyle
        zdarzen — tak zachowuje sie gra, ktora rzadko gada z wlasnym zapleczem,
        a czesto z CloudFrontem.
        """
        when, end = start, start + timedelta(minutes=minutes)
        i = 0
        while when < end:
            app = apps[(i // 3) % len(apps)]
            self.add(when, device, self.rng.choice(APPS[app]))
            if i % 4 == 3:
                self.add(when + timedelta(seconds=5), device, self.rng.choice(NOISE))
            if shared_every and i % shared_every == 0:
                self.add(when + timedelta(seconds=12), device, self.rng.choice(SHARED))
            when += timedelta(seconds=every_seconds + self.rng.randint(-20, 25))
            i += 1

    def dump(self, path: Path) -> int:
        self.rows.sort(key=lambda r: r[0])
        lines = [
            json.dumps(
                {
                    "ts": when.astimezone(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z"),
                    "device": device,
                    "domain": domain,
                },
                ensure_ascii=False,
            )
            for when, device, domain in self.rows
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return len(lines)


def build() -> Writer:
    w = Writer()

    # --- noc: WYLACZNIE tlo systemowe. Nie ma tu zadnej sesji i to jest teza
    #     tego fragmentu: sam szum nie moze nikogo obudzic pushem.
    w.noise(KUBA, at(0, 5), at(6, 50), every_minutes=22)
    w.noise(ZOSIA, at(0, 12), at(6, 50), every_minutes=27)

    # --- poranek: Kuba oglada YouTube przed szkola
    w.session(KUBA, at(7, 14), minutes=33, apps=["youtube"])
    w.noise(ZOSIA, at(7, 0), at(8, 0), every_minutes=18)

    # --- szkola: oba iPady w tle
    w.noise(KUBA, at(8, 10), at(15, 0), every_minutes=25)
    w.noise(ZOSIA, at(8, 10), at(15, 40), every_minutes=25)

    # --- popoludnie: Kuba Roblox, potem przegladarka, potem znow Roblox
    w.session(KUBA, at(15, 12), minutes=48, apps=["roblox", "przegladarka", "roblox"])
    # Zosia: YouTube Kids i Minecraft
    w.session(ZOSIA, at(15, 50), minutes=40, apps=["youtubekids", "minecraft"])

    # --- Asphalt: gra gadajaca RZADKO z wlasnym zapleczem i czesto z CDN-em.
    #     Bez kategorii `shared` jej sesja bylaby sztucznie posiekana.
    w.session(ZOSIA, at(17, 10), minutes=35, apps=["asphalt"],
              every_seconds=200, shared_every=1)

    # --- gra, ktorej NIE MA w app_map.yaml: ma wyjsc jako "Przegladarka / inne",
    #     a `kidwatch domains --unknown-only` ma ja pokazac do dopisania
    w.session(KUBA, at(16, 20), minutes=18, apps=["nieznana_gra"], every_seconds=110)

    # --- wieczor: krotka sesja Kuby, konczy sie przed cichymi godzinami
    w.session(KUBA, at(19, 20), minutes=22, apps=["youtube", "przegladarka"])
    w.noise(KUBA, at(17, 0), at(19, 15), every_minutes=24)
    w.noise(ZOSIA, at(16, 40), at(21, 0), every_minutes=24)

    # --- NOC: aktywnosc w cichych godzinach (21:30-07:00). To wlasnie ten
    #     przypadek, dla ktorego caly serwis istnieje.
    w.session(KUBA, at(22, 47), minutes=26, apps=["tiktok", "roblox"])
    w.noise(ZOSIA, at(21, 30), at(23, 30), every_minutes=26)

    return w


if __name__ == "__main__":
    count = build().dump(OUT)
    print(f"zapisano {OUT} — {count} zdarzen")
