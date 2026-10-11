#!/usr/bin/env python3
"""Generuje tests/fixtures/telefon_android.jsonl — doba telefonu z Androidem.

Syntetyczna (nie z logow tego domu), deterministyczna. Format jak day.jsonl:
`device` to nazwa, ktora NextDNS pokazuje dla Prywatnego DNS
`Telefon--Kuby-<profil>.dns.nextdns.io` (`--` -> spacja).

Scenariusz (czas lokalny, 2026-10-10):
  * cala doba: tlo Androida (FCM, sprawdzanie lacznosci, Play, uslugi
    producenta) co kilka minut — NIE moze otworzyc sesji, takze w nocy;
  * 03:10: pojedyncze zapytanie WhatsAppa (wiadomosc przyszla w nocy) — jedna
    chwila ruchu, sesja sie nie potwierdza;
  * 15:00-15:40: YouTube;
  * 22:40-22:55: TikTok — alarm "uzywa telefonu w nocy".

    uv run python tools/gen_fixture_telefon.py
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Warsaw")
DAY = (2026, 10, 10)
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "telefon_android.jsonl"
DEVICE = "Telefon Kuby"

BACKGROUND = [
    "mtalk.google.com",
    "alt3-mtalk.google.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "time.android.com",
    "android.clients.google.com",
    "play.googleapis.com",
    "www.googleapis.com",
    "dl.google.com",
    "redirector.gvt1.com",
    "dms.samsungdm.com",
    "vas.samsungapps.com",
    "app-measurement.com",
]
APPS = {
    "youtube": ["youtubei.googleapis.com", "rr3---sn-4g5e6nez.googlevideo.com",
                "i.ytimg.com", "yt3.ggpht.com"],
    "tiktok": ["api16-normal-c-useast1a.tiktokv.com", "v16m.tiktokcdn.com",
               "p16-sign.tiktokcdn.com"],
}


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(*DAY, hh, mm, ss, tzinfo=TZ)


def main() -> None:
    rnd = random.Random(20261010)
    rows: list[tuple[datetime, str]] = []

    t = at(0, 0)
    end = at(23, 59)
    while t < end:
        rows.append((t, rnd.choice(BACKGROUND)))
        t += timedelta(minutes=rnd.randint(3, 9), seconds=rnd.randint(0, 59))

    rows.append((at(3, 10, 4), "g.whatsapp.net"))

    sessions = (("youtube", at(15, 0), at(15, 40)), ("tiktok", at(22, 40), at(22, 55)))
    for app, start, stop in sessions:
        t = start
        while t < stop:
            rows.append((t, rnd.choice(APPS[app])))
            t += timedelta(seconds=rnd.randint(15, 45))

    rows.sort()
    with OUT.open("w", encoding="utf-8") as fh:
        for ts, domain in rows:
            ts_utc = ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            fh.write(json.dumps({"ts": ts_utc, "device": DEVICE, "domain": domain}) + "\n")
    print(f"{OUT}: {len(rows)} zdarzen")


if __name__ == "__main__":
    main()
