# kidwatch

Phone notifications about kids' iPad activity, inferred from DNS queries.
In a cluster they go through the RenaCode notification gateway (WhatsApp, or
e-mail when no number is linked); locally through ntfy or Home Assistant. On
top of that: a web panel with history, a usage chart, an "all screens" view
(iPads and TV on one daily timeline), trends and CSV export, NextDNS-based
"game time" controls, and optional Android TV (ADB) and UniFi sensors.

Full cluster deployment guide (in Polish):
[`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md).

**At a glance**

- **Data source:** DNS query logs from [NextDNS](https://nextdns.io) (live
  stream), or AdGuard Home's query log. No app on the iPad, no MDM, no
  jailbreak.
- **Notifications:** session start and end, new apps, night use, daily and
  weekly summaries, game time, TV viewing — via ntfy, Home Assistant or the
  WhatsApp/e-mail gateway.
- **Web panel:** history, all-screens timeline, trends, CSV export, NextDNS
  game-time controls, TV monitoring pause, password + optional TOTP 2FA login.
- **Optional:** Android/Google TV (ADB) and UniFi controller traffic.
- **Self-monitoring watchdog:** alerts when kidwatch stops seeing DNS traffic.
- **Stack:** Python 3.12 (asyncio, httpx, pydantic, SQLite), React 18 + Vite,
  Docker, Helm chart for k3s / Argo CD.

Code comments, notification texts and the panel UI are in Polish; strings
quoted below are reproduced verbatim.

Message types:

| | when | example |
|---|---|---|
| **Session start** | activity confirmed (3 distinct moments of traffic spanning ≥1 min within 5 min, or ≥3 min of traffic; a burst of queries within 10 s is one moment) after ≥10 min of silence | `<device> aktywny` · `15:12 — Roblox` |
| **App** | a new app during an ongoing session — each app once per session (switching back does not ping again) | `<child>` · `YouTube` |
| **Session end** | 10 min without activity | `<device> — koniec` · `15:12–15:59, 47 min` |
| **Daily summary** | 20:30 | sessions since 20:30 the previous day, time and top apps per child |
| **TV** (optional) | viewing start and end | `TV salon: start — <title> (YouTube)` |
| **Night** | a session in the night window (starting or ongoing) + a reminder every 30 min | `🌙 <child> uzywa iPada w nocy` · `23:12, YouTube, w domu` |
| **Weekly report** | Sunday 19:00 | since the previous Sunday 19:00: minutes vs previous week, sessions, active days, top 5, longest session, night use, TV |
| **Game time** (optional) | change from the panel, bonus end, schedule | `🎮 Czas gry dla <child>: +30 min (do 18:40)` |
| **TV pause** (optional) | monitoring paused / resumed | `Monitoring TV wstrzymany do …` · `Monitoring TV wznowiony` |

Plus the **self-monitoring watchdog** — see [Watchdog](#watchdog--the-most-important-part-without-supervision).

---

## First: what these numbers are NOT

**This is not a screen-time measurement.** The minutes shown for an app are
the number of distinct minutes in which the iPad sent a DNS query to that
app's domains. iOS caches DNS answers, so a child can play for an hour while
generating queries in only a few minutes. **Every number is a lower bound**,
and every notification says so (`czasy szacunkowe — liczba minut z ruchem DNS`).

The full data, including offline use, is in **Settings → Screen Time** on your
iPhone. Apple offers no public API for it and kidwatch does not try to hook
into it. If you compare the two, kidwatch will always show less — that is the
correct behaviour, not a bug.

What you will not see:

- **apps that don't query their own domains** (offline games, photos, notes);
- **a 100% split between YouTube Kids and YouTube** — YT Kids uses some of the
  same domains (`googlevideo.com`, `youtubei.googleapis.com`), so part of its
  traffic lands under "YouTube";
- **content** — only domains. You don't know *what* the child watched.

---

## Quick start — without erasing the iPad

**You don't need to supervise the iPads or wipe anything.** Checked against
Apple's official schema
([`com.apple.dnsSettings.managed.yaml`](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsSettings.managed.yaml)):
the whole DNS payload has `supervised: false` and `allowmanualinstall: true`.

### 1. NextDNS profile

1. Create an account at [my.nextdns.io](https://my.nextdns.io/) → new profile.
   Note the **profile ID**.
2. **Account → API → API key.** This is a secret; it goes into an environment
   variable.
3. In the profile enable logs (**Settings → Logs**) with retention ≥ 1 day.

### 2. DNS on each iPad — two options, pick one

**Option A: the NextDNS app (simplest)**

1. App Store → [NextDNS](https://apps.apple.com/us/app/nextdns/id1463342498) on the iPad.
2. Enter the profile ID.
3. **Enable sending the device name** — otherwise all iPads merge into one
   and kidwatch can't tell the children apart.
4. Give the device a unique name, e.g. `iPad-Child-1`. That name goes into
   `source_ids` in `config.yaml`.

**Option B: a `.mobileconfig` profile (no app)**

```bash
uv run python tools/gen_profile.py \
  --name "iPad Child 1" \
  --doh-url "https://dns.nextdns.io/YOUR_ID/iPad-Child-1" \
  --out child1.mobileconfig
```

**One file per iPad, each with a different URL suffix.** Devices are told
apart by the path in the DoH URL — a shared profile = one device in the logs.

Send the file to the iPad (AirDrop / mail), then **Settings → Profile
Downloaded → Install**.

### 3. Make removal harder (without supervision it can't be locked)

Screen Time **cannot** lock the DNS settings — it does not restrict access to
Settings → General, and VPN/DNS settings are not something parental controls
cover. What you can do:

- **Screen Time → Content & Privacy Restrictions → App Store → Deleting Apps:
  Don't Allow** (with option A this prevents deleting the NextDNS app);
- a Screen Time passcode the kids don't know;
- **keep the watchdog enabled** — it will report a removed profile.

### 4. ntfy on your iPhone

1. App Store → **ntfy**.
2. Subscribe to your topic.
3. The topic is passed in the `NTFY_TOPIC` variable, not in the file
   (`topic: ""` in `config.example.yaml`; without the variable the config does
   not validate). Generate a long one:
   `python3 -c "import secrets;print('kidwatch-'+secrets.token_hex(14))"`.
   **On ntfy.sh the topic name IS the password** — there is no access control;
   anyone who knows the name can read your notifications. A self-hosted ntfy
   server is better.

### 5. Run

```bash
cp config.example.yaml config.yaml    # set profile_id and device names
export NEXTDNS_API_KEY="..." NTFY_TOPIC="kidwatch-..."
uv sync
uv run python -m kidwatch test-notify  # test push
uv run python -m kidwatch run
```

### 6. Web panel (optional, locally)

The panel is disabled by default (`panel.enabled: false`, listens on
`127.0.0.1:8080`). It runs as a thread inside `run` and serves the built front
end from `panel.static_dir` (default `web/dist`):

```bash
(cd web && npm ci && npm run build)
uv run python -m kidwatch user-add <login>   # prints a random password ONCE
```

Then set `panel.enabled: true` in `config.yaml`. Session cookies are `Secure`
by default; set `panel.cookie_secure: false` only if you serve the panel over
plain `http://` on a host other than `localhost`. 2FA additionally requires
`PANEL_TOTP_KEY` (e.g. `openssl rand -base64 32`).

---

## Watchdog — the most important part without supervision

On an unsupervised iPad the child **can** turn DNS off. Their iPad then
disappears from the logs, which is **indistinguishable from "the iPad is lying
in a drawer"**. That is the worst possible silent failure: the service is
quiet and looks healthy.

That is why system noise is valuable here. An iPad queries Apple domains
non-stop, even while asleep. Silence **including noise** means one thing: we
have stopped seeing it.

Each layer guards against a different failure:

| layer | detects | reaction |
|---|---|---|
| `stream_silence_minutes` (20) | zero events from **all** devices — dead token, network, account | push `kidwatch nie widzi ruchu DNS` |
| `device_silence_minutes` (180) | silence of **one** iPad while others report — profile removed | push `<device> nie zglasza sie do DNS` |
| same threshold, device never seen | a configured device that has not appeared in DNS once since start — typo in `source_ids` or a profile that never worked | push `<device> nie pojawil sie w DNS` (at most once a day) |
| `livenessProbe` / `HEALTHCHECK` | the process **hung** — the watchdog can't report its own death, since the alert is sent by the same process | container restart (heartbeat file `KIDWATCH_HEARTBEAT`) |
| UniFi sensor (optional) | an iPad on home Wi-Fi transferred > `alarm_mb` (20) MB in `window_minutes` (15) while NextDNS has not a single query from it — DNS profile removed | push `<device> — profil DNS prawdopodobnie usunięty` |
| `tv.unreachable_alert_hours` (24) | TV without a single successful read for a day — tunnel, ADB, key | push `<TV> — odczyt z urzadzenia nie dziala` |
| `tv.traffic` (true), `tv.traffic_min_mb` (10), `tv.traffic_window_minutes` (3) | ADB not answering but UniFi sees the TV streaming — sessions continue from network traffic (no titles; service name from NextDNS if `tv.nextdns_ids` is set) | push `<TV> — ADB nie odpowiada, monitoring z ruchu sieci` after `tv.adb_alert_minutes` (30) |
| `tv.sony` (true), `TV_SONY_PSK` | Sony BRAVIA REST API on the TV host: power state without a key; with the pre-shared key also antenna (channel + EPG programme title) and HDMI input — sources ADB never saw | sessions `TVP1 HD: <programme> (Telewizja)`, `HDMI 2` |
| `tv.pilot` (true) | Google TV remote protocol v2 (the phone remote's channel, ports 6466/6467) — power and foreground app without ADB or developer options; paired once from the panel's TV card with the 6-character code shown on the TV | sessions named after the app (`YouTube`, `Disney+`) instead of `Streaming` |
| outbox | notifications no channel accepted for a day (see below) | push `kidwatch nie dostarczyl powiadomien` |

Repeated alerts go out at increasing intervals (20 → 40 → 80 min, capped at
8 h, `repeat_backoff_max_minutes`) so that one failure doesn't produce a dozen
pushes a day. Recovery is notified too (DNS and UniFi watchdogs). Each failure
is a separate episode — another one, even the same day, alerts again and gets
its own "back" message. Exception: the TV watchdog reports a missing read at
most once a day and sends no recovery message.

During quiet hours silence of a single iPad does not alert — it is allowed to
be off at night (`device_silence_ignore_quiet_hours`).

---

## How it works

```
NextDNS /logs/stream (SSE)  ─┐
                             ├─→ classifier ─→ engine ─→ gateway (WhatsApp / e-mail)
AdGuard /control/querylog   ─┘   (app_map)     (pure)    ntfy, Home Assistant
                                                  │
Google TV (ADB), UniFi ─────────────────────→  SQLite  ─→ web panel
                                     (sessions, cursor, dedup, outbox)
```

- **`sources/`** — a common interface for DNS sources (NextDNS, AdGuard).
  Alongside them, sensors: `tv.py` (Google TV over ADB), `unifi.py` (Wi-Fi
  presence) and `device.py` (reading the iPad over lockdown; disabled in the
  cluster). DNS sources reconnect on their own; a network error never aborts
  the loop.
- **`classifier.py`** — domain → noise / shared / app / unknown. **Longest
  match wins**, so the order in `app_map.yaml` doesn't matter. The file is
  hot-reloaded on mtime change; broken YAML keeps the old map.
- **`engine.py`** — all the rules. No network I/O, time comes from an injected
  clock — hence engine tests without a single `sleep`.
- **`store.py`** — SQLite. What must survive a restart: open sessions, keys of
  sent notifications (idempotency), the stream cursor and the outbox.
- **`scheduler.py`** — the tick loop: closing sessions, summaries, watchdog,
  cleanup, heartbeat.
- **`panel.py` / `panel_auth.py`** — the web panel's HTTP server (a thread in
  the `run` process, read-only connection to the main DB) and its login
  (Argon2id passwords, optional TOTP, separate `panel-auth.db`).
- **`gametime.py`, `tvpause.py`, `rollup.py`** — game time, TV pause and the
  daily aggregates.

### Noise neither wakes nor extends a session

If it did, a session would never end — an iPad queries Apple constantly. A
session ends at the last **non-system** activity.

### A restart doesn't duplicate pushes

Every notification has a `dedup_key` claimed atomically in SQLite. Processing
the same events again (e.g. after the stream resumes) sends nothing.

### A restart doesn't lose pushes

The loops don't send directly — they append the notification to the `outbox`
table in `kidwatch.db`, and a separate task sends them in order. A hanging
channel therefore doesn't hold up the tick or the heartbeat (liveness).

An entry leaves the queue **only once at least one channel has accepted it**
(the gateway answered 2xx). If none did — a gateway restart during a deploy,
a 502 from the mail provider — the entry stays and is retried after 30 s, 1,
2, 5, 10 min, then every 15 min; it also survives a kidwatch restart. Later
notifications wait behind it so that "session end" never arrives before
"start". After a day (or 100 attempts) the entry is dropped: a WARNING in the
log, "undelivered" in the panel history, and the watchdog alert
`kidwatch nie dostarczyl powiadomien` (at most once a day), which goes out
when the channel is back.

The price: if a channel accepts a push and the process dies before deleting
the entry, the same push arrives a second time after startup. Lost is worse
than duplicated.

### YouTube ads inside games

Games show video ads through Google IMA, which pulls clips from YouTube's
servers — to DNS that looks like YouTube was opened. YouTube traffic within
±60 s of a known ad network (Unity, AppLovin, ironSource, doubleclick, …)
during a game is counted as the game, with no "YouTube" push; a stretch of
YouTube longer than 2 min without the game is real viewing.

---

## Configuration

Everything lives in `config.yaml` (template: `config.example.yaml`; `--config`
or `KIDWATCH_CONFIG` selects the file). **Secrets come only from environment
variables:**

| variable | purpose | required |
|---|---|---|
| `NEXTDNS_API_KEY` | NextDNS API key (logs and game time) | with `source.kind: nextdns` |
| `ADGUARD_PASSWORD` | AdGuard Home password | with `source.kind: adguard` |
| `NTFY_TOPIC` | ntfy topic (the topic name is a password, so not in the file) | with ntfy enabled |
| `NTFY_TOKEN` | ntfy access token | no (public topics don't need it) |
| `HA_WEBHOOK_ID` | Home Assistant webhook | with HA enabled |
| `BRAMKA_KLUCZ` | the **sending** key for the RenaCode notification gateway (`notifiers.bramka`) | with the gateway enabled |
| `BRAMKA_KLUCZ_ADMIN` | gateway admin key — panel: WhatsApp linking, recipients, test message | no (without it the panel falls back to `BRAMKA_KLUCZ`, which only works with the old shared key) |
| `PANEL_TOTP_KEY` | encrypts the panel's 2FA secrets | no (without it 2FA can't be enabled) |
| `UNIFI_API_KEY` | local UniFi controller API | with `unifi.enabled` (without it the sensor doesn't start) |
| `KIDWATCH_STORE_PATH` | overrides `store.path` | no |

A missing secret produces a readable message and exit code **2**, not a
stack trace.

### Main thresholds

| key | default | meaning |
|---|---|---|
| `engine.idle_minutes` | 10 | this much silence = session end |
| `engine.app_cooldown_minutes` | 15 | unrecognised traffic: further domains batched every N minutes; a named app is reported once per session anyway (and in a new session not sooner than after this time) |
| `engine.confirm_minutes` / `confirm_moments` | 5 / 3 | session confirmation window and number of distinct moments (see below) |
| `engine.shared_extend_minutes` | 30 | how long `shared` traffic may extend a session |
| `engine.daily_summary_time` | 20:30 | daily summary |
| `engine.max_notifications_per_hour` | 12 | per device; the excess is aggregated |
| `engine.quiet_hours` | none (example config: 21:30–07:00) | no app pushes; session start with priority `session_start_priority` (5) |
| `engine.night` | = `quiet_hours` | night-alert window (`start`/`end`), `reminder_minutes: 30`, `enabled` |
| `engine.weekly_report` | Sunday 19:00 | `weekday` (0=Mon … 6=Sun), `time`, `enabled` |
| `store.retention_days` | 30 | older events are deleted (0 = never) |
| `store.notifications_retention_days` | 365 | notification history in the panel (0 = no limit) |
| `store.rollup_retention_days` | 0 | daily aggregates (0 = no limit) |

`engine.session_start_merge_seconds` and `engine.confirm_burst_events` are no
longer used (session confirmation replaced them); they are still accepted so
existing configs keep validating.

**Night and quiet hours are one push, not two.** A session starting in the
night window gets the night form (`🌙 <child> uzywa iPada w nocy — 23:12,
YouTube`, with `w domu` / `poza domem` when the UniFi sensor has a fresh
reading) instead of the `W CICHYCH GODZINACH` suffix. A session started in
the evening that continues into the night gets this push when activity shows
up at night; then a reminder every `reminder_minutes`.

**The weekly report** (automatic, Sunday 19:00) counts sessions from the
previous Sunday 19:00 to the current 19:00; the "exact" TV time (Android
counters) stays in the calendar week Mon–Sun. Run manually it covers a whole
ISO week (Mon–Sun, no 19:00 cut-off; without `--week`, on a Sunday the current
week, on other days the last full one), without claiming the dedup key:
`python -m kidwatch weekly [--week 2026-W40] [--dry-run]` (without
`--dry-run` it also sends through the channels).

**The hourly limit never throttles** session start and end, the watchdog,
night alerts, reports, game time or TV pause. Throttling "the iPad turned on
at 2 a.m." would defeat the purpose; session starts are inherently limited by
`idle_minutes`, so they can't cause an avalanche.

### "Background" sessions don't exist

An iPad lying on a desk still queries DNS: a YouTube background refresh, a
certificate OCSP check, a game notification. Each such query used to open a
"0 min" session with start and end pushes. Now a session is **confirmed** only
when, within the `engine.confirm_minutes` (5 min) window, activity (an app or
an unknown domain) has:

- at least `engine.confirm_moments` (3) **distinct moments** spanning one
  minute or more — a moment is all queries within 10 s of its first query, so
  a burst of a dozen queries in one second counts once;
- or a span of at least 3 minutes (a game that rarely talks to its own
  backend).

The start push then carries the actual start time. An unconfirmed session is
closed silently and kept in the database (`sessions.confirmed=0`) for
diagnostics only — it does not count toward summaries, reports, charts,
aggregates or the night alert.

Why moments rather than queries: a YouTube background refresh on an idle iPad
(production, 10.2026) is `youtubei.googleapis.com`, `redirector` and a few
`rr*.googlevideo.com` in the same second, sometimes one more `rr*` after 1–2
minutes — then silence. That's two moments, not three. Watching pulls
segments every dozen or so seconds and confirms after ~1 minute; a game with
traffic every 30–60 s after 1–2 minutes.

A 5-minute rather than 3-minute window: a game in play talks to its backend
every ~3–3.5 min (an Asphalt recording in `tests/fixtures/day.jsonl`), and
with 3 minutes a real half-hour session would never confirm.

### Panel accounts

Panel accounts are managed from the CLI (in the cluster via
`kubectl exec deploy/kidwatch -c kidwatch -- python -m kidwatch …`):

```bash
python -m kidwatch user-add <login> [--password-stdin]    # random password printed ONCE
python -m kidwatch user-reset <login> [--password-stdin]  # new password, unlock, log out everywhere
python -m kidwatch user-reset <login> --totp              # remove 2FA (lost phone)
python -m kidwatch user-del <login>
python -m kidwatch user-list
```

### Profile: password and WhatsApp

Avatar in the header → **Profil**: two-factor authentication, password change
(old + new, min. 12 characters; logs out other sessions) and **Powiadomienia /
WhatsApp**: gateway channel status, linking WhatsApp via QR (from WAHA,
refreshed every 20 s until `WORKING`; this is where the bot number is
connected), sending a test, disconnecting, and the list of **WhatsApp
recipients**. The panel calls the gateway server-side with
`BRAMKA_KLUCZ_ADMIN` (notifications are sent with the separate
`BRAMKA_KLUCZ`); the browser knows neither.

Recipients (at most 5): number with country code, label (≤ 40 characters),
a **"Dostaje"** (receives) column and an "active" switch. Changes are local
until you save the list — saving the **whole** list requires the password or
a 2FA code (the list is shared by all RenaCode apps, a session alone is not
enough). A wrong confirmation counts toward account lockout; an invalid list
(bad number, duplicate) is rejected earlier with 400, without checking the
password. The test button sends a WhatsApp-only test to active recipients
with "everything" routing and shows how many it reached (with the masked
number of anyone it didn't reach).

**"Dostaje"** is gateway routing: "Wszystko" (everything) — every RenaCode
app, kidwatch watchdog alerts and the test message; "Tylko kidwatch
(dzieci)" — regular kidwatch notifications **without** watchdog alerts
(kidwatch sends those with `kategoria: czujka`). A new row defaults to
kidwatch-only. An alert no one receives on WhatsApp goes by e-mail to the
gateway owner. With a gateway that predates routing the column shows
"wszystko" and saving doesn't send the routing field.

The gateway sends to all active recipients of a route at once; a partial
delivery is a success with no e-mail, an e-mail goes out only when nobody was
reached. Numbers are visible only to the logged-in account owner in the
profile; panel and gateway logs show only the last three digits. Endpoint:
`POST /api/profile/whatsapp/recipients`
`{"recipients": [{"number", "label", "active", "sources"?: ["*"] | ["kidwatch"]}], "confirm": "<password or code>"}`
(the old single-number `POST /api/profile/whatsapp/recipient` remains).
It requires a gateway with `POST /v1/whatsapp/odbiorcy` — with an older
gateway the profile shows its single recipient, but saving the list fails.

### Notification content

The daily summary, weekly report and session end are sections per child and
per TV, with bullet points; TV titles are shortened (without "| channel |
tags", at most 5, "+N more"). In WhatsApp section headers are bold (`*…*`);
in e-mail the gateway strips the asterisks. The panel receives the same data
in structured form (`notifications.data`) and draws lists with mini bars;
older entries are shown as text.

### Panel: tabs, trends, archive

Tabs: **Powiadomienia** (notification history), **Wszystkie ekrany**,
**Użycie** (daily usage chart), **Trendy**, **Dzień** (day view), with a
per-child switcher.

- **Wszystkie ekrany** (all screens) — iPads (minutes from DNS) and the TV
  (playback minutes, titles) on one daily timeline, with day and ISO-week
  totals. With a child selected, the TV is a separate greyed-out "TV
  (wspólny)" (shared) lane — it can be hidden and is **not** added to the
  child. Below, TV app time "exact, from the TV" (Android
  `dumpsys usagestats`, read every `tv.usage_poll_minutes`) next to the
  session estimate; the same time goes into the weekly report.
- **Trendy** — week over week and month over month per child (total, daily
  average, top apps, night minutes) and a 12-week chart.
- **Archive** — the `daily_rollup` table: one row per device per day
  (minutes, sessions, top apps, night minutes, TV minutes from usagestats).
  Recomputed every 15 min for today and yesterday, plus any day without an
  aggregate (the first start backfills all existing history). It outlives
  `store.retention_days`; its own retention is
  `store.rollup_retention_days` (0 = no limit, the default).
- **CSV export** — `GET /api/export.csv?from=YYYY-MM-DD&to=YYYY-MM-DD&child=`
  (logged in only; last 30 days by default, at most 3660). Daily aggregates,
  UTF-8 with BOM (for Excel), cells starting with `= + - @` prefixed with an
  apostrophe.

### Game time (NextDNS)

The iPad card in the panel has **Zablokuj gry / Odblokuj / +30 min** (block
games / unblock / +30 min) buttons. They toggle the services and categories
from `game_time` in NextDNS parental controls (`active: true/false`). Blocks
in NextDNS are a **profile** setting, so each child needs their own profile
(`devices[].nextdns_profile`; without it — the main profile). kidwatch then
reads the log streams of all profiles, each with its own cursor.

```yaml
game_time:
  enabled: true
  services: [youtube, roblox, minecraft, fortnite, tiktok, twitch]
  categories: [gaming]            # video-streaming also blocks Netflix and Disney+
  default_bonus_minutes: 30
  block_schedule: {start: "20:00", end: "07:00"}   # optional
```

- A click only **queues** the change (in `panel-auth.db`); it is executed by
  the service loop — the single writer of `kidwatch.db` — which also sends a
  push.
- A bonus counts from the end of the current bonus, capped at
  `max_bonus_minutes` (180); afterwards the loop restores the block.
- Every `sync_minutes` (5) the state is read from NextDNS. A change made by
  hand in my.nextdns.io is accepted; a failed kidwatch write is retried every
  minute.
- The schedule blocks at the start of the window and in the morning lifts
  **only its own** block — a manual block from the panel stays.
- A category id outside NextDNS's list (`dating, gambling, gaming, piracy,
  porn, social-networks, video-streaming`) is a config error. An unknown
  service id is only a log warning — NextDNS adds services, and an id it
  doesn't know will be rejected by the API itself (error in the panel and in
  the push).

### TV monitoring pause (trips)

When the kids are away and others watch TV at home, the TV card has a
**Wstrzymaj monitoring TV** (pause TV monitoring) button — until a date and
time (default: 7 days ahead) or until cancelled. While paused, the panel shows
a banner `Monitoring TV wstrzymany do …` with a **Wznów teraz** (resume now)
button. iPads keep being monitored as usual (NextDNS works away from home).

- A paused TV is **not polled at all** (neither the player nor usagestats):
  no sessions, pushes or TV minutes in daily and weekly totals. The "TV not
  responding" watchdog stays quiet and counts silence from the end of the
  pause. The first usagestats read after a pause only sets a baseline so
  paused time doesn't leak into "exact, from the TV".
- Viewing in progress when the pause starts ends silently at the last read.
- A low-priority push when enabled, when the end time changes and when the
  pause ends (`Monitoring TV wznowiony`).
- The daily summary and weekly report note "monitoring wstrzymany od … do …"
  in the TV section, and the all-screens timeline hatches that period.
- Like game time: a click (session + CSRF) only **queues** the change in
  `panel-auth.db` with the login; the loop tick executes it (within ~30 s).
  State and audit (who enabled it and when, who or what ended it) live in
  the `tv_pause` table in `kidwatch.db` and survive restarts.
- From the command line (queues the same job; the running `run` executes it):

  ```bash
  python -m kidwatch tv-pauza --do 2026-10-10T18:00   # pause until
  python -m kidwatch tv-pauza --do-odwolania          # pause until cancelled
  python -m kidwatch tv-pauza --wznow                 # resume now
  python -m kidwatch tv-pauza                         # show state
  ```

  A time without a zone is local time from `timezone`.

### Domain map

`app_map.yaml`, hot-reloaded — edit it locally without a restart. In the
cluster the file is mounted from a ConfigMap via `subPath`, which doesn't
update: a change rolls out through the `checksum/app-map` annotation, i.e. a
pod restart.

```yaml
noise:                    # never counts as activity
  - apple.com
  - apple                 # Apple has its own .apple gTLD and actually uses it
shared:                   # extends an open session, never opens or names one
  - cloudfront.net
apps:
  "Roblox":
    - roblox.com          # the domain and all subdomains
    - "*.rbxcdn.com"      # same thing, written for readability
  "Something":
    - "=only.example.com" # EXACTLY this domain, no subdomains
```

Noise wins on an identical pattern, but **the longer pattern wins** —
`music.apple.com` in `apps` beats `apple.com` in `noise`.

Non-system traffic with no match is recorded as **`Przegladarka / inne`**
(browser / other) — in the database, sessions and the panel. By default there
is **no** separate push for it (`engine.notify_unknown: false`): the first
live day showed it is almost entirely app backends (Google, analytics, ads),
not websites.

### What you can see of browsing

DNS knows the **domain**, never the page URL or content. That is the ceiling
of this method, and nothing raises it short of a proxy with its own CA (see
below).

Within that ceiling kidwatch names things instead of lumping them into
`Przegladarka / inne`:

```
[START]  <device> aktywny
         16:20 — super-gierka-online.com
[APKA]   <child>
         Przegladarka / inne: forum-o-grach.pl, wikipedia.org, jakas-gazeta.pl
[KONIEC] <device> — koniec
         15:12–15:59, 47 min
         Roblox ~26 min, Przegladarka / inne ~14 min
         strony: forum-o-grach.pl, wikipedia.org, jakas-gazeta.pl
         (czasy szacunkowe — liczba minut z ruchem DNS)
```

With `notify_unknown: true` a push goes out on the **first** unrecognised
domain, and further ones wait for `app_cooldown_minutes` and are batched —
otherwise every browser click would be a separate notification. Hosts of one
site are collapsed to one name (`a.shop.example`, `cdn1.shop.example` →
`shop.example`).

Domains report per child per day:

```bash
uv run python -m kidwatch web --days 7 [--device "<device>"] [--limit 25]
```

```
=== niedziela 27.09.2026 ===

<device> (<child>)
  aplikacje: YouTube ~37 min, Roblox ~36 min, Przegladarka / inne ~33 min
  strony (5 domen):
      10x  forum-o-grach.pl
      10x  super-gierka-online.com
       5x  wikipedia.org
```

Day names are hard-coded in Polish, not taken from `locale` — the container
has `C`, the terminal something else, and the report should look the same
everywhere.

### What you won't see, and why it isn't worth trying

Page URLs, content, messages, in-app history. The only way is a proxy with
its own CA installed on the iPad. Technically possible on the child's own
device, but: certificate pinning breaks a large share of apps, you also
intercept the children's passwords and private data, and the proxy becomes a
single point whose compromise gives away everything. Fragile and
disproportionate.

What DNS will never give you, however hard you try:

| need | only source |
|---|---|
| list of installed apps | USB cable + `ideviceinstaller`, or Settings → iPad Storage |
| subscriptions and in-game purchases | Apple receipts by e-mail, Settings → Subscriptions |
| **preventing** purchases | "Ask to Buy" in Family Sharing — beats any after-the-fact monitoring |
| exact per-app time, including offline | Screen Time (no public API) |
| games that work offline | nothing — they are invisible to DNS |

### Three sections, three behaviours — and why games forced them

| section | opens a session | extends an open one | names it |
|---|---|---|---|
| `noise` | no | **no** | no |
| `shared` | no | **yes**, within `shared_extend_minutes` | no |
| `apps` | yes | yes | yes |

`shared` exists because of games. Asphalt talks to `gameloft.com` once every
few minutes and to CloudFront constantly. If CDNs were noise, a gaming
session would be artificially short or never happen; if they were an app, an
ad fetched in the background would wake you up with a push at night.

Extension is **bounded** by `shared_extend_minutes` (default 30), counted
from the last **recognised** event. Without it background app refresh would
keep a session open forever and no duration would mean anything.

What `shared` deliberately does **not** contain: `akamaiedge.net` and
`akadns.net`. Games use them, but on an iPad they are dominated by Apple
background traffic — extending sessions with it would defeat the bound.

### Games are the hardest case

Games are detected worse than streaming, for three reasons:

1. **They play offline.** A game that doesn't hit the network is invisible to
   DNS. There's no way around it — only Screen Time shows it.
2. **They ride shared CDNs.** Netify shows Gameloft using `gameloft.com` plus
   Akamai, CloudFront, AWS and Cloudflare. Only the first can be attributed.
3. **Publishers change backends.** Any domain list written up front rots.

Hence a command that closes the gap from **real** data:

```bash
uv run python -m kidwatch domains --unknown-only [--days 7] [--limit 40]
```

```
domena                                 kategoria   zapytan  hostow  aplikacja
----------------------------------------------------------------------------
super-gierka-online.com                unknown          10       2
forum-o-grach.pl                       unknown          10       1
```

Add the top of this list to `app_map.yaml` — the file hot-reloads, no
restart needed. It is the only reliable way to get good game coverage.

### Other CLI commands

| command | what it does |
|---|---|
| `run` | the service: listen to sources, send notifications, serve the panel |
| `test-notify` | send a test push through the enabled channels |
| `summary [--date YYYY-MM-DD]` | print the daily summary (doesn't claim the dedup key) |
| `weekly [--week YYYY-Www] [--dry-run]` | weekly report (see above) |
| `domains`, `web` | domain reports (see above) |
| `replay <file.jsonl> [--dry-run]` | replay a recorded day against an in-memory DB |
| `tv [--raw]` | one-off TV read over ADB (checks key and tunnel) |
| `tv-pauza` | TV monitoring pause (see above) |
| `unifi [--fingerprint]` | who is on home Wi-Fi per UniFi; `--fingerprint` prints the controller's SHA-256 certificate fingerprint for `unifi.cert_sha256` |
| `device`, `device-watch` | one-off / looping read of iPad state over lockdown (`device_read`, requires pairing and the same LAN) |
| `user-add`, `user-reset`, `user-del`, `user-list` | panel accounts |

Global options: `--config <path>` (default `$KIDWATCH_CONFIG` or
`config.yaml`), `-v/--verbose`.

---

## Deployment

### k3s + Argo CD

Helm chart in `charts/kidwatch`. The author's Argo CD application lives in a
private infrastructure repo. Deploying without that infrastructure (your own
image, ntfy instead of the gateway, your own domain) is described in
[`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md), section
"Bez infrastruktury RenaCode". Argo CD watches `charts/kidwatch/values.yaml`,
and CI (`.github/workflows/docker-publish.yml`) runs tests, ruff, the front-end
tests/build and `helm lint`, then builds the image to GHCR and bumps its tag in
that file on every push to `main`. There is no SSH or `kubectl apply`.

The GHCR image is private: the chart expects an `imagePullSecrets` entry
`ghcr-pull` (set `imagePullSecrets: []` and your own `image.repository` when
building your own image).

Secrets are created **once, by hand** — Argo CD doesn't sync them. Commands
are in [`docs/uruchomienie-od-zera.md`](docs/uruchomienie-od-zera.md) (step 7):

| Secret | contents | required |
|---|---|---|
| `kidwatch-secrets` | `NEXTDNS_API_KEY`, `BRAMKA_KLUCZ`, `BRAMKA_KLUCZ_ADMIN`, `PANEL_TOTP_KEY`, optionally `UNIFI_API_KEY` (or `NTFY_TOPIC` instead of the gateway keys) | yes |
| `kidwatch-config` | the real `config.yaml` (uploaded by `tools/wgraj_konfiguracje.sh`) | yes |
| `kidwatch-adb` | `adbkey`, `adbkey.pub` accepted by the TV | with the TV sensor |
| `kidwatch-pairing` | pairing records `<UDID>.plist` | no (mounted only with `deviceRead.enabled: true`; disabled in the cluster) |

A pairing record contains the **host's private key** — whoever has it is a
trusted computer for the iPad. `.gitignore` blocks `*.plist` so it can't land
in the repo.

Things worth knowing:

- **`replicaCount: 1` + `strategy: Recreate` are a correctness requirement.**
  SQLite has one writer; two pods would diverge session state and duplicate
  pushes. For the same reason the panel runs as a thread in the same process,
  not in a separate pod.
- **Disable pruning in the Argo CD application.** The database PVC has
  `helm.sh/resource-policy: keep`; automatic deletion could remove the volume
  with its state, and then the service would send every push again.
- **`Synced` doesn't mean "the process reads the new config".** The pod has a
  `checksum/config` annotation over `files/config.yaml`, but the real config
  is in the `kidwatch-config` Secret, which the checksum doesn't cover — after
  changing it, `tools/wgraj_konfiguracje.sh` validates the file locally,
  uploads it and restarts the pod.
- **`charts/kidwatch/files/app_map.yaml` is a copy** of the root file (a chart
  can't reach outside its directory). After changing the map:
  `cp app_map.yaml charts/kidwatch/files/app_map.yaml`. `tests/test_deploy.py`
  catches drift.
- **NetworkPolicy** (`networkPolicy.enabled`, on by default): ingress only
  from Traefik to the panel port; optional egress restriction to the home
  network (`networkPolicy.egress.siecDomowa` / `wDomu`, empty in the public
  repo and injected by the deployment).
- **Ingress** uses Traefik with per-client rate limits (`ingress.limity`,
  requires the `traefik.io/v1alpha1` CRDs) and optional alias hosts that
  301-redirect to the main host (`ingress.aliasy`).

### Tailscale — disabled

The chart has a Tailscale sidecar (`tailscale.enabled`, default `false`) left
over from when iPad reads were meant to go over a tailnet. Verified
2026-10-02: iOS accepts lockdown (port 62078) only from the same local
network, so neither Tailscale nor a WireGuard tunnel home works
(`ConnectionResetError`). Tailscale is not deployed and not needed. The pod
reaches the TV and UniFi through a VPS ↔ home WireGuard tunnel
(`docs/uruchomienie-od-zera.md`, step 4).

### docker compose

```bash
cp config.example.yaml config.yaml
printf 'NEXTDNS_API_KEY=...\nNTFY_TOPIC=...\n' > .env     # .env is in .gitignore
docker compose up -d --build
```

The databases (`kidwatch.db`, `panel-auth.db`) live on the `kidwatch-data`
volume under `/data` — `docker-compose.yml` sets `KIDWATCH_STORE_PATH`, which
overrides `store.path` from the config. `app_map.yaml` is mounted from the
host, so the map can be edited without restarting the container. The image
includes the built panel at `/app/web`; to use it set `panel.enabled: true`,
`panel.host: 0.0.0.0`, `panel.static_dir: /app/web` and publish the port.

---

## Profile: regular vs supervised

Verified against Apple's schema. Which networks a DNS profile applies to
depends **only** on how it is installed:

| method | network scope |
|---|---|
| **local install** (manual, Apple Configurator) | **all** ✅ |
| **supervised** (MDM, supervised device) | **all** ✅ |
| **device enrollment** (MDM without supervision) | managed networks only ❌ |

Source: [`network.dns-settings.yaml`](https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/network.dns-settings.yaml)
(lines 242–249) and the note in `com.apple.dnsSettings.managed.yaml`
(257–259).

**Conclusion: don't set up an MDM organisation.** Apple Business Manager
requires a legal entity and a D-U-N-S number, and MDM without supervision
gives **worse** network coverage than a manually installed profile.
Supervision (Apple Configurator, cable, **wiping the iPad**) is the only thing
that adds real locks.

With `--supervised` the generator adds keys that **work only on a supervised
device** — on a regular iPad iOS ignores them:

| key | since | blocks |
|---|---|---|
| `ProhibitDisablement` | iOS 14 | turning DNS off in Settings |
| `PayloadRemovalDisallowed` | iOS 6 | removing the profile |
| `allowCloudPrivateRelay: false` | iOS 15 | Private Relay bypassing DNS |
| `allowVPNCreation: false` | iOS 11 | a free VPN from the App Store |
| `allowUIConfigurationProfileInstallation: false` | iOS 6 | the child's own profile |

That is why **the default mode doesn't add them**. A key that does nothing
would give an illusion of protection — and nothing is worse here than a false
sense of visibility.

Other generator options: `--org` (organisation name in the profile).

### Note for the future: the payload is `deprecated`

`com.apple.dnsSettings.managed` is marked **deprecated as of OS 27**. Its
successor is the DDM declaration `com.apple.configuration.network.dns-settings`
(introduced in 27.0), delivered by an MDM server. *Deprecated* doesn't mean
*removed* — the old payload works. The `--also-declaration` flag writes a JSON
file with the DDM declaration next to the profile, ready for when that
changes.

---

## Development

```bash
uv sync
uv run pytest              # the only tests that open a socket are in test_integration_live_http.py
uv run ruff check .
(cd web && npm ci && npm test && npm run build)
```

Replay a realistic day and compare with the snapshot:

```bash
uv run python -m kidwatch --config tests/fixtures/config.yaml \
  replay tests/fixtures/day.jsonl --dry-run
```

### Validating the profile against Apple's schema

`plutil -lint` checks **only plist syntax**. A key with a wrong name, in the
wrong place in the tree or of the wrong type passes lint without a blink, and
iOS **silently ignores it** — the profile installs "fine", it just doesn't do
what it promises. For a profile whose whole job is blocking DNS bypasses,
that is the worst possible failure mode.

Proof: a profile with the typo `allowVPNCreaton` (instead of
`allowVPNCreation`) passes `plutil -lint` as **OK**.

`tests/test_profile_schema.py` validates every emitted key against Apple's
official schema — name, type, allowed values, nesting level and supervision
requirement. The list of keys requiring supervision is **derived from the
schema**, not written from memory. The index is generated from
[apple/device-management](https://github.com/apple/device-management):

```bash
uv run python tools/fetch_apple_schema.py   # refreshes tools/apple_schema_index.json
```

This test caught a real bug: `ProhibitDisablement` was being placed inside
`DNSSettings`, while according to the schema it is its **sibling** at the
payload level. In the wrong place iOS ignores it, so `--supervised` mode
promised a lock that wasn't there.

### Can't be tested with a virtual iPad

It can't. Apple doesn't allow iPadOS virtualisation, so Parallels is
irrelevant, and the Xcode iOS simulator **has no mechanism for installing a
configuration profile** — `xcrun simctl` has no such subcommand (the
`--profiles` flag concerns CoreSimulator device-type profiles, not
`.mobileconfig`).

The profile can be checked on a real Apple system in a **macOS** VM — the
`com.apple.dnsSettings.managed` payload supports macOS 11.0+ — but that
verifies macOS, not iPadOS. Beyond that there is schema validation (above)
and installing on a real iPad, which is reversible.

### Integration tests on a real socket

The rest of the tests run on `httpx.MockTransport`, a fake transport — no
socket is opened. That doesn't prove that after an **actual TCP disconnect**
the source resumes the stream from the right cursor.

`tests/test_integration_live_http.py` starts two real HTTP/1.1 servers on
ephemeral loopback ports and drives the full path: socket → SSE → parser →
engine → HTTP POST → receiver. The NextDNS server **disconnects mid-stream**,
and the test checks that the reconnect comes with `?id=evt-1`.

`replay` **never touches the real database** (it uses `:memory:`) —
otherwise a test run would claim dedup keys and block real notifications.

To change the day scenario: edit `tools/gen_fixture_day.py`, then regenerate
the fixture and snapshot (commands in its docstring).

### A decision that departs from the obvious

**ntfy gets JSON, not HTTP headers.** Headers don't carry UTF-8 — httpx
encodes them with the `ascii` codec, so a title with a Polish character blows
up the whole send with `UnicodeEncodeError`. Children's names are exactly the
strings that go into the title. The test
`test_naglowki_http_naprawde_nie_przenosza_polskich_znakow` pins down the
reason.

---

## Privacy

DNS logs show what a device connects to. This is data about children — keep
it to yourself, on your own NextDNS profile and your own ntfy server, and
don't give access to anyone who doesn't need it. Kids should know their iPads
have a DNS filter; kidwatch is not a tool for hiding supervision.

## License

MIT — see [LICENSE](LICENSE).
