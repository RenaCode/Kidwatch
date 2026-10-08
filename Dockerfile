# syntax=docker/dockerfile:1
# Front panelu WWW. Ta sama baza co web.Dockerfile w Trader-AI (pin po digescie).
# node:20-alpine, odczytane z registry-1.docker.io 2026-09-23.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Obraz uv istnieje TYLKO pod ruchomym tagiem python3.12-bookworm-slim —
# warianty z numerem wersji uv w tym schemacie nazw nie istnieja (sprawdzone
# w rejestrze: 0.12.18-python3.12-bookworm-slim zwraca 404). Dlatego pin po
# digescie: to jedyny sposob na powtarzalny build.
# Odswiezenie:
#   docker buildx imagetools inspect ghcr.io/astral-sh/uv:python3.12-bookworm-slim
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Zaleznosci osobna warstwa, zeby zmiana kodu nie unieważniała cache.
# --frozen: buduj DOKLADNIE to, co w uv.lock; bez cichego rozjazdu wersji
# miedzy maszyna deweloperska a obrazem.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


FROM python:3.12-slim-bookworm

# tini: bez niego PID 1 nie przekazuje SIGTERM i kontener konczy sie dopiero
# po wywlaszczeniu, gubiac otwarta transakcje SQLite.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Serwis nie potrzebuje roota. UID na sztywno, zeby zgadzal sie z fsGroup w k8s.
RUN groupadd --gid 10001 kidwatch \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin kidwatch

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KIDWATCH_CONFIG=/config/config.yaml

COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 src ./src
COPY --chown=10001:10001 app_map.yaml ./app_map.yaml
# Zbudowany front panelu — serwuje go watek panelu z procesu `run`.
COPY --from=web --chown=10001:10001 /web/dist ./web
# Aplikacja Kidwatch TV (APK z joba `tv-app` w CI) - panel instaluje ja
# na telewizor przez ADB (sources/tv_app.py). Lokalnie katalog bez APK.
COPY --chown=10001:10001 tv-app/dist ./tv-app

# Katalog na baze — w k8s montowany jako PVC.
RUN mkdir -p /data && chown 10001:10001 /data
VOLUME ["/data"]

USER 10001:10001

# Ten sam plik tetna czyta sonda liveness w k8s (deploy/k8s/deployment.yaml).
# Proces, ktory zawisl, nie wysle alarmu o sobie samym — musi go zauwazyc
# warstwa nizej.
ENV KIDWATCH_HEARTBEAT=/tmp/kidwatch-heartbeat
HEALTHCHECK --interval=60s --timeout=5s --start-period=90s --retries=3 \
    CMD python -c "import os,sys,time; p=os.environ['KIDWATCH_HEARTBEAT']; \
sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 180 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "python", "-m", "kidwatch"]
CMD ["run"]
