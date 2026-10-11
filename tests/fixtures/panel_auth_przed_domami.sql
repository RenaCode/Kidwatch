-- panel-auth.db SPRZED domow (main 13c3a8e, po #44 i #45): schemat przepisany
-- recznie i zamrozony, z syntetycznymi kontami. Test migracji do Domu 1
-- (tests/test_domy.py) startuje z tego pliku, a nie ze schematu biezacego
-- kodu — inaczej migracja sprawdzalaby sama siebie.
-- Dane wylacznie generyczne (publiczne repo): loginy konto-*, dzieci
-- "Dziecko 1/2", hashe hasel to atrapy.

CREATE TABLE users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    login            TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    failed_logins    INTEGER NOT NULL DEFAULT 0,
    locked_until     REAL,
    created_at       REAL NOT NULL,
    last_login_at    REAL,
    totp_secret_enc  BLOB,
    totp_confirmed_at REAL,
    totp_last_step   INTEGER,
    rola             TEXT NOT NULL DEFAULT 'wlasciciel'
);

CREATE TABLE user_uprawnienia (
    user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    uprawnienie TEXT NOT NULL,
    nadane      INTEGER NOT NULL,
    PRIMARY KEY (user_id, uprawnienie)
);

CREATE TABLE login_failures (
    login        TEXT NOT NULL,
    ip           TEXT NOT NULL,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (login, ip)
);

CREATE TABLE ip_failures (
    ip           TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    updated_at   REAL NOT NULL
);

CREATE TABLE tickets (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    failed     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   REAL
);
CREATE INDEX ix_backup_codes_user ON backup_codes (user_id);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    kind       TEXT
);
CREATE INDEX ix_sessions_user ON sessions (user_id);
CREATE INDEX ix_sessions_expires ON sessions (expires_at);

CREATE TABLE game_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    child      TEXT NOT NULL,
    action     TEXT NOT NULL,
    minutes    INTEGER,
    login      TEXT,
    created_at REAL NOT NULL,
    done_at    REAL,
    ok         INTEGER,
    error      TEXT
);
CREATE INDEX ix_game_requests_open ON game_requests (done_at, id);

CREATE TABLE tv_pause_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    until      TEXT,
    login      TEXT,
    created_at REAL NOT NULL,
    done_at    REAL,
    ok         INTEGER,
    error      TEXT
);

CREATE TABLE user_powiadomienia (
    user_id      INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    whatsapp     TEXT,
    email        TEXT,
    kanal        TEXT NOT NULL DEFAULT 'auto',
    kategorie    TEXT,
    cisza_od     TEXT,
    cisza_do     TEXT,
    cisza_alarmy INTEGER NOT NULL DEFAULT 1,
    dzieci       TEXT,
    aktywne      INTEGER NOT NULL DEFAULT 1,
    updated_at   REAL NOT NULL
);

CREATE TABLE powiadomienia_ustawienia (
    klucz   TEXT PRIMARY KEY,
    wartosc TEXT NOT NULL
);

-- Konta: dwoch wlascicieli (jeden z odebranym uprawnieniem), podglad
-- z nadaniem. Konto 2 ma sesje — po migracji ma byc nadal zalogowane.
INSERT INTO users (id, login, password_hash, created_at, rola) VALUES
    (1, 'konto-a', 'atrapa', 1759000000, 'wlasciciel'),
    (2, 'konto-b', 'atrapa', 1759000100, 'podglad'),
    (3, 'konto-c', 'atrapa', 1759000200, 'wlasciciel');
INSERT INTO user_uprawnienia (user_id, uprawnienie, nadane) VALUES
    (2, 'tv.pauza', 1),
    (3, 'mdm.komendy', 0);
INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, kind) VALUES
    ('a1', 2, 'c1', 1759000300, 4102444800, NULL);

-- Kolejki: jedno zadanie wykonane, po jednym oczekujacym.
INSERT INTO game_requests (child, action, minutes, login, created_at, done_at, ok) VALUES
    ('Dziecko 1', 'block', NULL, 'konto-a', 1759000400, 1759000401, 1),
    ('Dziecko 2', 'bonus', 30, 'konto-a', 1759000500, NULL, NULL);
INSERT INTO tv_pause_requests (action, until, login, created_at) VALUES
    ('pause', NULL, 'konto-a', 1759000600);

INSERT INTO user_powiadomienia (user_id, kanal, kategorie, updated_at) VALUES
    (2, 'auto', '["sesje"]', 1759000700);
INSERT INTO powiadomienia_ustawienia (klucz, wartosc) VALUES ('tryb', 'trasy');
