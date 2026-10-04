"""Logowanie do panelu WWW: konta, hasla, opcjonalny drugi skladnik, sesje.

Ten sam model co w Trader-AI (services/api/security.py, routers/auth.py):
  - haslo Argon2id, parametry jak w Traderze;
  - drugi skladnik TOTP (pyotp) OPCJONALNY: wlacza go sam uzytkownik
    z zalogowanej sesji, wylacza haslem i kodem albo administrator z CLI
    (`user-reset --totp`). Sekret w bazie zaszyfrowany AES-GCM kluczem
    z Sekretu k8s (PANEL_TOTP_KEY), ochrona przed powtorzeniem kodu;
  - kody zapasowe, jednorazowe, w bazie wylacznie ich SHA-256;
  - sesja serwerowa, w bazie wylacznie SHA-256 tokenu — wyciek pliku bazy nie
    pozwala podszyc sie pod nikogo;
  - NOWA sesja przy kazdym logowaniu (session fixation);
  - token CSRF zwiazany z sesja, odsylany w naglowku przy kazdym POST;
  - blokada konta po MAX_FAILED nieudanych probach (haslo i kody razem).

PRZEPLYW. Konto bez TOTP: haslo -> sesja. Konto z TOTP: haslo -> krotkotrwaly
bilet, ktory sam niczego nie otwiera -> /api/auth/mfa z kodem -> sesja.
Dokladnie jak w Traderze.

DLACZEGO OSOBNA BAZA, A NIE TABELE W kidwatch.db

Panel czyta kidwatch.db w trybie `mode=ro`, a petla glowna jest jej jedynym
pisarzem — na tym stoi poprawnosc sesji i dedupu (store.py). Logowanie musi
jednak PISAC: licznik nieudanych prob, bilety, sesje, zuzyte kody. Zapis do
kidwatch.db z watku panelu zlamalby te zasade i dzielil blokade pliku
z petla glowna, wiec kazde logowanie mogloby opoznic tik silnika. Osobny
plik (domyslnie /data/panel-auth.db, ten sam wolumen) ma dwoch pisarzy, ale
obaj sa niegrozni: watek panelu i jednorazowe `kidwatch user-add` przez
`kubectl exec`. Zwykla blokada pliku SQLite w zupelnosci to obsluguje.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import logging
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

# Parametry Argon2id jak w Traderze (64 MiB / t=3 / p=4, powyzej minimum OWASP).
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

#: Ile weryfikacji hasla moze trwac naraz. JEDNA, i to nie z ostroznosci:
#: kazda zajmuje 64 MiB, a pod ma limit 384 Mi. Kilkanascie rownoleglych prob
#: logowania (ThreadingHTTPServer daje watek na zadanie) zabiloby proces OOM-em
#: razem z petla powiadomien. Przy okazji serializuje to sprawdzenie blokady
#: z zapisem licznika — rownolegle zgadywanie nie przeskoczy progu.
_verify_slot = threading.BoundedSemaphore(1)
#: Dluzej niz tyle nie czekamy na wolny slot — kolejka zadan zatrzymanych na
#: semaforze to tez watki i pamiec.
VERIFY_WAIT_SECONDS = 5.0

MAX_FAILED = 5
LOCKOUT_SECONDS = 15 * 60

#: Limit per SAM adres, niezalezny od loginu (audyt 3, S1). Licznik (login,
#: adres) omija sie, losujac login przy kazdej probie. Wyzej niz MAX_FAILED:
#: z jednego adresu (dom, NAT operatora) logowac moze sie kilka osob, a rodzic
#: myli sie w roznych loginach. Przerwa dluzsza niz okno zaczyna liczenie od
#: nowa — pomylki rozlozone na dni nie blokuja domowego adresu.
IP_MAX_FAILED = 20
IP_WINDOW_SECONDS = 15 * 60
#: Ile logowan z JEDNEGO adresu moze naraz czekac na slot Argon2 albo go
#: trzymac. Bez tego kilka rownoleglych POST-ow z jednego adresu trzymalo
#: slot bez przerwy, a rodzic dostawal 503. Nadmiar dostaje 429 od razu,
#: zanim zajmie watek na VERIFY_WAIT_SECONDS.
MAX_INFLIGHT_PER_IP = 1
_inflight: dict[str, int] = {}
_inflight_lock = threading.Lock()
MIN_PASSWORD_LEN = 12

#: Bilet miedzy haslem a kodem — jak w Traderze.
MFA_TICKET_SECONDS = 5 * 60
#: Jak dlugo po udanym `reauth` sesja moze pobierac QR bota WhatsApp
#: (przeglad 04.10, K-1). Skan to przeplyw interaktywny: rodzic klika
#: "Polacz", podaje haslo i w ciagu minuty skanuje kod.
REAUTH_FRESH_SECONDS = 5 * 60
#: Ile bledych kodow wytrzymuje JEDEN bilet. Nizej niz MAX_FAILED celowo, jak
#: w Traderze: bilet to jedno podejscie, nie budzet prob na konto.
MAX_FAILED_PER_TICKET = 3

TOTP_STEP = 30
TOTP_WINDOW = 1  # tolerancja rozjazdu zegara: jeden krok w kazda strone
TOTP_ISSUER = "Kidwatch"

#: 8, nie 10 jak w Traderze — wystarcza na lata przy jednym rodzicu, a krotsza
#: lista czesciej faktycznie trafia do menedzera hasel zamiast na kartke.
BACKUP_CODES = 8

TOTP_KEY_ENV = "PANEL_TOTP_KEY"

SESSION_COOKIE = "kidwatch_session"
CSRF_COOKIE = "kidwatch_csrf"
CSRF_HEADER = "X-CSRF-Token"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    login            TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    failed_logins    INTEGER NOT NULL DEFAULT 0,
    -- Unix time; NULL = nie zablokowane.
    locked_until     REAL,
    created_at       REAL NOT NULL,
    last_login_at    REAL,
    -- Sekret TOTP zaszyfrowany AES-GCM (nonce + szyfrogram). Aktywny dopiero
    -- z totp_confirmed_at — sam wygenerowany sekret niczego nie wlacza.
    totp_secret_enc  BLOB,
    totp_confirmed_at REAL,
    -- Ostatni zaakceptowany krok czasowy (RFC 6238 §5.2): kod z krokiem nie
    -- wiekszym jest odrzucany, choc sam w sobie poprawny.
    totp_last_step   INTEGER
);

-- Nieudane hasla przy logowaniu, per (login, adres). Per adres, nie per
-- konto: blokada konta z zewnatrz (5 prob co 15 min) zamykala rodzica poza
-- panelem na stale. Takze dla loginow, ktorych nie ma — inaczej 429 tylko
-- dla istniejacych zdradzaloby, ktore konta istnieja.
CREATE TABLE IF NOT EXISTS login_failures (
    login        TEXT NOT NULL,
    ip           TEXT NOT NULL,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (login, ip)
);

-- Nieudane hasla per SAM adres, bez wzgledu na login (IP_MAX_FAILED).
CREATE TABLE IF NOT EXISTS ip_failures (
    ip           TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    updated_at   REAL NOT NULL
);

-- Bilet miedzy haslem a drugim skladnikiem. Jak sesja: w bazie tylko hash.
CREATE TABLE IF NOT EXISTS tickets (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    failed     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   REAL
);
CREATE INDEX IF NOT EXISTS ix_backup_codes_user ON backup_codes (user_id);

-- token_hash to SHA-256 tokenu z ciasteczka. Sam token nigdzie nie lezy.
-- csrf jest w jawnej postaci, bo i tak trafia do czytelnego ciasteczka; sam
-- w sobie nic nie otwiera, wazny jest tylko w parze z sesja.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions (expires_at);
"""


class AuthError(Exception):
    """Odmowa z kodem HTTP i komunikatem dla uzytkownika."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class UserExists(ValueError):
    pass


class UnknownUser(LookupError):
    pass


@dataclass(frozen=True)
class Session:
    login: str
    user_id: int
    token_hash: str
    csrf: str
    expires_at: float


# ======================================================================= hasla
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _verify(stored_hash: str, password: str) -> tuple[bool, str | None]:
    """(czy_poprawne, nowy_hash_albo_None) — nowy, gdy zmienily sie parametry."""
    try:
        _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, None
    if _hasher.check_needs_rehash(stored_hash):
        return True, _hasher.hash(password)
    return True, None


# Hash-wydmuszka do weryfikacji przy nieistniejacym loginie. Liczony leniwie,
# bo kosztuje tyle co jedno logowanie, a import modulu ma byc tani.
_dummy_hash: str | None = None


def _dummy() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(16))
    return _dummy_hash


def generate_password() -> str:
    """~144 bity losowosci, bez znakow mylacych przy przepisywaniu z terminala."""
    return secrets.token_urlsafe(18)


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"haslo musi miec co najmniej {MIN_PASSWORD_LEN} znakow")


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ===================================================================== TOTP
class SecretBox:
    """AES-GCM na kluczu z PANEL_TOTP_KEY (32 bajty w base64), jak w Traderze.

    Nonce losowy per zapis, doklejany przed szyfrogramem. Jako dane powiazane
    (AAD) idzie id uzytkownika: szyfrogram przeniesiony do cudzego wiersza sie
    nie odszyfruje, wiec podmiana sekretow miedzy kontami w pliku bazy nic
    nie daje.

    Bez rotacji kluczy (Trader ma SECRETS_KEY_OLD): utrata albo zmiana klucza
    kosztuje tu tyle, co `user-reset <login> --totp` i ponowne zeskanowanie
    kodu — przy jednym, dwoch kontach taniej niz kod do rotacji.
    """

    def __init__(self, key_b64: str) -> None:
        try:
            key = base64.b64decode(key_b64, validate=True)
        except ValueError as exc:
            raise ValueError(f"{TOTP_KEY_ENV} nie jest poprawnym base64") from exc
        if len(key) != 32:
            raise ValueError(f"{TOTP_KEY_ENV} musi miec 32 bajty (openssl rand -base64 32)")
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: str, user_id: int) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext.encode(), _aad(user_id))

    def decrypt(self, blob: bytes, user_id: int) -> str:
        return self._aes.decrypt(blob[:12], blob[12:], _aad(user_id)).decode()


def _aad(user_id: int) -> bytes:
    return f"kidwatch-totp:{user_id}".encode()


def _decrypt(box: SecretBox, blob: bytes, user_id: int, login: str) -> str:
    try:
        return box.decrypt(blob, user_id)
    except InvalidTag as exc:
        # Klucz w Sekrecie inny niz ten, ktorym zaszyfrowano. Bez tego byloby
        # 500 bez slowa wyjasnienia.
        log.error("panel: sekret TOTP %r nie odszyfrowuje sie — zmieniony %s?",
                  login, TOTP_KEY_ENV)
        raise AuthError(
            503, "Nie da się odczytać drugiego składnika. Administrator musi wykonać "
            "user-reset --totp."
        ) from exc


def totp_uri(secret: str, login: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=login, issuer_name=TOTP_ISSUER)


def qr_png_base64(data: str) -> str:
    """Kod QR liczony LOKALNIE, jak w Traderze. Zadnej zewnetrznej uslugi:
    URI zawiera sekret, a wyslanie go do generatora QR w sieci oddaloby drugi
    skladnik obcemu serwerowi."""
    import qrcode  # noqa: PLC0415 — Pillow laduje sie tylko przy konfiguracji 2FA

    buf = io.BytesIO()
    qrcode.make(data).save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def verify_totp(secret: str, code: str, now: float, last_step: int | None) -> int | None:
    """Numer zaakceptowanego kroku czasowego albo None. Kopia logiki z Tradera.

    Kod jest wazny w oknie +-1 kroku, ale tylko RAZ: krok nie wiekszy niz
    ostatnio zaakceptowany jest odrzucany (RFC 6238 §5.2). Bez tego kod
    przechwycony raz dawal sie uzyc ponownie przez ~90 s.
    """
    # isascii: isdigit() przepuszcza cyfry arabskie itp., a compare_digest
    # rzuca na nich TypeError — 500 zamiast "zly kod" i bez licznika prob.
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = int(now) // TOTP_STEP
    for offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        step = current + offset
        if hmac.compare_digest(totp.at(step * TOTP_STEP), code):
            if last_step is not None and step <= last_step:
                return None  # kod juz zuzyty
            return step
    return None


def _normalize_code(code: str) -> str:
    return code.strip().replace(" ", "").replace("-", "").lower()


def new_backup_codes() -> list[str]:
    """xxxx-xxxx-xxxx (48 bitow) — jak w Traderze."""
    return ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(BACKUP_CODES)]


def backup_code_hash(code: str) -> str:
    # SHA-256, nie Argon2: kod ma 48 bitow losowosci, a nie jest haslem
    # wymyslonym przez czlowieka — slownik na niego nie dziala.
    return hashlib.sha256(_normalize_code(code).encode()).hexdigest()


# ======================================================================= baza
@dataclass(frozen=True)
class LoginResult:
    """Wynik poprawnego hasla: sesja (konto bez TOTP) albo bilet do /mfa."""

    token: str | None = None
    session: Session | None = None
    challenge: str | None = None

    @property
    def mfa_required(self) -> bool:
        return self.challenge is not None


class PanelAuth:
    """Konta, bilety i sesje panelu w osobnym pliku SQLite.

    Kazda operacja otwiera WLASNE polaczenie: ThreadingHTTPServer obsluguje
    zadania w roznych watkach, a polaczenie sqlite3 nie jest wspoldzielone
    miedzy watkami. Ruch jest znikomy, wiec koszt otwarcia nie ma znaczenia.

    `box` = None znaczy brak klucza PANEL_TOTP_KEY. Logowanie samym haslem
    dziala dalej, nie da sie tylko WLACZYC drugiego skladnika. Konto, ktore
    ma go juz wlaczonego, bez klucza sie nie zaloguje — wylaczenie 2FA po
    cichu, bo zniknal klucz, byloby gorsze niz odmowa.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        box: SecretBox | None = None,
        session_seconds: float = 7 * 24 * 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = str(path)
        self.box = box
        self.session_seconds = session_seconds
        self.clock = clock
        # token_hash -> czas ostatniego udanego reauth. W pamieci celowo: po
        # restarcie poda rodzic potwierdza tozsamosc jeszcze raz, a QR i tak
        # wygasa po kilkudziesieciu sekundach.
        self._reauth_at: dict[str, float] = {}
        self._reauth_lock = threading.Lock()
        new = not Path(self.path).exists()
        with self._conn() as conn:
            conn.executescript(SCHEMA)
        if new:
            # Hashe hasel i sesji nie sa dla innych uzytkownikow systemu.
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    @property
    def totp_available(self) -> bool:
        return self.box is not None

    def _box(self) -> SecretBox:
        if self.box is None:
            raise AuthError(
                503,
                f"Weryfikacja dwuetapowa jest niedostępna: panel nie ma klucza "
                f"{TOTP_KEY_ENV}. Administrator musi dodać go do sekretu kidwatch-secrets.",
            )
        return self.box

    # ------------------------------------------------------------- konta (CLI)
    def add_user(self, login: str, password: str) -> None:
        login = login.strip()
        if not login:
            raise ValueError("pusty login")
        check_password_policy(password)
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (login, password_hash, created_at) VALUES (?, ?, ?)",
                    (login, hash_password(password), self.clock()),
                )
            except sqlite3.IntegrityError as exc:
                raise UserExists(login) from exc

    @staticmethod
    def _user_id(conn: sqlite3.Connection, login: str) -> int:
        row = conn.execute("SELECT id FROM users WHERE login = ?", (login.strip(),)).fetchone()
        if row is None:
            raise UnknownUser(login)
        return row["id"]

    def reset_user(self, login: str, password: str) -> int:
        """Nowe haslo, zdjeta blokada, WSZYSTKIE sesje i bilety uniewaznione.

        Drugi skladnik zostaje — zapomniane haslo to nie zgubiony telefon.
        Reset robi sie zwykle wtedy, gdy haslo moglo wyciec; kto je przejal,
        traci dostep w tej samej chwili. Zwraca liczbe uniewaznionych sesji.
        """
        check_password_policy(password)
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            uid = self._user_id(conn, login)
            conn.execute(
                "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL "
                "WHERE id = ?",
                (hash_password(password), uid),
            )
            conn.execute("DELETE FROM login_failures WHERE login = ?", (login.strip(),))
            n = self._revoke_all(conn, uid)
            conn.execute("COMMIT")
        return n

    def reset_totp(self, login: str) -> int:
        """Zdejmuje drugi skladnik z CLI: na zgubiony telefon i na zmiane
        PANEL_TOTP_KEY. Kasuje kody zapasowe, sesje i bilety, zdejmuje blokade.
        Potem konto loguje sie samym haslem i moze wlaczyc 2FA od nowa."""
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            uid = self._user_id(conn, login)
            self._clear_totp(conn, uid)
            conn.execute(
                "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (uid,)
            )
            conn.execute("DELETE FROM login_failures WHERE login = ?", (login.strip(),))
            n = self._revoke_all(conn, uid)
            conn.execute("COMMIT")
        return n

    @staticmethod
    def _clear_totp(conn: sqlite3.Connection, uid: int) -> None:
        conn.execute(
            "UPDATE users SET totp_secret_enc = NULL, totp_confirmed_at = NULL, "
            "totp_last_step = NULL WHERE id = ?",
            (uid,),
        )
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (uid,))

    @staticmethod
    def _revoke_all(conn: sqlite3.Connection, uid: int) -> int:
        conn.execute("DELETE FROM tickets WHERE user_id = ?", (uid,))
        return conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,)).rowcount

    def delete_user(self, login: str) -> None:
        with self._conn() as conn:
            if conn.execute("DELETE FROM users WHERE login = ?", (login.strip(),)).rowcount == 0:
                raise UnknownUser(login)

    def list_users(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT u.login, u.failed_logins, u.locked_until, u.created_at, "
                "u.last_login_at, u.totp_confirmed_at IS NOT NULL AS totp, "
                "(SELECT COUNT(*) FROM backup_codes b WHERE b.user_id = u.id "
                " AND b.used_at IS NULL) AS backup_codes_left "
                "FROM users u ORDER BY u.login"
            ).fetchall()
        return [dict(r) for r in rows]

    def has_users(self) -> bool:
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    # ------------------------------------------------------------- logowanie
    def login(
        self, login: str, password: str, *, ip: str | None = None, user_agent: str | None = None
    ) -> LoginResult:
        """Haslo. Konto bez TOTP dostaje sesje, konto z TOTP — bilet do /mfa."""
        # Stala odpowiedz niezaleznie od tego, czy login istnieje — inaczej
        # tresc bledu pozwala wyliczyc konta.
        generic = AuthError(401, "Nieprawidłowy login lub hasło")
        addr = ip or "?"

        with self._ip_gate(addr), self._password_slot(), self._conn() as conn:
            row = conn.execute(
                "SELECT id, id AS user_id, login, password_hash, locked_until, "
                "totp_confirmed_at FROM users WHERE login = ?",
                (login.strip(),),
            ).fetchone()
            now = self.clock()
            key = (login.strip(), ip or "?")
            # Blokada (login, adres) PRZED haslem i tak samo dla kazdego
            # loginu: nie jest wyrocznia ani trafienia, ani istnienia konta.
            self._check_ip_lock(conn, key, now)

            if row is None:
                # Pelna weryfikacja na wydmuszce, nie sleep: czas odpowiedzi
                # nie zdradza, ze konta nie ma.
                _verify(_dummy(), password)
                self._count_ip_failure(conn, key, now)
                self._count_addr_failure(conn, addr, now)
                log.warning("panel: logowanie na nieznany login z %s", ip or "?")
                raise generic

            ok, rehash = _verify(row["password_hash"], password)
            if not ok:
                self._count_ip_failure(conn, key, now)
                self._count_addr_failure(conn, addr, now)
                log.warning("panel: zle haslo dla %r z %s", row["login"], ip or "?")
                raise generic
            conn.execute("DELETE FROM login_failures WHERE login = ? AND ip = ?", key)
            conn.execute("DELETE FROM ip_failures WHERE ip = ?", (addr,))
            # Blokada KONTA (zle kody drugiego skladnika, zmiana hasla) dopiero
            # po trafionym hasle: kogos, kto hasla nie zna, i tak zatrzymuje
            # licznik per adres, a samo haslo nic tu nie zdradza.
            self._check_lock(row, now)
            if rehash:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?", (rehash, row["id"])
                )

            if row["totp_confirmed_at"]:
                # Bez klucza nie wydajemy biletu, ktorego nie da sie dokonczyc.
                self._box()
                # LICZNIK PROB ZOSTAJE NIETKNIETY — zeruje go dopiero kod.
                # Zerowanie po samym hasle sprawialo w Traderze, ze kto zna
                # haslo, mogl zgadywac kody bez konca.
                challenge = secrets.token_urlsafe(32)
                conn.execute("DELETE FROM tickets WHERE expires_at <= ?", (now,))
                conn.execute(
                    "INSERT INTO tickets (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (token_hash(challenge), row["id"], now + MFA_TICKET_SECONDS),
                )
                log.info("panel: haslo poprawne dla %r, czeka na kod", row["login"])
                return LoginResult(challenge=challenge)

            # Konto bez drugiego skladnika: haslo JEST calym logowaniem.
            conn.execute("BEGIN IMMEDIATE")
            token, session = self._finish(conn, row, now, ip, user_agent)
            conn.execute("COMMIT")
            return LoginResult(token=token, session=session)

    def mfa(
        self, challenge: str, code: str, *, ip: str | None = None, user_agent: str | None = None
    ) -> tuple[str, Session]:
        """Kod TOTP albo kod zapasowy na bilecie z /login konczy logowanie."""
        box = self._box()
        with self._conn() as conn:
            t = conn.execute(
                "SELECT t.token_hash, t.user_id, t.expires_at, u.login, u.locked_until, "
                "u.totp_secret_enc, u.totp_last_step "
                "FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?",
                (token_hash(challenge or ""),),
            ).fetchone()
            now = self.clock()
            if t is None or t["expires_at"] <= now or t["totp_secret_enc"] is None:
                raise AuthError(401, "Bilet wygasł — zaloguj się ponownie")
            # Blokada konta obowiazuje TAKZE na bilecie juz wydanym — inaczej
            # bilet sprzed blokady pozwalalby dokonczyc serie prob.
            self._check_lock(t, now)

            if not self._accept_code(conn, box, t, code, now):
                # Dwie niezalezne bramki, jak w Traderze: bilet pada po
                # MAX_FAILED_PER_TICKET, konto blokuje sie po MAX_FAILED.
                conn.execute(
                    "UPDATE tickets SET failed = failed + 1 WHERE token_hash = ?",
                    (t["token_hash"],),
                )
                conn.execute(
                    "DELETE FROM tickets WHERE token_hash = ? AND failed >= ?",
                    (t["token_hash"], MAX_FAILED_PER_TICKET),
                )
                self._count_failure(conn, t["user_id"], now)
                log.warning("panel: zly kod drugiego skladnika dla %r", t["login"])
                raise AuthError(401, "Nieprawidłowy kod")

            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM tickets WHERE token_hash = ?", (t["token_hash"],))
            token, session = self._finish(conn, t, now, ip, user_agent)
            conn.execute("COMMIT")
        return token, session

    # ------------------------------------------------------ 2FA z zalogowanej sesji
    def totp_setup(self, session: Session) -> dict:
        """Nowy sekret, jeszcze NIEAKTYWNY — wlacza go dopiero `totp_confirm`.
        Mozna wolac wielokrotnie (nowy kod QR za kazdym razem)."""
        box = self._box()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT totp_confirmed_at FROM users WHERE id = ?", (session.user_id,)
            ).fetchone()
            if row["totp_confirmed_at"]:
                raise AuthError(409, "Weryfikacja dwuetapowa jest już włączona")
            secret = pyotp.random_base32()
            conn.execute(
                "UPDATE users SET totp_secret_enc = ?, totp_last_step = NULL WHERE id = ?",
                (box.encrypt(secret, session.user_id), session.user_id),
            )
        uri = totp_uri(secret, session.login)
        return {"secret": secret, "uri": uri, "qr_png_base64": qr_png_base64(uri)}

    def totp_confirm(self, session: Session, code: str) -> list[str]:
        """Kod z aplikacji wlacza TOTP. Zwraca kody zapasowe — pokazywane RAZ,
        w bazie tylko ich hashe.

        Pozostale sesje konta sa uniewazniane: powstaly bez drugiego skladnika,
        a wlaczenie 2FA to wlasnie decyzja, ze samo haslo juz nie wystarcza
        (ta sama zasada co przy zmianie hasla w Traderze)."""
        box = self._box()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT login, totp_secret_enc, totp_confirmed_at, totp_last_step "
                "FROM users WHERE id = ?",
                (session.user_id,),
            ).fetchone()
            if row["totp_confirmed_at"]:
                raise AuthError(409, "Weryfikacja dwuetapowa jest już włączona")
            if row["totp_secret_enc"] is None:
                raise AuthError(409, "Najpierw wygeneruj kod QR")
            now = self.clock()
            secret = _decrypt(box, row["totp_secret_enc"], session.user_id, row["login"])
            step = verify_totp(secret, _normalize_code(code), now, row["totp_last_step"])
            if step is None:
                # Bez licznika prob: sesja juz jest, zgadywanie kodu do WLASNEGO,
                # swiezo wygenerowanego sekretu niczego nie otwiera.
                raise AuthError(401, "Kod nie pasuje — sprawdź zegar telefonu")

            codes = new_backup_codes()
            conn.execute("BEGIN IMMEDIATE")
            # Warunkowo: z dwoch rownoleglych potwierdzen przechodzi jedno.
            # Drugie skasowaloby kody zapasowe, ktore pierwsze wlasnie pokazalo.
            if conn.execute(
                "UPDATE users SET totp_confirmed_at = ?, totp_last_step = ? "
                "WHERE id = ? AND totp_confirmed_at IS NULL",
                (now, step, session.user_id),
            ).rowcount != 1:
                conn.execute("ROLLBACK")
                raise AuthError(409, "Weryfikacja dwuetapowa jest już włączona")
            conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (session.user_id,))
            conn.executemany(
                "INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
                [(session.user_id, backup_code_hash(c)) for c in codes],
            )
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?",
                (session.user_id, session.token_hash),
            )
            conn.execute("COMMIT")
        log.info("panel: %r wlaczyl drugi skladnik", session.login)
        return codes

    def totp_disable(self, session: Session, password: str, code: str) -> None:
        """Wylaczenie wymaga hasla I kodu. Sama wazna sesja nie wystarcza:
        przejeta sesja (pozyczony telefon, niezablokowany komputer) nie moze
        po cichu zdjac 2FA, ktore chroni przed nastepnym logowaniem."""
        box = self._box()
        with self._password_slot(), self._conn() as conn:
            row = conn.execute(
                "SELECT id AS user_id, login, password_hash, locked_until, totp_secret_enc, "
                "totp_confirmed_at, totp_last_step FROM users WHERE id = ?",
                (session.user_id,),
            ).fetchone()
            now = self.clock()
            if not row["totp_confirmed_at"]:
                raise AuthError(409, "Weryfikacja dwuetapowa nie jest włączona")
            self._check_lock(row, now)
            ok, _ = _verify(row["password_hash"], password)
            if not ok or not self._accept_code(conn, box, row, code, now):
                # Te same proby co przy logowaniu — inaczej to byloby okno do
                # zgadywania hasla bez blokady.
                self._count_failure(conn, row["user_id"], now)
                raise AuthError(401, "Nieprawidłowe hasło albo kod")
            conn.execute("BEGIN IMMEDIATE")
            self._clear_totp(conn, row["user_id"])
            conn.execute(
                "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
                (row["user_id"],),
            )
            conn.execute("COMMIT")
        log.warning("panel: %r wylaczyl drugi skladnik", session.login)

    def reauth(self, session: Session, secret: str) -> None:
        """Ponowne potwierdzenie tozsamosci przed zmiana o szerokim zasiegu
        (numer odbiorcy w bramce dotyczy wszystkich aplikacji RenaCode, audyt 3,
        S2). `secret` to haslo albo — przy wlaczonym 2FA — kod TOTP lub kod
        zapasowy. Sama sesja (pozyczony telefon, niezablokowany komputer) nie
        wystarcza. Pomylki licza sie do blokady konta jak przy logowaniu."""
        if not secret or len(secret) > 512:
            raise AuthError(401, "Potwierdź hasłem albo kodem z aplikacji")
        with self._password_slot(), self._conn() as conn:
            row = conn.execute(
                "SELECT id AS user_id, login, password_hash, locked_until, totp_secret_enc, "
                "totp_confirmed_at, totp_last_step FROM users WHERE id = ?",
                (session.user_id,),
            ).fetchone()
            now = self.clock()
            if row is None:
                raise AuthError(401, "Wymagane zalogowanie")
            self._check_lock(row, now)
            ok = False
            norm = _normalize_code(secret)
            if row["totp_confirmed_at"] and self.box is not None and len(norm) in (6, 12):
                ok = self._accept_code(conn, self.box, row, secret, now)
            if not ok:
                ok, _ = _verify(row["password_hash"], secret)
            if not ok:
                self._count_failure(conn, row["user_id"], now)
                log.warning("panel: nieudane potwierdzenie tozsamosci dla %r", row["login"])
                raise AuthError(401, "Nieprawidłowe hasło albo kod")
        with self._reauth_lock:
            self._reauth_at[session.token_hash] = now

    def require_fresh_reauth(
        self, session: Session, max_age_s: float = REAUTH_FRESH_SECONDS
    ) -> None:
        """Odmowa (403), jesli ta sesja nie potwierdzila tozsamosci w ciagu
        `max_age_s` sekund. Dla QR bota WhatsApp (K-1): WAHA wchodzi w stan
        skanu sama, po kazdym rozlaczeniu, a sama przejeta sesja nie moze
        wtedy podpiac obcego numeru jako nadawcy powiadomien. 403, nie 401 -
        sesja jest wazna, front nie ma wracac do ekranu logowania."""
        now = self.clock()
        with self._reauth_lock:
            for key in [k for k, t in self._reauth_at.items() if now - t > max_age_s]:
                del self._reauth_at[key]
            fresh = session.token_hash in self._reauth_at
        if not fresh:
            raise AuthError(
                403, "Potwierdź tożsamość ponownie (hasło albo kod), żeby pobrać kod QR"
            )

    def change_password(self, session: Session, old: str, new: str) -> int:
        """Zmiana hasla z panelu. Wymaga STAREGO hasla (przejeta sesja nie
        zmieni hasla i nie zamknie wlasciciela na zewnatrz), liczy pomylki
        jak logowanie i wylogowuje wszystkie INNE sesje konta — po zmianie
        hasla z powodu wycieku stare urzadzenia maja wypasc. Zwraca liczbe
        zamknietych sesji."""
        if len(new) < MIN_PASSWORD_LEN:
            raise AuthError(400, f"Nowe hasło musi mieć co najmniej {MIN_PASSWORD_LEN} znaków")
        if len(new) > 512:
            raise AuthError(400, "Nowe hasło jest za długie")
        if new == old:
            raise AuthError(400, "Nowe hasło musi się różnić od starego")
        with self._password_slot(), self._conn() as conn:
            row = conn.execute(
                "SELECT id AS user_id, login, password_hash, locked_until FROM users "
                "WHERE id = ?",
                (session.user_id,),
            ).fetchone()
            now = self.clock()
            self._check_lock(row, now)
            ok, _ = _verify(row["password_hash"], old)
            if not ok:
                self._count_failure(conn, row["user_id"], now)
                raise AuthError(401, "Nieprawidłowe obecne hasło")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL "
                "WHERE id = ?",
                (hash_password(new), row["user_id"]),
            )
            closed = conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?",
                (row["user_id"], session.token_hash),
            ).rowcount
            # Bilety do /mfa tez: wydano je na STARE haslo, a kto je zna, nie
            # moze dokonczyc logowania kodem (jak _revoke_all przy resecie).
            conn.execute("DELETE FROM tickets WHERE user_id = ?", (row["user_id"],))
            conn.execute("COMMIT")
        log.warning("panel: %r zmienil haslo, wylogowano innych sesji: %d", session.login, closed)
        return closed

    # ------------------------------------------------------------- pomocnicze
    @contextlib.contextmanager
    def _ip_gate(self, addr: str) -> Iterator[None]:
        """Limit per adres PRZED slotem Argon2: zablokowany adres i nadmiar
        rownoleglych prob z jednego adresu nie zajmuja slotu ani watku."""
        with _inflight_lock:
            if _inflight.get(addr, 0) >= MAX_INFLIGHT_PER_IP:
                raise AuthError(429, "Poprzednia próba logowania jeszcze trwa. Spróbuj za chwilę.")
            _inflight[addr] = _inflight.get(addr, 0) + 1
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT locked_until FROM ip_failures WHERE ip = ?", (addr,)
                ).fetchone()
            now = self.clock()
            if row is not None and row["locked_until"] and row["locked_until"] > now:
                left = int(row["locked_until"] - now) + 1
                raise AuthError(429, f"Zbyt wiele nieudanych prób. Spróbuj za {left} s.")
            yield
        finally:
            with _inflight_lock:
                if _inflight.get(addr, 0) <= 1:
                    _inflight.pop(addr, None)
                else:
                    _inflight[addr] -= 1

    @staticmethod
    def _count_addr_failure(conn: sqlite3.Connection, addr: str, now: float) -> None:
        conn.execute("DELETE FROM ip_failures WHERE updated_at < ?", (now - 24 * 3600,))
        # Po wygasnieciu blokady albo przerwie dluzszej niz okno — od nowa.
        conn.execute(
            "INSERT INTO ip_failures (ip, failures, locked_until, updated_at) "
            "VALUES (?, 1, NULL, ?) "
            "ON CONFLICT (ip) DO UPDATE SET "
            "failures = CASE WHEN (locked_until IS NOT NULL AND locked_until <= ?) "
            "OR updated_at < ? THEN 1 ELSE failures + 1 END, "
            "locked_until = CASE "
            "WHEN (locked_until IS NOT NULL AND locked_until <= ?) OR updated_at < ? THEN NULL "
            "WHEN failures + 1 >= ? THEN ? "
            "ELSE locked_until END, "
            "updated_at = excluded.updated_at",
            (addr, now, now, now - IP_WINDOW_SECONDS, now, now - IP_WINDOW_SECONDS,
             IP_MAX_FAILED, now + IP_WINDOW_SECONDS),
        )

    @contextlib.contextmanager
    def _password_slot(self) -> Iterator[None]:
        if not _verify_slot.acquire(timeout=VERIFY_WAIT_SECONDS):
            raise AuthError(503, "Zbyt wiele prób logowania naraz. Spróbuj za chwilę.")
        try:
            yield
        finally:
            _verify_slot.release()

    @staticmethod
    def _check_lock(row: sqlite3.Row, now: float) -> None:
        # Blokada sprawdzana PRZED haslem i kodem: zablokowane konto nie jest
        # wyrocznia, ktora mowi, czy kolejna proba byla trafiona.
        if row["locked_until"] and row["locked_until"] > now:
            left = int(row["locked_until"] - now) + 1
            raise AuthError(
                429, f"Konto zablokowane po nieudanych próbach. Spróbuj za {left} s."
            )

    @staticmethod
    def _count_failure(conn: sqlite3.Connection, uid: int, now: float) -> None:
        # Licznik podbijany W BAZIE (x + 1), nie odczytem i zapisem w Pythonie —
        # tak samo jak w Traderze. Po wygasnieciu blokady liczy od nowa: bez
        # tego kazda kolejna pomylka blokowala od razu na 15 min.
        # (SQLite liczy wszystkie wyrazenia SET na STARYCH wartosciach wiersza.)
        conn.execute(
            "UPDATE users SET "
            "failed_logins = CASE WHEN locked_until IS NOT NULL AND locked_until <= ? "
            "THEN 1 ELSE failed_logins + 1 END, "
            "locked_until = CASE "
            "WHEN locked_until IS NOT NULL AND locked_until <= ? THEN NULL "
            "WHEN failed_logins + 1 >= ? THEN ? "
            "ELSE locked_until END WHERE id = ?",
            (now, now, MAX_FAILED, now + LOCKOUT_SECONDS, uid),
        )

    @staticmethod
    def _check_ip_lock(conn: sqlite3.Connection, key: tuple[str, str], now: float) -> None:
        row = conn.execute(
            "SELECT locked_until FROM login_failures WHERE login = ? AND ip = ?", key
        ).fetchone()
        if row is not None and row["locked_until"] and row["locked_until"] > now:
            left = int(row["locked_until"] - now) + 1
            raise AuthError(429, f"Zbyt wiele nieudanych prób. Spróbuj za {left} s.")

    @staticmethod
    def _count_ip_failure(conn: sqlite3.Connection, key: tuple[str, str], now: float) -> None:
        # Ta sama arytmetyka co _count_failure, na wierszu (login, adres).
        # Stare wiersze sprzata ten sam zapis — tabela nie rosnie z kazdym
        # zgadywanym loginem.
        conn.execute("DELETE FROM login_failures WHERE updated_at < ?",
                     (now - 24 * 3600,))
        conn.execute(
            "INSERT INTO login_failures (login, ip, failures, locked_until, updated_at) "
            "VALUES (?, ?, 1, NULL, ?) "
            "ON CONFLICT (login, ip) DO UPDATE SET "
            "failures = CASE WHEN locked_until IS NOT NULL AND locked_until <= ? "
            "THEN 1 ELSE failures + 1 END, "
            "locked_until = CASE "
            "WHEN locked_until IS NOT NULL AND locked_until <= ? THEN NULL "
            "WHEN failures + 1 >= ? THEN ? "
            "ELSE locked_until END, "
            "updated_at = excluded.updated_at",
            (*key, now, now, now, MAX_FAILED, now + LOCKOUT_SECONDS),
        )

    @staticmethod
    def _accept_code(
        conn: sqlite3.Connection, box: SecretBox, row: sqlite3.Row, code: str, now: float
    ) -> bool:
        """Kod TOTP albo kod zapasowy. Oba ZUZYWANE warunkowym UPDATE-em w bazie:
        dwa rownolegle zadania z tym samym kodem nie przejda oba."""
        norm = _normalize_code(code)
        secret = _decrypt(box, row["totp_secret_enc"], row["user_id"], row["login"])
        step = verify_totp(secret, norm, now, row["totp_last_step"])
        if step is not None:
            return conn.execute(
                "UPDATE users SET totp_last_step = ? WHERE id = ? "
                "AND (totp_last_step IS NULL OR totp_last_step < ?)",
                (step, row["user_id"], step),
            ).rowcount == 1
        if len(norm) == 12:
            used = conn.execute(
                "UPDATE backup_codes SET used_at = ? WHERE id = ("
                " SELECT id FROM backup_codes WHERE user_id = ? AND code_hash = ?"
                " AND used_at IS NULL LIMIT 1)",
                (now, row["user_id"], backup_code_hash(norm)),
            ).rowcount == 1
            if used:
                log.warning("panel: %r uzyl KODU ZAPASOWEGO", row["login"])
            return used
        return False

    def _finish(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        now: float,
        ip: str | None,
        user_agent: str | None,
    ) -> tuple[str, Session]:
        """Licznik prob wyzerowany, NOWA sesja (session fixation)."""
        conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? "
            "WHERE id = ?",
            (now, row["user_id"]),
        )
        token = secrets.token_urlsafe(32)
        session = Session(
            login=row["login"],
            user_id=row["user_id"],
            token_hash=token_hash(token),
            csrf=secrets.token_urlsafe(32),
            expires_at=now + self.session_seconds,
        )
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at, "
            "ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session.token_hash, row["user_id"], session.csrf, now, session.expires_at,
             ip, (user_agent or "")[:300]),
        )
        # Sprzatanie przy okazji: osobny watek na to byloby przesada.
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        log.info("panel: zalogowano %r z %s", row["login"], ip or "?")
        return token, session

    # ------------------------------------------------------------- sesje
    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._conn() as conn:
            row = conn.execute(
                "SELECT s.token_hash, s.csrf, s.expires_at, u.id, u.login "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (token_hash(token),),
            ).fetchone()
        if row is None or row["expires_at"] <= self.clock():
            return None
        return Session(
            login=row["login"],
            user_id=row["id"],
            token_hash=row["token_hash"],
            csrf=row["csrf"],
            expires_at=row["expires_at"],
        )

    def account(self, session: Session) -> dict:
        """Stan konta dla /api/auth/me — z tego front rysuje odznake 2FA."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT u.totp_confirmed_at IS NOT NULL AS totp, "
                "(SELECT COUNT(*) FROM backup_codes b WHERE b.user_id = u.id "
                " AND b.used_at IS NULL) AS left_ "
                "FROM users u WHERE u.id = ?",
                (session.user_id,),
            ).fetchone()
        return {
            "totp_enabled": bool(row["totp"]),
            "backup_codes_left": row["left_"],
            "totp_available": self.totp_available,
        }

    def logout(self, session: Session) -> None:
        with self._reauth_lock:
            self._reauth_at.pop(session.token_hash, None)
        with self._conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (session.token_hash,))


def csrf_ok(session: Session, header: str | None) -> bool:
    """Naglowek musi sie zgadzac z tokenem ZAPISANYM PRZY SESJI.

    Mocniej niz czysty double-submit z Tradera (ciasteczko == naglowek): tam
    ktos, kto potrafi podrzucic ciasteczko (np. z poddomeny), ustala obie
    wartosci sam. Porownanie przez compare_digest, zeby czas nie zdradzal,
    ile znakow sie zgadzalo.
    """
    # Na bajtach: compare_digest na str z bajtem spoza ASCII rzuca TypeError,
    # czyli 500 zamiast 403.
    return bool(header) and hmac.compare_digest(session.csrf.encode(), header.encode())


def box_from_env() -> SecretBox | None:
    """Klucz z PANEL_TOTP_KEY albo None. Brak klucza nie jest bledem: panel
    dziala, logowanie haslem tez — nie da sie tylko wlaczyc 2FA."""
    raw = os.environ.get(TOTP_KEY_ENV, "").strip()
    if not raw:
        log.warning(
            "panel: brak %s — wlaczenie 2FA niedostepne. Wygeneruj: "
            "openssl rand -base64 32 i dodaj do sekretu kidwatch-secrets", TOTP_KEY_ENV
        )
        return None
    try:
        return SecretBox(raw)
    except ValueError as exc:
        log.error("panel: %s — 2FA niedostepne", exc)
        return None
