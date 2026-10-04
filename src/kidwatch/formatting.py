"""Tresc dluzszych powiadomien: jedna struktura, dwa wyjscia.

Podsumowanie dnia, raport tygodnia i koniec sesji skladaja sie z SEKCJI
(dziecko/urzadzenie, telewizor). Z tej samej listy sekcji powstaje:
  * tekst do maila i WhatsAppa — wieloliniowy, z punktorami, naglowek sekcji
    w *gwiazdkach* (WhatsApp pogrubia, bramka usuwa je z maila);
  * dane dla panelu (Notification.data -> notifications.data), z ktorych front
    rysuje naglowki, listy i mini-paski zamiast parsowac tekst.

Wczesniej to byla jedna linia na urzadzenie z aplikacjami po przecinku,
a tytuly YouTube z ich " | Kanal | tagi" robily z niej sciane tekstu.
"""

from __future__ import annotations

#: Ile pozycji listy pokazac; reszta jako "+N wiecej".
LIST_LIMIT = 5
TITLE_MAX = 60
BULLET = "•"


def short_title(title: str, limit: int = TITLE_MAX) -> str:
    """"Myjka okien | Fiksiki | Zabawa, Nauka" -> "Myjka okien".

    YouTube dokleja do tytulu kanal i tagi po " | " — dla rodzica to szum.
    Bardzo dlugie tytuly sa obcinane z wielokropkiem.
    """
    head = title.split(" | ", 1)[0].strip() or title.strip()
    return head if len(head) <= limit else head[: limit - 1].rstrip() + "…"


def short_titles(titles: list[str], limit: int = LIST_LIMIT) -> tuple[list[str], int]:
    """(skrocone tytuly bez powtorzen, ile jeszcze nie pokazano)."""
    out: list[str] = []
    for t in titles:
        s = short_title(t)
        if s and s not in out:
            out.append(s)
    return out[:limit], max(0, len(out) - limit)


def fmt_minutes(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} min"
    h, m = divmod(minutes, 60)
    return f"{h} h" if m == 0 else f"{h} h {m} min"


def section(
    label: str,
    summary: str,
    *,
    kind: str = "ipad",
    facts: list[str] | None = None,
    apps: list[tuple[str, int]] | None = None,
    apps_label: str = "Aplikacje",
    approx: bool = True,
    titles: list[str] | None = None,
    exact: list[tuple[str, int]] | None = None,
    exact_label: str | None = None,
    after: list[str] | None = None,
) -> dict:
    """Sekcja jako slownik gotowy do JSON-a (panel) i do tekstu (kanaly)."""
    shown, more = short_titles(titles or [])
    apps = apps or []
    return {
        "label": label,
        "kind": kind,
        "summary": summary,
        "facts": list(facts or []),
        "apps_label": apps_label,
        "approx": approx,
        "apps": [{"app": a, "minutes": n} for a, n in apps[:LIST_LIMIT]],
        "apps_more": max(0, len(apps) - LIST_LIMIT),
        "titles": shown,
        "titles_more": more,
        "exact_label": exact_label,
        "exact": [{"app": a, "minutes": n} for a, n in (exact or [])[:LIST_LIMIT]],
        "after": list(after or []),
    }


def _bullets(items: list[str], more: int, more_word: str = "wiecej") -> list[str]:
    lines = [f"{BULLET} {i}" for i in items]
    if more:
        lines.append(f"{BULLET} +{more} {more_word}")
    return lines


def section_text(sec: dict) -> str:
    if not sec["label"]:
        lines = [sec["summary"]]
    elif sec["summary"]:
        lines = [f"*{sec['label']}* — {sec['summary']}"]
    else:
        lines = [f"*{sec['label']}*"]
    lines += _bullets(sec["facts"], 0)
    # Naglowek listy tylko wtedy, gdy przed nia sa inne punkty — inaczej
    # "Aplikacje:" pod samym naglowkiem sekcji to pusta linia wiecej.
    headed = bool(sec["facts"])
    if sec["apps"]:
        if headed:
            lines.append(f"{sec['apps_label']}:")
        tilde = "~" if sec["approx"] else ""
        lines += _bullets(
            [f"{a['app']} {tilde}{fmt_minutes(a['minutes'])}" for a in sec["apps"]],
            sec["apps_more"],
            "innych",
        )
        headed = True
    if sec["titles"]:
        if headed:
            lines.append("Co lecialo:")
        lines += _bullets(sec["titles"], sec["titles_more"])
    if sec["exact"]:
        lines.append(f"{sec['exact_label'] or 'Dokladnie'}:")
        lines += _bullets([f"{e['app']} {fmt_minutes(e['minutes'])}" for e in sec["exact"]], 0)
    lines += sec.get("after", [])
    return "\n".join(lines)


def sections_text(sections: list[dict], note: str | None = None) -> str:
    """Sekcje rozdzielone pusta linia — na telefonie to czytelne bloki."""
    body = "\n\n".join(section_text(s) for s in sections)
    return f"{body}\n\n{note}" if note else body


def payload(kind: str, sections: list[dict], **extra) -> dict:
    return {"type": kind, "sections": sections, **extra}
