"""Panel: komendy z WhatsAppa — dziennik i awaryjny wylacznik.

Dwa widoki dziennika: administratora instalacji (`whatsapp.konfiguracja`,
zakres instancji: wszystkie wiadomosci, takze z nieznanych numerow, plus
wylacznik "wylacz komendy z WhatsAppa dla wszystkich") i domu
(`konta.zarzadzanie` w domu: komendy tego domu). Numery w dzienniku sa
zamaskowane juz w bazie.

Z wylaczona funkcja (`whatsapp_komendy.enabled: false`) panel nie zaklada
tabel w panel-auth.db — mowi tylko, ze komendy sa wylaczone.
"""

from __future__ import annotations

from .config import WhatsappKomendyConfig
from .komendy_baza import BazaKomend


class KomendyPanelu:
    def __init__(self, path: str, cfg: WhatsappKomendyConfig) -> None:
        self.path = path
        self.cfg = cfg
        self._baza: BazaKomend | None = None

    @property
    def baza(self) -> BazaKomend | None:
        if not self.cfg.enabled:
            return None
        if self._baza is None:
            self._baza = BazaKomend(self.path)
        return self._baza

    def stan(self, limit: int = 200) -> dict:
        baza = self.baza
        if baza is None:
            return {"wlaczone": False, "wylaczone": None, "wpisy": []}
        llm = self.cfg.llm
        return {
            "wlaczone": True,
            "wylaczone": baza.wylaczone(),
            "wpisy": baza.dziennik(limit=limit),
            "llm": {
                "dostawcy": [d for d in llm.dostawcy if llm.klucz(d)],
                "wywolania_dzis": baza.wywolania_llm(),
                "limit": llm.wywolan_na_dobe,
            },
            "limity": {
                "luzowanie_minut": self.cfg.luzowanie_minut,
                "odblokowania": self.cfg.odblokowania,
                "na_godzine": self.cfg.na_godzine,
            },
        }

    def dziennik_domu(self, dom_id: int, limit: int = 100) -> dict:
        baza = self.baza
        if baza is None:
            return {"wlaczone": False, "wpisy": []}
        return {"wlaczone": True, "wylaczone": baza.wylaczone() is not None,
                "wpisy": baza.dziennik(dom_id=dom_id, limit=limit)}

    def ustaw_wylacznik(self, wylaczone: bool, kto: str) -> dict:
        baza = self.baza
        if baza is None:
            raise LookupError("komendy z WhatsAppa są wyłączone w konfiguracji")
        baza.ustaw_wylaczone(wylaczone, kto)
        return {"ok": True, "wylaczone": baza.wylaczone()}
