# -*- coding: utf-8 -*-
"""Prompt zur Einbindung (einbindung_prompt.py): muss zu den Regeln des
Werkzeugs passen. Schlägt einer dieser Tests nach einer Änderung fehl, ist
die Vorlage veraltet - bitte im selben Commit anpassen (siehe CLAUDE.md)."""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
WURZEL = os.path.dirname(HIER)
sys.path.insert(0, WURZEL)
import einbindung_prompt as E  # noqa: E402
import signier_werkzeug as W  # noqa: E402

SCHLUESSEL = "7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc="   # öffentlich (Herausgeber), nur als Beispielwert


class EinbindungTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="einbindung-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": self.tmp})
        self._env.start()
        W._sitzung["token"] = ""

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def profil(self, **k):
        pr = {"id": "beispiel01", "name": "Beispiel-Software", "regel": "alle", "repo": "Besitzer/beispiel",
              "zweig": "main", "oeffentlich": SCHLUESSEL, "ausschluss": ["logs/*", "*.log"], **k}
        W.profile_speichern({"profile": [pr], "github_token": "klar:Z2hwX0dlaGVpbQ=="})
        return pr

    def text(self, **k):
        pr = self.profil(**k)
        return W.aktion("einbindung_prompt", {"id": pr["id"]})

    def test_pruefmodul_pruefsumme_aktuell(self):
        with open(os.path.join(WURZEL, "Pruefmodul", "signatur_pruefen.py"), "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), W.PRUEFMODUL_SHA256,
                             "Prüfmodul geändert: PRUEFMODUL_SHA256 und ggf. die Vorlage anpassen")

    def test_regeln_wie_im_werkzeug_und_pruefmodul(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("signatur_pruefen", os.path.join(WURZEL, "Pruefmodul", "signatur_pruefen.py"))
        P = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(P)
        t = self.text()["text"]
        self.assertEqual((P.FORMAT, list(P.STANDARD_AUSSCHLUSS), tuple(P.BINAER)),
                         (W.FORMAT, list(W.STANDARD_AUSSCHLUSS), tuple(W.BINAER)))
        self.assertIn(f"`{W.FORMAT}`", t)
        self.assertIn(f'"format": "{W.FORMAT}"', t)
        for muster in W.STANDARD_AUSSCHLUSS:
            self.assertIn(f"`{muster}`", t)
        self.assertIn(" ".join(W.BINAER), t)
        self.assertIn(W.PRUEFMODUL_SHA256, t)
        self.assertIn(f"Stand Tag\n  `v{W.VERSION}`", t)
        self.assertIn(W.WERKZEUG_REPO, t)
        # die signierte Nachricht genau wie im Werkzeug
        self.assertIn('sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")', t)
        self.assertEqual(W.nachricht("1", {}), b'{"dateien":{},"format":"' + W.FORMAT.encode() + b'","version":"1"}')

    def test_profilwerte(self):
        d = self.text()
        t = d["text"]
        self.assertNotIn("{{", t)
        self.assertIn(SCHLUESSEL, t)
        self.assertIn("04B4 5F7A 55E8 BEB9 AEB2 34D5 8A95 812A 5710 2226 AA9E 777F 4C2D 30C1 CAE7 8086", t)
        self.assertIn("`logs/*`, `*.log`", t)
        self.assertIn("**Besitzer/beispiel**", t)
        self.assertEqual(d["datei"], "Prompt_Einbindung_Beispiel-Software.md")
        self.assertIn("keine", self.text(ausschluss=[])["text"].split("Ausnahmen des Profils")[1].splitlines()[0])
        self.assertIn("<Besitzer/Name>", self.text(repo="")["text"])

    def test_wichtige_regeln_stehen_drin(self):
        t = self.text()["text"]
        for satz in ("Keine Tags `v<Version>` automatisch setzen", "export-ignore", "Submodule",
                     "Nie** aus einer Datei, die mit einem Update kommt", "nicht stillschweigend",
                     "Version laut Signatur == Inhalt von `VERSION` == gewählter Tag", "Die Versionsnummer vergebe ich",
                     "Nicht signieren"):
            self.assertIn(satz, t)

    def test_keine_geheimnisse(self):
        t = self.text()["text"]
        for geheim in ("ghp_", "Z2hwX0dlaGVpbQ", "PRIVATE KEY", "klar:"):
            self.assertNotIn(geheim, t)

    def test_nicht_fuer_dashboard_und_nicht_ohne_schluessel(self):
        pr = self.profil(regel="speedrace")
        self.assertRaises(ValueError, W.aktion, "einbindung_prompt", {"id": pr["id"]})
        pr = self.profil(oeffentlich="")
        self.assertRaises(ValueError, W.aktion, "einbindung_prompt", {"id": pr["id"]})

    def test_profilname_ohne_steuerzeichen(self):
        t = self.text(name="Name\nmit `Zeilen`")["text"]
        self.assertIn("„Name mit `Zeilen`“", t)
        self.assertEqual(E.fingerabdruck(SCHLUESSEL)[:4], "04B4")

    def test_seite_hat_knopf(self):
        self.assertIn('id="b-prompt"', W.SEITE)


if __name__ == "__main__":
    unittest.main()
