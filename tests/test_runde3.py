# -*- coding: utf-8 -*-
"""Korrekturen aus der dritten Prüfrunde (Befundliste Runde 3)."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import signier_werkzeug as W  # noqa: E402

KENNWORT = "Test-Kennwort-123"


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="runde3-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata"),
                                                 "HOME": os.path.join(self.tmp, "home")})
        self._env.start()
        W._sitzung["token"] = ""

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def neues_profil(self, **k):
        d = W.aktion("profil_speichern", {"name": "Beispiel", "regel": "alle", "repo": "Besitzer/beispiel", **k})
        return d["profile"][-1]

    def schreiben(self, rel, daten):
        pfad = os.path.join(self.tmp, "ordner", *rel.split("/"))
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        with open(pfad, "wb") as f:
            f.write(daten)


class SchluesselTests(Basis):
    """M1, N5: hinterlegter öffentlicher Schlüssel wird nicht still ersetzt."""

    def test_neuer_schluessel_bei_hinterlegtem_oeffentlichem_abgelehnt(self):
        pr = self.neues_profil()
        d = W.aktion("schluessel_neu", {"id": pr["id"], "kennwort": KENNWORT})
        oeff = next(p for p in d["profile"] if p["id"] == pr["id"])["oeffentlich"]
        pem = W.schluessel_pfad(pr)
        weg = os.path.join(self.tmp, "usb.pem")
        shutil.move(pem, weg)   # Datei auf den USB-Stick verschoben
        self.assertRaisesRegex(ValueError, "gesicherte Schlüsseldatei", W.aktion, "schluessel_neu",
                               {"id": pr["id"], "kennwort": KENNWORT})
        # fremde Schlüsseldatei: abgelehnt
        anderes = self.neues_profil(name="Anderes")
        W.aktion("schluessel_neu", {"id": anderes["id"], "kennwort": KENNWORT})
        self.assertRaisesRegex(ValueError, "passt nicht", W.aktion, "schluessel_import",
                               {"id": pr["id"], "pfad": W.schluessel_pfad(anderes), "kennwort": KENNWORT})
        self.assertEqual(next(p for p in W.aktion("zustand", {})["profile"] if p["id"] == pr["id"])["oeffentlich"], oeff)
        # die richtige (gesicherte) Datei: übernommen
        d = W.aktion("schluessel_import", {"id": pr["id"], "pfad": weg, "kennwort": KENNWORT})
        p = next(p for p in d["profile"] if p["id"] == pr["id"])
        self.assertTrue(p["hat_schluessel"])
        self.assertEqual(p["oeffentlich"], oeff)

    def test_profil_loeschen_scheitert_schluessel_bleibt(self):
        pr = self.neues_profil()
        W.aktion("schluessel_neu", {"id": pr["id"], "kennwort": KENNWORT})
        with mock.patch.object(W, "profile_speichern", side_effect=OSError("gesperrt")):
            self.assertRaises(OSError, W.aktion, "profil_loeschen", {"id": pr["id"]})
        self.assertTrue(os.path.isfile(W.schluessel_pfad(pr)))
        self.assertTrue(next(p for p in W.aktion("zustand", {})["profile"] if p["id"] == pr["id"])["hat_schluessel"])


class ProfilStandTests(Basis):
    """M2: Speichern aus einem veralteten Tab wird abgelehnt."""

    def test_veralteter_stand(self):
        pr = self.neues_profil()
        stand = pr["stand"]
        W.aktion("profil_speichern", {"id": pr["id"], "name": "A", "regel": "alle", "ausschluss": "geheim/*",
                                      "stand": stand})
        self.assertRaisesRegex(ValueError, "inzwischen geändert", W.aktion, "profil_speichern",
                               {"id": pr["id"], "name": "B", "regel": "speedrace", "stand": stand})
        p = next(p for p in W.aktion("zustand", {})["profile"] if p["id"] == pr["id"])
        self.assertEqual((p["name"], p["regel"], p["ausschluss"]), ("A", "alle", ["geheim/*"]))
        W.aktion("profil_speichern", {"id": pr["id"], "name": "B", "regel": "alle", "stand": p["stand"]})

    def test_seite_schickt_stand_und_zeichnet_nur_schluesselteil(self):
        self.assertIn("stand: bStand", W.SEITE)
        self.assertIn('schluesselTeil(Z.profile.find(x => x.id === $("b-id").value));', W.SEITE)


class LokalSignierenTests(Basis):
    """N1, N2, N4: lokales Signieren."""

    def profil_mit_schluessel(self, **k):
        pr = self.neues_profil(**k)
        d = W.aktion("schluessel_neu", {"id": pr["id"], "kennwort": KENNWORT})
        return next(p for p in d["profile"] if p["id"] == pr["id"])

    def signieren(self, pr):
        return W.aktion("signieren_ordner", {"id": pr["id"], "ordner": os.path.join(self.tmp, "ordner"),
                                             "kennwort": KENNWORT})

    def test_bom_und_format(self):
        pr = self.profil_mit_schluessel()
        self.schreiben("a.txt", b"1")
        for inhalt, text in ((b"\xef\xbb\xbf1.2.3\n", "BOM"), (b"1.2\n", "x.y.z"), (b"1.2.3.\n", "x.y.z")):
            self.schreiben("VERSION", inhalt)
            with self.subTest(inhalt=inhalt):
                self.assertRaisesRegex(ValueError, text, self.signieren, pr)
                self.assertFalse(os.path.exists(os.path.join(self.tmp, "ordner", "SIGNATUR.json")))
        self.schreiben("VERSION", b"1.2.3\n")
        self.assertIn("Version 1.2.3", self.signieren(pr)["meldung"])

    def test_pycache_bricht_ab(self):
        pr = self.profil_mit_schluessel()
        self.schreiben("a.py", b"x = 1\n")
        self.schreiben("__pycache__/a.cpython-313.pyc", b"\0")
        self.assertRaisesRegex(ValueError, "Kompilierte", self.signieren, pr)

    def test_fremde_signatur_wird_gesichert(self):
        fremd = self.profil_mit_schluessel(name="Fremd")
        pr = self.profil_mit_schluessel()
        self.schreiben("a.txt", b"1")
        self.signieren(fremd)
        with open(os.path.join(self.tmp, "ordner", "SIGNATUR.json"), "rb") as f:
            alt = f.read()
        m = self.signieren(pr)["meldung"]
        self.assertIn("gesichert unter", m)
        pfad = m.split("gesichert unter ", 1)[1].rstrip(".")
        with open(pfad, "rb") as f:
            self.assertEqual(f.read(), alt)
        self.assertTrue(pfad.startswith(W.daten_ordner()))   # nicht im signierten Ordner
        self.assertNotIn("gesichert", self.signieren(pr)["meldung"])   # eigene Signatur: einfach ersetzt


class HochladenMeldungTests(unittest.TestCase):
    """N12: verlorene Antwort beim Vorspulen und beim Nachlesen."""

    def test_unklar_statt_nichts_veroeffentlicht(self):
        stand = "a" * 40

        def gh(pfad, token, methode="GET", daten=None, **k):
            if pfad.endswith("/git/commits/" + stand):
                return {"tree": {"sha": "b" * 40}}
            if pfad.endswith("/git/blobs"):
                import base64
                return {"sha": W._git_blob_sha(base64.b64decode(daten["content"]))}
            if pfad.endswith("/git/trees"):
                return {"sha": "c" * 40}
            if pfad.endswith("/git/commits"):
                return {"sha": "d" * 40}
            raise ValueError("Zeitüberschreitung")
        staende = iter([stand])

        def zweig(*a):
            try:
                return next(staende)
            except StopIteration:
                raise ValueError("Netz weg")
        with mock.patch.object(W, "_gh", side_effect=gh), mock.patch.object(W, "_zweig_stand", side_effect=zweig):
            with self.assertRaisesRegex(ValueError, "Unklar"):
                W.github_hochladen_commit("Besitzer/beispiel", "main", "t", {W.SIGNATUR_DATEI: "{}\n"}, "1.0.0",
                                          stand, [])


if __name__ == "__main__":
    unittest.main()
