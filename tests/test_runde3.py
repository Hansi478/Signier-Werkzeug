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

    def test_feste_namen_genau_geschrieben(self):
        """N9: „version“ bzw. „Signatur.json“ (Windows fände sie als VERSION/SIGNATUR.json)."""
        pr = self.profil_mit_schluessel()
        self.schreiben("a.txt", b"1")
        for name in ("version", "Signatur.json"):
            self.schreiben(name, b"1.0.0\n")
            with self.subTest(name=name):
                self.assertRaisesRegex(ValueError, "Schreibweise", self.signieren, pr)
            os.remove(os.path.join(self.tmp, "ordner", name))
        self.signieren(pr)

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


class OberflaecheTests(Basis):
    """M4, N16-N19."""

    def test_qnap_ablaufauswahl_bleibt(self):
        d = W.aktion("qnap_abbrechen", {"ablauf": "aufraeumen"})
        self.assertEqual(d["ablauf"], "aufraeumen")
        self.assertEqual(W.aktion("qnap_abbrechen", {})["ablauf"], "installieren")

    def test_seite(self):
        for teil in ("function qProfilAbgleichen", "waehlenOffen", 'bauTimer = null; bauErwartet = "";'):
            self.assertIn(teil, W.SEITE)
        self.assertNotIn("qFormGeladen", W.SEITE)

    def test_zweiter_start_wartet_nicht(self):
        self.assertTrue(W._instanz_sperren())
        try:
            import subprocess
            code = ("import sys, time; sys.path.insert(0, %r); import signier_werkzeug as W; t = time.monotonic(); "
                    "ok = W._instanz_sperren(); print(ok, round(time.monotonic() - t, 1))") % os.path.dirname(HIER)
            aus = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=os.environ).stdout.split()
            self.assertEqual(aus[0], "False")
            self.assertLess(float(aus[1]), 2)
        finally:
            os.close(W._INSTANZ.pop("fd"))

    def test_beenden_nimmt_keine_neuen_aktionen_an(self):
        server = W.Server.__new__(W.Server)
        import threading
        server._aktiv_lock, server.aktiv, server.endet = threading.Lock(), 0, True
        with self.assertRaisesRegex(ValueError, "beendet"):
            with server._aktion_laeuft():
                pass


class TestsUndWorkflowsTests(Basis):
    """N32-N36."""

    def lesen(self, *teile):
        with open(os.path.join(os.path.dirname(HIER), *teile), encoding="utf-8") as f:
            return f.read()

    def test_seite_ueber_den_server_mit_festen_ausnahmen(self):
        import html
        import http.client
        import threading
        server = W.Server()
        t = threading.Thread(target=server.httpd.serve_forever, daemon=True)
        t.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
            c.request("GET", "/?t=" + server.token, headers={"Host": f"127.0.0.1:{server.port}"})
            seite = c.getresponse().read().decode("utf-8")
            self.assertNotIn("__AUSGENOMMEN__", seite)
            self.assertIn(html.escape("  ".join(W.STANDARD_AUSSCHLUSS)), seite)
        finally:
            server.httpd.shutdown()
            server.httpd.server_close()

    def test_entwurfstext_aus_bauen_yml_wird_erkannt(self):
        import re
        for name in ("bauen.yml", "pruefen.yml"):
            with self.subTest(name=name):
                yml = self.lesen(".github", "workflows", name)
                vorlage = re.search(r"printf '(Ungeprüfter Entwurf[^']*)'", yml).group(1)
                commit, summe, lauf = "a" * 40, "b" * 64, "https://github.com/Besitzer/Name/actions/runs/123"
                text = vorlage.replace("\\n", "\n") % (commit, summe, lauf)   # wie printf
                self.assertEqual(W._ENTWURF_COMMIT_RE.search(text).group(1), commit)
                self.assertEqual(W._ENTWURF_SUMME_RE.search(text).group(1), summe)
                self.assertEqual(W._ENTWURF_LAUF_RE.search(text).group(1), lauf)

    def test_cryptography_wie_in_der_exe(self):
        yml = self.lesen(".github", "workflows", "pruefen.yml")
        self.assertNotRegex(yml, r"cryptography==\d")   # Version kommt aus requirements-bau.txt
        self.assertIn("grep -E '^cryptography==' requirements-bau.txt", yml)
        self.assertRegex(self.lesen("requirements-bau.txt"), r"(?m)^cryptography==\d+\.\d+\.\d+ ")

    @unittest.skipUnless(os.name == "nt", "nur unter Windows")
    def test_echte_junction(self):
        import _winapi
        import importlib.util
        spec = importlib.util.spec_from_file_location("signatur_pruefen", os.path.join(
            os.path.dirname(HIER), "Pruefmodul", "signatur_pruefen.py"))
        P = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(P)
        self.schreiben("a.txt", b"1")
        self.schreiben("ziel/b.txt", b"2")
        ordner = os.path.join(self.tmp, "ordner")
        _winapi.CreateJunction(os.path.join(ordner, "ziel"), os.path.join(ordner, "link"))
        self.assertRaisesRegex(ValueError, "Verknüpfung", W.dateiliste, ordner, "alle", [])
        self.assertRaises(P.SignaturFehler, P._dateiliste, ordner, [])


class HandbuchTests(unittest.TestCase):
    """Handbuch nur als PDF: „i“ neben der Version öffnet Handbuch.pdf."""

    def test_info_knopf_oeffnet_pdf(self):
        kopf = W.SEITE.split("</header>")[0]
        self.assertLess(kopf.index("Version __VERSION__"), kopf.index('id="info-knopf"'))   # neben der Version
        self.assertIn('window.open("/handbuch.pdf?t="', W.SEITE)
        self.assertNotIn("hb-dialog", W.SEITE)

    def test_pdf_passt_zur_version_und_quelle(self):
        import re
        with open(W.handbuch_pfad(), "rb") as f:
            pdf = f.read()
        self.assertTrue(pdf.startswith(b"%PDF-"))
        m = re.search(rb"/Title\s*<FEFF([0-9A-Fa-f]+)>", pdf)
        titel = bytes.fromhex(m.group(1).decode()).decode("utf-16-be")
        self.assertEqual(titel, f"Handbuch – Signier-Werkzeug {W.VERSION}",
                         "Handbuch.pdf veraltet: node docs/handbuch_pdf.js ausführen")
        with open(os.path.join(os.path.dirname(HIER), "docs", "handbuch_quelle.html"), encoding="utf-8") as f:
            quelle = f.read()
        for teil in ("Profile &amp; Schlüssel", "Signieren", "Prüfen", "QNAP", "© 2026 Hans-Christoph Rose"):
            self.assertIn(teil, quelle)

    def test_server_liefert_pdf_nur_mit_token(self):
        import http.client
        import threading
        server = W.Server()
        threading.Thread(target=server.httpd.serve_forever, daemon=True).start()
        try:
            def holen(pfad):
                c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
                c.request("GET", pfad, headers={"Host": f"127.0.0.1:{server.port}"})
                r = c.getresponse()
                return r.status, r.getheader("Content-Type"), r.read()
            status, typ, daten = holen("/handbuch.pdf?t=" + server.token)
            self.assertEqual((status, typ), (200, "application/pdf"))
            self.assertTrue(daten.startswith(b"%PDF-"))
            self.assertEqual(holen("/handbuch.pdf")[0], 403)
            self.assertEqual(holen("/anderes.pdf?t=" + server.token)[0], 403)
        finally:
            server.httpd.shutdown()
            server.httpd.server_close()

    def test_exe_enthaelt_handbuch(self):
        with open(os.path.join(os.path.dirname(HIER), ".github", "workflows", "bauen.yml"), encoding="utf-8") as f:
            self.assertIn('--add-data "Handbuch.pdf:."', f.read())


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
