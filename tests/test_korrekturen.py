# -*- coding: utf-8 -*-
"""Tests zu den Korrekturen aus der Fehlersuche (Befundliste H1–H8, M1, M2,
M4, M10, M12). Nur Platzhalter, eigene Test-Schlüssel, kein Netz."""
import base64
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import signier_werkzeug as W  # noqa: E402

KENNWORT = "Test-Kennwort-123"
STAND, NEU = "a" * 40, "b" * 40


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="korrektur-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata")})
        self._env.start()
        W._sitzung["token"] = ""
        W._geheim_bekannt.clear()

    def tearDown(self):
        self._env.stop()
        W._sitzung["token"] = ""
        shutil.rmtree(self.tmp, ignore_errors=True)

    def schreiben(self, wurzel, rel, daten):
        pfad = os.path.join(wurzel, *rel.split("/"))
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        with open(pfad, "wb") as f:
            f.write(daten)

    def profil(self, regel="alle"):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        privat = Ed25519PrivateKey.generate()
        pr = {"id": "test" + os.urandom(4).hex(), "name": "Beispiel", "oeffentlich": W.oeffentlich_text(privat),
              "regel": regel, "ausschluss": [], "repo": "Besitzer/beispiel", "zweig": "main"}
        W.neu_anlegen(W.schluessel_pfad(pr), privat.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(KENNWORT.encode())))
        W.profile_speichern({"profile": [pr]})
        return pr


class SignierenGithubTests(Basis):
    """H2, H3, H4: Tag vorher prüfen, ein Commit auf den geprüften Stand, kein ✅ bei Teilerfolg."""

    def lauf(self, version=b"1.0.0\n", tag=None, tag_setzen=None):
        pr = self.profil()
        W._sitzung["token"] = "ghp_" + "x" * 36
        quelle = os.path.join(self.tmp, "quelle")
        self.schreiben(quelle, "VERSION", version)
        self.schreiben(quelle, "app.py", b"print(1)\n")

        def laden(repo, zweig, token, ziel):
            ordner = os.path.join(ziel, "stand")
            shutil.copytree(quelle, ordner)
            return ordner, STAND
        hochladen = mock.Mock(return_value=NEU)
        with mock.patch.object(W, "github_laden", laden), \
                mock.patch.object(W, "github_baum", return_value=[]), \
                mock.patch.object(W, "_tag_commit", return_value=tag), \
                mock.patch.object(W, "github_hochladen_commit", hochladen), \
                mock.patch.object(W, "github_tag_setzen", tag_setzen or mock.Mock(return_value="v1.0.0")):
            try:
                return W.aktion("signieren_github", {"id": pr["id"], "kennwort": KENNWORT}), hochladen
            except ValueError as e:
                return e, hochladen

    def test_normal(self):
        d, hoch = self.lauf()
        self.assertTrue(d["ok"])
        self.assertIn("Tag v1.0.0 gesetzt", d["meldung"])
        args = hoch.call_args[0]
        self.assertEqual(args[5], STAND)                       # Vorgänger = geprüfter Stand
        self.assertEqual(list(args[3]), [W.SIGNATUR_DATEI])   # auch „andere Software“ über den sicheren Weg

    def test_tag_auf_unsigniertem_stand_bricht_vor_dem_hochladen_ab(self):
        e, hoch = self.lauf(tag=STAND)
        self.assertIsInstance(e, ValueError)
        self.assertIn("noch nicht signierten Stand", str(e))
        hoch.assert_not_called()

    def test_tag_auf_anderem_stand(self):
        e, hoch = self.lauf(tag="c" * 40)
        self.assertIsInstance(e, ValueError)
        hoch.assert_not_called()

    def test_version_mit_bom_oder_ungueltig(self):
        for version, text in ((b"\xef\xbb\xbf1.0.0\n", "BOM"), (b"", "ungültig"), (b"neu\n", "ungültig")):
            with self.subTest(version=version):
                e, hoch = self.lauf(version=version)
                self.assertIsInstance(e, ValueError)
                self.assertIn(text, str(e))
                hoch.assert_not_called()
            shutil.rmtree(os.path.join(self.tmp, "quelle"))

    def test_tag_scheitert_kein_erfolg(self):
        e, hoch = self.lauf(tag_setzen=mock.Mock(side_effect=ValueError("GitHub hat die Anfrage abgelehnt.")))
        self.assertIsInstance(e, ValueError)
        self.assertIn("konnte nicht gesetzt", str(e))
        self.assertIn("Bis dahin noch nicht verteilen", str(e))
        self.assertNotIn("Jetzt kann das Update", str(e))
        hoch.assert_called_once()


class HochladenTests(Basis):
    def test_commitnachricht_nur_signatur(self):
        posts = []

        def gh(pfad, token, methode="GET", daten=None, **k):
            posts.append((methode, pfad, daten))
            if pfad.endswith("/branches/main"):
                return {"commit": {"sha": STAND}}
            if pfad.endswith(f"/git/commits/{STAND}"):
                return {"tree": {"sha": "d" * 40}}
            if pfad.endswith("/git/blobs"):
                return {"sha": W._git_blob_sha(base64.b64decode(daten["content"]))}
            if pfad.endswith("/git/trees"):
                return {"sha": "e" * 40}
            if pfad.endswith("/git/commits"):
                return {"sha": NEU}
            return {}
        with mock.patch.object(W, "_gh", side_effect=gh):
            W.github_hochladen_commit("Besitzer/beispiel", "main", "t", {"SIGNATUR.json": "{}\n"}, "1.0.0", STAND, [])
        commit = [p for p in posts if p[1].endswith("/git/commits") and p[0] == "POST"][0][2]
        self.assertEqual(commit["message"], "SIGNATUR.json für Version 1.0.0")
        self.assertEqual(commit["parents"], [STAND])

    def test_vorspulen_zeitueberschreitung_aber_erledigt(self):
        stand = {"sha": STAND}

        def gh(pfad, token, methode="GET", daten=None, **k):
            if pfad.endswith("/branches/main"):
                return {"commit": {"sha": stand["sha"]}}
            if pfad.endswith(f"/git/commits/{STAND}"):
                return {"tree": {"sha": "d" * 40}}
            if pfad.endswith("/git/blobs"):
                return {"sha": W._git_blob_sha(base64.b64decode(daten["content"]))}
            if pfad.endswith("/git/trees"):
                return {"sha": "e" * 40}
            if pfad.endswith("/git/commits"):
                return {"sha": NEU}
            if methode == "PATCH":
                stand["sha"] = NEU   # GitHub hat ausgeführt, die Antwort ging verloren
                raise ValueError("GitHub nicht erreichbar (TimeoutError).")
            return {}
        with mock.patch.object(W, "_gh", side_effect=gh):
            self.assertEqual(W.github_hochladen_commit("Besitzer/beispiel", "main", "t", {"SIGNATUR.json": "{}\n"},
                                                       "1.0.0", STAND, []), NEU)

    def test_tag_gleichzeitig_gesetzt(self):
        tags = {"v1.0.0": None}

        def tag_commit(repo, token, name):
            return tags[name]

        def gh(pfad, token, methode="GET", daten=None, **k):
            tags["v1.0.0"] = NEU   # ein zweiter Lauf war schneller
            raise W.GitHubFehler("GitHub hat die Anfrage abgelehnt.", 422)
        with mock.patch.object(W, "_tag_commit", side_effect=tag_commit), mock.patch.object(W, "_gh", side_effect=gh):
            self.assertEqual(W.github_tag_setzen("Besitzer/beispiel", "t", "1.0.0", NEU), "v1.0.0")


class DateienTests(Basis):
    """H7: beschädigte Datendateien nie still als leer lesen."""

    def test_profile_mit_bom_werden_gelesen(self):
        self.profil()
        pfad = W._profile_datei()
        with open(pfad, "rb") as f:
            daten = f.read()
        with open(pfad, "wb") as f:
            f.write(b"\xef\xbb\xbf" + daten.replace(b"\n", b"\r\n"))
        self.assertEqual(len(W.profile_laden()["profile"]), 1)

    def test_kaputte_profile_werden_nicht_ueberschrieben(self):
        self.profil()
        pfad = W._profile_datei()
        with open(pfad, "wb") as f:
            f.write(b'{"profile": [ kaputt')
        with self.assertRaisesRegex(ValueError, "beschädigt"):
            W.aktion("zustand", {})
        with self.assertRaises(ValueError):
            W.aktion("profil_speichern", {"name": "Neu", "regel": "alle"})
        with open(pfad, "rb") as f:
            self.assertEqual(f.read(), b'{"profile": [ kaputt')   # unverändert
        for inhalt in (b"[]", b"\xff\xfe", b"[" * 100000):
            with open(pfad, "wb") as f:
                f.write(inhalt)
            self.assertRaises(ValueError, W.profile_laden)

    def test_kaputte_qnap_datei(self):
        os.makedirs(W.daten_ordner(), exist_ok=True)
        with open(os.path.join(W.daten_ordner(), "qnap.json"), "wb") as f:
            f.write(b"{nicht json")
        self.assertRaisesRegex(ValueError, "beschädigt", W._qnap_laden)


class TokenTests(Basis):
    def test_unlesbares_dpapi_token_blockiert_nichts(self):
        """M2: z. B. profile.json auf einen anderen PC kopiert."""
        with mock.patch.object(W.os, "name", "nt"), \
                mock.patch.object(W, "_dpapi", side_effect=OSError("DPAPI fehlgeschlagen")):
            self.assertEqual(W.geheim_lesen("dpapi:" + base64.b64encode(b"x").decode()), "")
            ansicht = W._ansicht({"github_token": "dpapi:" + base64.b64encode(b"x").decode()})
        self.assertEqual(ansicht["token_speicher"], "unlesbar")
        self.assertIn("unlesbar:", W.SEITE)


class BauSignaturSchreibenTests(Basis):
    """M4: SIGNATUR.json und SIGNATUR-BAU.json gehören zusammen."""

    def dashboard(self, wurzel, bau=True):
        self.schreiben(wurzel, "app.py", b'UPDATE_ALLOWED_FILES = ("app.py", "VERSION", "SIGNATUR.json")\n'
                                         b'UPDATE_ALLOWED_DIRS = ("templates",)\n')
        self.schreiben(wurzel, "VERSION", b"1.8.9\n")
        if bau:
            self.schreiben(wurzel, "Dockerfile", b"FROM beispiel\n")

    def test_zweite_datei_scheitert_erste_wird_zurueckgesetzt(self):
        w = os.path.join(self.tmp, "stand")
        self.dashboard(w)
        pr = self.profil("speedrace")
        self.schreiben(w, "SIGNATUR-BAU.json", b"alt\n")
        os.mkdir(os.path.join(w, "SIGNATUR.json"))   # Schreiben von SIGNATUR.json muss scheitern
        self.assertRaises(ValueError, W.signieren_mit_bau, w, pr, KENNWORT)
        with open(os.path.join(w, "SIGNATUR-BAU.json"), "rb") as f:
            self.assertEqual(f.read(), b"alt\n")

    def test_ohne_vorherige_bau_signatur_wird_sie_wieder_entfernt(self):
        w = os.path.join(self.tmp, "stand")
        self.dashboard(w)
        pr = self.profil("speedrace")
        with mock.patch.object(W, "_signatur_json_pruefen", side_effect=ValueError("Probe")):
            self.assertRaises(ValueError, W.signieren_mit_bau, w, pr, KENNWORT)
        self.assertFalse(os.path.exists(os.path.join(w, "SIGNATUR-BAU.json")))
        self.assertFalse(os.path.exists(os.path.join(w, "SIGNATUR.json")))

    def test_alte_bau_signatur_ohne_bau_dateien(self):
        w = os.path.join(self.tmp, "stand")
        self.dashboard(w, bau=False)
        pr = self.profil("speedrace")
        self.schreiben(w, "SIGNATUR-BAU.json", b"{}\n")
        self.assertRaisesRegex(ValueError, "alte SIGNATUR-BAU.json", W.signieren_mit_bau, w, pr, KENNWORT)
        self.assertFalse(os.path.exists(os.path.join(w, "SIGNATUR.json")))


class ServerTests(Basis):
    """M12: Beenden nicht mitten in einer laufenden Aktion."""

    def test_beenden_wartet_auf_laufende_aktion(self):
        server = W.Server()
        t = threading.Thread(target=server.httpd.serve_forever, daemon=True)
        t.start()

        def post(name):
            c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
            c.request("POST", "/api/" + name, body=b"{}", headers={"X-Token": server.token,
                                                                   "Host": f"127.0.0.1:{server.port}"})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        try:
            with server._aktion_laeuft():
                status, d = post("beenden")
                self.assertEqual(status, 400)
                self.assertIn("läuft noch ein Vorgang", d["fehler"])
            status, _ = post("beenden")
            self.assertEqual(status, 200)
            t.join(5)
            self.assertFalse(t.is_alive())
        finally:
            server.httpd.server_close()


class QnapPaketPycTests(unittest.TestCase):
    """H8: der QNAP-Ablauf packt keine kompilierten Python-Dateien ein."""

    def test_pyc_im_tag_commit(self):
        import test_qnap
        t = test_qnap.PaketTests("test_gute_version")
        t.setUp()
        try:
            archiv = t.zipball(aendern={"__pycache__/app.cpython-311.pyc": b"\x00boese"})
            with self.assertRaisesRegex(ValueError, "kompilierte Python-Dateien"):
                t.laden(archiv)
        finally:
            t.tearDown()


if __name__ == "__main__":
    unittest.main()
