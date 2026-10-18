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
sys.path.insert(0, HIER)
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
        for version, text in ((b"\xef\xbb\xbf1.0.0\n", "BOM"), (b"", "x.y.z"), (b"neu\n", "x.y.z"), (b"1..2\n", "x.y.z")):
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

    def _signatur_schreiben_scheitert(self, auch_ruecksetzen=False):
        echt = W.atomar_schreiben
        aufrufe = []

        def schreiben(ordner, name, daten, *a, **k):
            aufrufe.append(name)
            if name == W.SIGNATUR_DATEI or (auch_ruecksetzen and len(aufrufe) > 2):
                raise OSError("gesperrt")
            return echt(ordner, name, daten, *a, **k)
        return mock.patch.object(W, "atomar_schreiben", side_effect=schreiben), aufrufe

    def test_zweite_datei_scheitert_erste_wird_zurueckgesetzt(self):
        w = os.path.join(self.tmp, "stand")
        self.dashboard(w)
        pr = self.profil("speedrace")
        self.schreiben(w, "SIGNATUR-BAU.json", b"alt\n")
        patch, aufrufe = self._signatur_schreiben_scheitert()
        with patch:
            self.assertRaises(OSError, W.signieren_mit_bau, w, pr, KENNWORT)
        self.assertEqual(aufrufe, ["SIGNATUR-BAU.json", "SIGNATUR.json", "SIGNATUR-BAU.json"])   # neu, scheitert, zurück
        with open(os.path.join(w, "SIGNATUR-BAU.json"), "rb") as f:
            self.assertEqual(f.read(), b"alt\n")

    def test_ruecksetzen_scheitert_wird_gemeldet(self):
        w = os.path.join(self.tmp, "stand")
        self.dashboard(w)
        pr = self.profil("speedrace")
        self.schreiben(w, "SIGNATUR-BAU.json", b"alt\n")
        patch, _ = self._signatur_schreiben_scheitert(auch_ruecksetzen=True)
        with patch, self.assertRaisesRegex(ValueError, "passen jetzt nicht zusammen"):
            W.signieren_mit_bau(w, pr, KENNWORT)

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




# ---------------------------------------------------------------------------
# Zweite Runde: M7–M14 und N-Punkte
# ---------------------------------------------------------------------------
import ssl  # noqa: E402
import types  # noqa: E402
import unicodedata  # noqa: E402
import urllib.error  # noqa: E402

import qnap_begleiter as Q  # noqa: E402
import test_qnap  # noqa: E402


class QnapZweiteRunde(test_qnap.Ablauf):
    def bis_hochladen(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="nein")
        self.schritt("werkzeuge", compose="plugin")
        self.schritt("version", tag="v1.8.5")

    def test_eigene_zip_wird_gemerkt_und_nur_sie_geloescht(self):
        """M7"""
        self.bis_hochladen()
        zn = self.b.ansicht()["lauf"]["paket"]["zipname"]
        self.assertRegex(zn, r"^programmordner\.signier-\d{8}-\d{4}\.zip$")
        self.schritt("hochladen")
        self.assertEqual(self.b.ansicht()["zips"], [zn])
        self.b.abbrechen()
        self.assertEqual(self.b.ansicht()["zips"], [zn])   # bleibt auch nach Abbruch gemerkt
        self.b.beginnen("aufraeumen")
        self.schritt("verbindung", root="ja")
        self.b.rueckmelden("alt_loeschen", "uebersprungen", {})
        v = self.b.vorbereiten("zip_loeschen")
        self.assertEqual(v["befehl"], f"cd '/share/BEISPIEL' && if [ -e '{zn}' ]; then rm -- '{zn}'; fi; ls -la")
        self.b.ausfuehren("zip_loeschen", v["marke"], {"bestaetigt": True})
        self.b.rueckmelden("zip_loeschen", "geklappt", {})
        self.assertEqual(self.b.ansicht()["zips"], [])
        self.assertRaises(ValueError, Q.SCHRITTE["zip_loeschen"]["befehl"], test_qnap.profil(root_wert=True), {}, {}, False)

    def test_profil_fest_solange_etwas_gemerkt_ist(self):
        """M8"""
        self.bis_hochladen()
        self.schritt("hochladen")
        self.b.abbrechen()
        self.assertRaisesRegex(ValueError, "bleibt fest", self.b.profil_speichern,
                               {**test_qnap.PROFIL, "programmordner": "/share/ANDERS/programmordner"}, ("quelle01",))
        self.assertRaisesRegex(ValueError, "dasselbe Gerät", self.b.profil_speichern,
                               {**test_qnap.PROFIL, "host": "198.51.100.7"}, ("quelle01",))
        self.b.profil_speichern({**test_qnap.PROFIL, "benutzer": "anderer-benutzer"}, ("quelle01",))   # erlaubt
        # neue Adresse desselben Geräts (z. B. DHCP): nach Bestätigung erlaubt, protokolliert
        self.b.profil_speichern({**test_qnap.PROFIL, "host": "198.51.100.7", "gleiches_geraet": True}, ("quelle01",))
        self.assertEqual(self.b.ansicht()["profil"]["host"], "198.51.100.7")
        self.assertIn("gleiches Gerät bestätigt", self.protokoll())
        # gemerkte ZIP vergessen: danach ist der Ordner frei
        self.assertTrue(self.b.ansicht()["zips"])
        self.b.zips_vergessen()
        self.assertEqual(self.b.ansicht()["zips"], [])
        self.b.profil_speichern({**test_qnap.PROFIL, "programmordner": "/share/ANDERS/programmordner"}, ("quelle01",))

    def test_ueberspringen_nach_ausfuehren_abgelehnt(self):
        """N9"""
        self.b.beginnen("aufraeumen")
        self.schritt("verbindung", root="ja")
        z = self.zustand
        z["alt"] = "programmordner.alt-20260101-1200"
        self._speichern(z)
        v = self.b.vorbereiten("alt_loeschen")
        self.b.ausfuehren("alt_loeschen", v["marke"], {"bestaetigt": True, "name": "programmordner.alt-20260101-1200"})
        self.assertRaisesRegex(ValueError, "schon ausgeführt", self.b.rueckmelden, "alt_loeschen", "uebersprungen", {})

    def test_bau_sperre_ueber_abbruch_hinweg(self):
        """N10"""
        self.b.beginnen("neubau")
        for sid, extra in (("vorbereitung", {}), ("verbindung", {"root": "ja"}), ("werkzeuge", {"compose": "plugin"}),
                           ("ordner", {}), ("zustand", {}), ("bau_vorpruefung", {"treffer": "mehr"})):
            self.schritt(sid, **extra)
        self.schritt("bau_pruefen", "fehler", bauergebnis="2")
        self.b.abbrechen()
        self.assertTrue(self.b.ansicht()["bau_gesperrt"])
        self.b.beginnen("neubau")
        for sid, extra in (("vorbereitung", {}), ("verbindung", {"root": "ja"}), ("werkzeuge", {"compose": "plugin"}),
                           ("ordner", {}), ("zustand", {})):
            self.schritt(sid, **extra)
        v = self.b.vorbereiten("bau_vorpruefung")
        self.b.ausfuehren("bau_vorpruefung", v["marke"], {"bestaetigt": True})
        self.assertRaisesRegex(ValueError, "Ergebnis 2", self.b.rueckmelden, "bau_vorpruefung", "geklappt",
                               {"treffer": "0", "ohne_pruefung": True})
        self.b.abbrechen()
        self.b.sperre_aufheben()
        self.assertFalse(self.b.ansicht()["bau_gesperrt"])
        self.assertIn("Bau-Sperre vom Benutzer aufgehoben", self.protokoll())

    def test_laden_ohne_sperre(self):
        """N13: während des Downloads bleibt der Begleiter bedienbar."""
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="ja")
        self.schritt("werkzeuge", compose="plugin")
        v = self.b.vorbereiten("version")
        fertig = []

        def paket(pr, tag, name):
            t = threading.Thread(target=lambda: fertig.append(self.b.abbrechen()))
            t.start()
            t.join(5)
            return self.paket(pr, tag, name)
        with self.assertRaisesRegex(ValueError, "abgebrochen"):
            self.b.ausfuehren("version", v["marke"], {"bestaetigt": True, "tag": "v1.8.5"}, paket)
        self.assertEqual(len(fertig), 1)   # Abbrechen lief während des Ladens durch

    def test_geaenderter_ablauf_nach_update(self):
        """N14"""
        self.b.beginnen("neubau")
        z = self.zustand
        z["lauf"]["schritte"] = ["vorbereitung", "verbindung", "bauen"]
        self._speichern(z)
        self.assertRaisesRegex(ValueError, "geändert", self.b.vorbereiten, "vorbereitung")


class QnapHttpZertifikat(unittest.TestCase):
    def test_zertifikatsfehler(self):
        """N12"""
        oeffner = mock.Mock()
        oeffner.open.side_effect = urllib.error.URLError(ssl.SSLCertVerificationError("selbst signiert"))
        with mock.patch.object(Q.urllib.request, "build_opener", return_value=oeffner):
            self.assertIn("Zertifikat", Q.http_pruefen("https://192.0.2.10:8443")["text"])


class WerkzeugZweiteRunde(Basis):
    def test_unvollstaendiger_download(self):
        """N1"""
        antwort = types.SimpleNamespace(headers={"Content-Length": "100"}, read=mock.Mock(side_effect=[b"x" * 10, b""]))
        self.assertRaisesRegex(ValueError, "unvollständig", W._lesen, antwort, 1000, None)

    def test_aelterer_entwurf_wird_nicht_veroeffentlicht(self):
        """N4"""
        with mock.patch.object(W, "privat_laden", return_value=mock.Mock()), \
                mock.patch.object(W, "oeffentlich_text", return_value=W.WERKZEUG_SCHLUESSEL), \
                mock.patch.object(W, "werkzeug_entwurf", return_value={"tag_name": "v1.2.7"}), \
                mock.patch.object(W, "werkzeug_neueste", return_value=("1.2.8", {})), \
                mock.patch.object(W, "_herunterladen") as laden:
            self.assertRaisesRegex(ValueError, "nicht neuer", W.werkzeug_veroeffentlichen, {"id": "x" * 8}, "k", "t")
            laden.assert_not_called()

    def test_alle_tags(self):
        """N16"""
        refs = [{"ref": f"refs/tags/v1.{i}.0"} for i in range(150)] + [{"ref": "refs/tags/vkaputt"}]
        with mock.patch.object(W, "_gh", return_value=refs) as gh:
            v = W.github_versionen("Besitzer/beispiel", "t")
        self.assertIn("matching-refs/tags/v", gh.call_args[0][0])
        self.assertEqual(v[0], "v1.149.0")

    def test_signatur_zu_gross(self):
        """M13"""
        w = os.path.join(self.tmp, "gross")
        self.schreiben(w, "a.txt", b"1")
        pr = self.profil()
        with mock.patch.object(W, "MAX_SIGNATUR_BYTES", 50):
            self.assertRaisesRegex(ValueError, "größer", W.signieren, w, pr, KENNWORT, "1.0.0")
        self.assertFalse(os.path.exists(os.path.join(w, "SIGNATUR.json")))

    def test_update_doppelter_fehler_behaelt_neue_exe(self):
        """M14"""
        d = os.path.join(self.tmp, "programm")
        os.makedirs(d)
        exe = os.path.join(d, "Signier-Werkzeug.exe")
        with open(exe, "wb") as f:
            f.write(b"alt")
        echt = os.replace

        def replace(a, b):
            if b == exe:
                raise PermissionError("gesperrt")
            return echt(a, b)
        neu = b"MZ" + b"\0" * 100
        with mock.patch.object(W, "_laufende_exe", return_value=exe), \
                mock.patch.object(W, "werkzeug_neueste", return_value=("99.0.0", {"assets": [
                    {"name": W.EXE_NAME, "browser_download_url": "u1"}, {"name": W.SIGNATUR_DATEI, "browser_download_url": "u2"}]})), \
                mock.patch.object(W, "_herunterladen", side_effect=[neu, b"{}"]), \
                mock.patch.object(W, "_exe_plausibel"), mock.patch.object(W, "werkzeug_signatur_pruefen"), \
                mock.patch.object(W.os, "replace", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "umbenennen"):
                W.werkzeug_update()
        reste = os.listdir(d)
        self.assertIn("Signier-Werkzeug.exe.alt", reste)
        self.assertTrue(any(open(os.path.join(d, n), "rb").read() == neu for n in reste))   # neue exe nicht gelöscht

    def test_mehr_als_50_ausnahmen(self):
        """N26"""
        self.profil()
        self.assertRaisesRegex(ValueError, "50", W.aktion, "profil_speichern",
                               {"name": "X", "regel": "alle", "ausschluss": "\n".join(f"m{i}/*" for i in range(51))})

    def test_schluessel_wieder_weg_wenn_profil_nicht_gespeichert(self):
        """N32"""
        W.profile_speichern({"profile": [{"id": "abcdef0123456789", "name": "X", "regel": "alle", "oeffentlich": ""}]})
        with mock.patch.object(W, "profile_speichern", side_effect=PermissionError("gesperrt")):
            self.assertRaises(PermissionError, W.aktion, "schluessel_neu", {"id": "abcdef0123456789", "kennwort": KENNWORT})
        self.assertFalse(os.path.exists(W.schluessel_pfad({"id": "abcdef0123456789"})))

    def test_bau_dateiliste_wie_os_walk(self):
        """N35/N39"""
        w = os.path.join(self.tmp, "bau")
        self.schreiben(w, "tools/__pycache__", b"eine Datei, kein Ordner")   # Dashboard hasht sie
        self.schreiben(w, "tools/a.sh", b"x")
        self.schreiben(w, "dockerfile", b"klein geschrieben")               # nicht „Dockerfile“
        ist, unz = W.bau_dateiliste(w)
        self.assertEqual(sorted(ist), ["tools/__pycache__", "tools/a.sh"])
        self.assertEqual(unz, [])
        self.assertTrue(W.bau_bereich("tools/__pycache__"))
        self.assertFalse(W.bau_bereich("tools/__pycache__/x.cpython-314.pyc"))

    def test_tiefes_json_in_signaturen(self):
        """N36"""
        w = os.path.join(self.tmp, "tief")
        self.schreiben(w, "SIGNATUR.json", b"[" * 100000)
        self.schreiben(w, "SIGNATUR-BAU.json", b"[" * 100000)
        self.assertFalse(W.pruefen(w, "x" * 44)["ok"])
        self.assertEqual(W.bau_pruefen(w, "x" * 44)["stufe"], "fehler")

    def test_schluesselbund_kette(self):
        """N40"""
        class Sicher:
            priority = 5

        class PlaintextKeyring:
            priority = 1

        class ChainerBackend:
            priority = 10
            backends = [PlaintextKeyring(), Sicher()]
        fake = mock.MagicMock()
        fake.get_keyring.return_value = ChainerBackend()
        with mock.patch.dict(sys.modules, {"keyring": fake}), mock.patch.object(W.os, "name", "posix"):
            self.assertIsInstance(W._keyring(), Sicher)
            ChainerBackend.backends = [PlaintextKeyring()]
            self.assertIsNone(W._keyring())

    def test_nfc_und_nfd(self):
        """N42"""
        import importlib.util
        spec = importlib.util.spec_from_file_location("signatur_pruefen", os.path.join(os.path.dirname(HIER), "Pruefmodul",
                                                                                      "signatur_pruefen.py"))
        P = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(P)
        w = os.path.join(self.tmp, "nfc")
        name = unicodedata.normalize("NFC", "Größe.txt")
        self.schreiben(w, name, b"1")
        pr = self.profil()
        W.signieren(w, pr, KENNWORT, "1.0.0")
        sig = json.loads(open(os.path.join(w, "SIGNATUR.json"), encoding="utf-8").read())
        self.assertIn(name, sig["dateien"])
        # Prüfer, dessen Dateisystem NFD liefert (macOS): gleiches Ergebnis in Werkzeug und Prüfmodul
        ist = {unicodedata.normalize("NFD", n): h for n, h in W.dateiliste(w, "alle").items()}
        self.assertNotEqual(list(ist), [name])
        with mock.patch.object(W, "dateiliste", return_value=ist):
            self.assertTrue(W.pruefen(w, pr["oeffentlich"])["ok"])
        with mock.patch.object(P, "_dateiliste", return_value=ist):
            self.assertEqual(P.pruefen(w, pr["oeffentlich"]), "1.0.0")

    def test_reparse_points(self):
        """N43: nur Symlinks/Junctions (Name-Surrogates) sind Verknüpfungen."""
        import stat as st
        datei = types.SimpleNamespace(st_mode=st.S_IFREG | 0o644, st_file_attributes=0x400, st_reparse_tag=0)
        self.assertEqual(W._art(datei), "datei")   # z. B. OneDrive-Platzhalter, von Windows aufgelöst
        junction = types.SimpleNamespace(st_mode=st.S_IFDIR | 0o755, st_file_attributes=0x400, st_reparse_tag=0xA0000003)
        self.assertEqual(W._art(junction), "verknuepfung")
        alt = types.SimpleNamespace(st_mode=st.S_IFDIR | 0o755, st_file_attributes=0x400)   # ohne st_reparse_tag
        self.assertEqual(W._art(alt), "verknuepfung")

    def test_git_arbeitsordner_hinweis(self):
        """N44"""
        pr = self.profil()
        w = os.path.join(self.tmp, "git")
        self.schreiben(w, "a.txt", b"1")
        self.schreiben(w, ".git/HEAD", b"ref")
        d = W.aktion("signieren_ordner", {"id": pr["id"], "kennwort": KENNWORT, "ordner": w})
        self.assertIn("Git-Arbeitsordner", d["meldung"])

    def test_feste_ausnahmen_in_der_seite(self):
        """N27"""
        self.assertIn("__AUSGENOMMEN__", W.SEITE)
        self.assertNotIn("__AUSGENOMMEN__", W.SEITE.replace("__AUSGENOMMEN__", "x"))

    def test_dialog_ohne_sperre(self):
        """M11: das Auswahlfenster wartet nicht auf die globale Sperre."""
        gesperrt, frei = threading.Event(), threading.Event()

        def halten():
            with W._lock:
                gesperrt.set()
                frei.wait(5)
        t = threading.Thread(target=halten)
        t.start()
        gesperrt.wait(5)
        try:
            with mock.patch.object(W, "ordner_waehlen", return_value="C:\\\\Ordner"):
                self.assertEqual(W.aktion("ordner_waehlen", {}), {"pfad": "C:\\\\Ordner"})
        finally:
            frei.set()
            t.join(5)


class ReservierteNamenTests(unittest.TestCase):
    def test_wie_ntpath(self):
        """N3"""
        for name in ("NUL.tar.gz", "con.a.b", "nul .txt", "AUX", "com1.txt", "lpt¹.log"):
            with self.subTest(name=name):
                self.assertRaises(ValueError, W.zip_pfad_teile, "ordner/" + name)
        for name in ("console.txt", "nullable.py", "auxiliar.md", "com10.txt"):
            with self.subTest(name=name):
                W.zip_pfad_teile("ordner/" + name)


class InstanzTests(Basis):
    def test_nur_eine_instanz(self):
        """N25: eine zweite Instanz bekommt die Sperre nicht (anderer Prozess)."""
        self.assertTrue(W._instanz_sperren(0))
        try:
            import subprocess
            code = ("import sys; sys.path.insert(0, %r); import signier_werkzeug as W; "
                    "sys.exit(0 if W._instanz_sperren(0) else 3)") % os.path.dirname(HIER)
            r = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                               timeout=60)
            self.assertEqual(r.returncode, 3)
        finally:
            os.close(W._INSTANZ.pop("fd"))


if __name__ == "__main__":
    unittest.main()
