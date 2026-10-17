# -*- coding: utf-8 -*-
"""Sicherheitstests für das Signier-Werkzeug (python -m unittest discover -s tests).

Läuft unter Linux und Windows (Workflows pruefen.yml und bauen.yml); Tests,
die Symlinks oder FIFOs brauchen, werden übersprungen, wo das System sie
nicht anlegen kann.
"""
import base64
import hashlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
import unicodedata
import zipfile
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
WURZEL = os.path.dirname(HIER)
sys.path.insert(0, WURZEL)
import signier_werkzeug as W  # noqa: E402

_spec = importlib.util.spec_from_file_location("signatur_pruefen", os.path.join(WURZEL, "Pruefmodul", "signatur_pruefen.py"))
P = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(P)


def _symlink_moeglich():
    with tempfile.TemporaryDirectory() as t:
        try:
            os.symlink(os.path.join(t, "ziel"), os.path.join(t, "link"))
            return True
        except (OSError, NotImplementedError, AttributeError):
            return False


SYMLINK = _symlink_moeglich()
FIFO = hasattr(os, "mkfifo")


def zip_bauen(eintraege, praefix="owner-repo-0123abc/"):
    """eintraege: Liste von (Name, Daten) oder ZipInfo-Paaren."""
    puffer = io.BytesIO()
    with zipfile.ZipFile(puffer, "w", zipfile.ZIP_DEFLATED) as z:
        if praefix:
            z.writestr(praefix, "")
        for name, daten in eintraege:
            if isinstance(name, zipfile.ZipInfo):
                z.writestr(name, daten)
            else:
                z.writestr(praefix + name, daten)
    puffer.seek(0)
    return puffer


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sw-test-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata"), "NO_PROXY": "*", "no_proxy": "*"})
        self._env.start()
        W._sitzung["token"] = ""
        W._geheim_bekannt.clear()

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def schreiben(self, rel, daten=b"x"):
        pfad = os.path.join(self.tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        with open(pfad, "wb") as f:
            f.write(daten)
        return pfad

    def profil(self, regel="alle", ausschluss=None):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        privat = Ed25519PrivateKey.generate()
        pr = {"id": "test" + os.urandom(4).hex(), "oeffentlich": W.oeffentlich_text(privat), "regel": regel,
              "ausschluss": ausschluss or []}
        W.neu_anlegen(W.schluessel_pfad(pr), privat.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"Test-Kennwort-123")))
        return pr


# ---------------------------------------------------------------------------
# 1 + 4: ZIP-Import - Pfade, Typen, Kollisionen, Ressourcen, Aufräumen
# ---------------------------------------------------------------------------
class ZipTests(Basis):
    BOESE = ["../ausserhalb.txt", "..\\..\\ausserhalb.txt", "/absolut/datei", "C:\\Windows\\datei", "C:..\\..\\datei",
             "C:datei", "C:/datei", "\\\\server\\share\\datei", "//server/share/datei", "a/../../ausserhalb.txt",
             "a/./b", "a//b", "CON", "nul.txt", "Com1", "datei.", "datei ", "a:b", "a|b", "a*b", "x\x01y",
             "ordner/../../ausserhalb.txt"]

    def entpacken(self, puffer, **grenzen):
        ziel = tempfile.mkdtemp(dir=self.tmp)
        try:
            return W.zip_entpacken(puffer, ziel, grenzen or None), ziel
        except ValueError:
            self.assertEqual(os.listdir(ziel), [], "abgelehntes Archiv hat Dateien hinterlassen")
            raise

    def test_boese_pfade_abgelehnt(self):
        for name in self.BOESE:
            with self.subTest(name=name):
                vorher = sorted(os.listdir(self.tmp))
                with self.assertRaises(ValueError):
                    self.entpacken(zip_bauen([(name, b"boese")]))
                nachher = [n for n in sorted(os.listdir(self.tmp)) if n not in vorher]
                self.assertTrue(all(os.path.isdir(os.path.join(self.tmp, n)) for n in nachher))
                self.assertFalse(os.path.exists(os.path.join(self.tmp, "ausserhalb.txt")))
                self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), "ausserhalb.txt")))

    def test_pfadpruefung_einzeln(self):
        for name in self.BOESE:
            with self.subTest(name=name), self.assertRaises(ValueError):
                W.zip_pfad_teile(name)
        self.assertEqual(W.zip_pfad_teile("templates/index.html"), ["templates", "index.html"])

    def test_gutes_archiv(self):
        anzahl, ziel = self.entpacken(zip_bauen([("app.py", b"print(1)\n"), ("templates/a.html", b"<p>"),
                                                  ("leer/", b"")]))
        self.assertEqual(anzahl, 2)
        with open(os.path.join(ziel, "templates", "a.html"), "rb") as f:
            self.assertEqual(f.read(), b"<p>")
        self.assertTrue(os.path.isdir(os.path.join(ziel, "leer")))

    def test_symlink_und_sondertypen_abgelehnt(self):
        for modus in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644, stat.S_IFCHR | 0o644, stat.S_IFSOCK | 0o644):
            with self.subTest(modus=oct(modus)):
                info = zipfile.ZipInfo("owner-repo-0123abc/link")
                info.create_system = 3
                info.external_attr = modus << 16
                with self.assertRaises(ValueError):
                    self.entpacken(zip_bauen([(info, b"/etc/passwd")]))

    def test_doppelt_und_kollision(self):
        nfc, nfd = unicodedata.normalize("NFC", "é.txt"), unicodedata.normalize("NFD", "é.txt")
        faelle = [[("a.txt", b"1"), ("a.txt", b"2")], [("A.txt", b"1"), ("a.txt", b"2")], [(nfc, b"1"), (nfd, b"2")],
                  [("a", b"1"), ("a/b", b"2")], [("a/b", b"1"), ("A", b"2")], [("Ordner/x", b"1"), ("ordner/y", b"2"), ("ORDNER", b"3")]]
        for eintraege in faelle:
            with self.subTest(eintraege=[n for n, _ in eintraege]), self.assertRaises(ValueError):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self.entpacken(zip_bauen(eintraege))

    def test_aufbau(self):
        with self.assertRaises(ValueError):   # kein gemeinsamer Hauptordner
            self.entpacken(zip_bauen([("a/x", b"1"), ("b/y", b"2")], praefix=""))
        with self.assertRaises(ValueError):   # Datei ohne Hauptordner
            self.entpacken(zip_bauen([("x", b"1")], praefix=""))

    def test_grenzen(self):
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([(f"d{i}", b"x") for i in range(6)]), eintraege=5)
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([("gross", b"x" * 2000)]), datei_bytes=1000)
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([("a", b"x" * 600), ("b", b"x" * 600)]), gesamt_bytes=1000)
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([("a/b/c/d", b"x")]), tiefe=3)
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([("x" * 50, b"x")]), pfad_zeichen=40)
        with self.assertRaises(ValueError):
            self.entpacken(zip_bauen([(f"o/{i}", b"x") for i in range(4)]), je_ordner=3)

    def test_zip_bombe(self):
        with self.assertRaises(ValueError):   # 20 MB Nullen -> wenige KB komprimiert
            self.entpacken(zip_bauen([("bombe.bin", b"\0" * (20 * 1024 * 1024))]))

    def test_verschluesselt_und_kompression(self):
        roh = bytearray(zip_bauen([("x", b"x")]).getvalue())
        for sig, versatz in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):   # Flag "verschlüsselt" setzen
            i = roh.find(sig)
            while i >= 0:
                roh[i + versatz] |= 0x1
                i = roh.find(sig, i + 1)
        self.assertTrue(all(i.flag_bits & 0x1 for i in zipfile.ZipFile(io.BytesIO(bytes(roh))).infolist()))
        with self.assertRaises(ValueError):
            self.entpacken(io.BytesIO(bytes(roh)))
        puffer = io.BytesIO()
        with zipfile.ZipFile(puffer, "w", zipfile.ZIP_BZIP2) as z:
            z.writestr("owner-repo-0123abc/x", b"x")
        puffer.seek(0)
        with self.assertRaises(ValueError):
            self.entpacken(puffer)

    def test_kaputtes_archiv(self):
        with self.assertRaises(ValueError):
            self.entpacken(io.BytesIO(b"PK\x03\x04 kein zip"))

    def test_github_laden_raeumt_auf(self):
        boese = zip_bauen([("ok.txt", b"1"), ("../ausserhalb.txt", b"2")]).getvalue()

        def gh(pfad, token, *a, ziel=None, **k):
            ziel.write(boese)
            return len(boese)
        with mock.patch.object(W, "_zweig_stand", return_value="a" * 40), mock.patch.object(W, "_gh", gh):
            with self.assertRaises(ValueError):
                W.github_laden("owner/repo", "main", "", self.tmp)
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith("stand-")], [])

    def test_github_laden_grenze_download(self):
        class Antwort:
            headers = {}

            def __init__(self):
                self.daten = io.BytesIO(b"x" * 5000)

            def read(self, n):
                return self.daten.read(n)
        with self.assertRaises(ValueError):
            W._lesen(Antwort(), 1000, io.BytesIO())


# ---------------------------------------------------------------------------
# 2 + 9: SIGNATUR.json und atomares Schreiben
# ---------------------------------------------------------------------------
class SchreibTests(Basis):
    def test_ueberschreiben_atomar(self):
        W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"alt")
        W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"neu")
        with open(os.path.join(self.tmp, "SIGNATUR.json"), "rb") as f:
            self.assertEqual(f.read(), b"neu")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["SIGNATUR.json"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tmp, "SIGNATUR.json")).st_mode), 0o644)

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_symlink_am_ziel_abgelehnt(self):
        ziel = os.path.join(self.tmp, "fremd.txt")
        for vorhanden in (True, False):   # auch auf ein (noch) nicht vorhandenes Ziel
            with self.subTest(vorhanden=vorhanden):
                if vorhanden:
                    with open(ziel, "wb") as f:
                        f.write(b"unangetastet")
                link = os.path.join(self.tmp, "SIGNATUR.json")
                os.symlink(ziel, link)
                with self.assertRaises(ValueError):
                    W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"{}")
                if vorhanden:
                    with open(ziel, "rb") as f:
                        self.assertEqual(f.read(), b"unangetastet")
                    os.remove(ziel)
                else:
                    self.assertFalse(os.path.exists(ziel))
                os.remove(link)
                self.assertEqual(os.listdir(self.tmp), [])

    def test_ordner_am_ziel_abgelehnt(self):
        os.mkdir(os.path.join(self.tmp, "SIGNATUR.json"))
        with self.assertRaises(ValueError):
            W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"{}")
        self.assertEqual(os.listdir(self.tmp), ["SIGNATUR.json"])

    def test_hardlink_wird_nicht_durchgeschrieben(self):
        anderes = self.schreiben("anderes.txt", b"bleibt")
        try:
            os.link(anderes, os.path.join(self.tmp, "SIGNATUR.json"))
        except (OSError, AttributeError):
            self.skipTest("Hardlinks nicht möglich")
        W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"neu")
        with open(anderes, "rb") as f:
            self.assertEqual(f.read(), b"bleibt")

    def test_fehler_hinterlaesst_nichts(self):
        W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"alt")
        with mock.patch.object(W.os, "replace", side_effect=OSError("simuliert")):
            with self.assertRaises(OSError):
                W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"neu")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["SIGNATUR.json"])
        with open(os.path.join(self.tmp, "SIGNATUR.json"), "rb") as f:
            self.assertEqual(f.read(), b"alt")

    def test_ungueltiger_inhalt_wird_nicht_geschrieben(self):
        with self.assertRaises(ValueError):
            W.atomar_schreiben(self.tmp, "SIGNATUR.json", b"kein json", pruefen=W._signatur_json_pruefen)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_temp_namen_nicht_vorhersehbar(self):
        self.assertNotEqual(W._tmp_name("x"), W._tmp_name("x"))

    def test_neu_anlegen_exklusiv(self):
        pfad = self.schreiben("a.pem", b"alt")
        with self.assertRaises(FileExistsError):
            W.neu_anlegen(pfad, b"neu")
        with open(pfad, "rb") as f:
            self.assertEqual(f.read(), b"alt")

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_lesen_folgt_keinem_symlink(self):
        ziel = self.schreiben("geheim.txt", b"geheim")
        os.symlink(ziel, os.path.join(self.tmp, "link.txt"))
        with self.assertRaises(ValueError):
            W.regulaer_lesen(os.path.join(self.tmp, "link.txt"))

    @unittest.skipUnless(FIFO, "FIFOs nicht möglich")
    def test_lesen_fifo_blockiert_nicht(self):
        os.mkfifo(os.path.join(self.tmp, "fifo"))
        with self.assertRaises(ValueError):
            W.regulaer_lesen(os.path.join(self.tmp, "fifo"))

    def test_signieren_schreibt_gueltige_datei(self):
        self.schreiben("a.txt", b"Zeile\r\n")
        pr = self.profil("alle", ["appdata/*"])
        W.signieren(self.tmp, pr, "Test-Kennwort-123", "1.0.0")
        r = W.pruefen(self.tmp, pr["oeffentlich"], "alle", ["appdata/*"])
        self.assertTrue(r["ok"], r)


# ---------------------------------------------------------------------------
# 3: Einheitliche Bestandsregel
# ---------------------------------------------------------------------------
def alte_pruefsumme(pfad):
    """Unveränderte Prüfsumme aus Version 1.2.0 (Kompatibilität)."""
    with open(pfad, "rb") as f:
        daten = f.read()
    if not pfad.lower().endswith(W.BINAER) and b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def dashboard_dateiliste(wurzel, items):
    """Nachbau von _signatur_dateiliste des Speedrace-Dashboards (app.py)."""
    out = {}
    for name in items:
        if name == "SIGNATUR.json":
            continue
        pfad = os.path.join(wurzel, name)
        if os.path.isfile(pfad):
            out[name] = alte_pruefsumme(pfad)
            continue
        for root, dirs, files in os.walk(pfad):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for f in sorted(files):
                if not f.endswith(".pyc"):
                    voll = os.path.join(root, f)
                    out[os.path.relpath(voll, wurzel).replace(os.sep, "/")] = alte_pruefsumme(voll)
    return out


class BestandTests(Basis):
    def baum(self):
        self.schreiben("a.txt", b"eins\r\nzwei\r\n")
        self.schreiben("bild.png", b"\x89PNG\r\n\x00")
        self.schreiben("unter/b.py", b"x = 1\n")
        self.schreiben("unter/__pycache__/b.cpython-312.pyc", b"\0")
        self.schreiben(".git/config", b"[core]")
        self.schreiben("logs/x.log", b"1")
        self.schreiben("unter/notiz.log", b"2")

    def test_dateimenge_und_kompatibilitaet(self):
        self.baum()
        aus = ["logs/*", "*.log", "appdata/*"]
        ist = W.dateiliste(self.tmp, "alle", aus)
        self.assertEqual(sorted(ist), ["a.txt", "bild.png", "unter/b.py"])
        for rel, summe in ist.items():
            self.assertEqual(summe, alte_pruefsumme(os.path.join(self.tmp, *rel.split("/"))), rel)
        self.assertEqual(ist, P._dateiliste(self.tmp, aus), "Werkzeug und Prüfmodul weichen ab")

    def test_speedrace_regel_wie_dashboard(self):
        self.schreiben("app.py", b'UPDATE_ALLOWED_FILES = ("app.py", "VERSION", "SIGNATUR.json")\n'
                                 b'UPDATE_ALLOWED_DIRS = ("templates", "static")\n')
        self.schreiben("VERSION", b"9.9.9\n")
        self.schreiben("templates/a.html", b"<p>\r\n")
        self.schreiben("templates/__pycache__/x.pyc", b"\0")
        self.schreiben("static/s/b.js", b"1")
        self.schreiben("nicht_im_update.txt", b"egal")
        ist = W.dateiliste(self.tmp, "speedrace")
        self.assertEqual(ist, dashboard_dateiliste(self.tmp, ["app.py", "VERSION", "SIGNATUR.json", "templates", "static"]))
        pr = self.profil("speedrace")
        version, _, _ = W.signieren(self.tmp, pr, "Test-Kennwort-123")
        self.assertEqual(version, "9.9.9")
        self.assertTrue(W.pruefen(self.tmp, pr["oeffentlich"], "speedrace")["ok"])

    def test_roundtrip_pruefmodul(self):
        self.baum()
        pr = self.profil("alle", ["logs/*", "*.log", "appdata/*"])
        W.signieren(self.tmp, pr, "Test-Kennwort-123", "2.0.0")
        # __pycache__ wird nicht signiert, aber geladen: Prüfmodul und Werkzeug lehnen ab
        with self.assertRaisesRegex(P.SignaturFehler, "Kompilierte Python-Dateien"):
            P.pruefen(self.tmp, pr["oeffentlich"], ["logs/*", "*.log", "appdata/*"])
        self.assertIn("Kompilierte", W.pruefen(self.tmp, pr["oeffentlich"], "alle", ["logs/*", "*.log", "appdata/*"])["fehler"])
        shutil.rmtree(os.path.join(self.tmp, "unter", "__pycache__"))
        self.assertEqual(P.pruefen(self.tmp, pr["oeffentlich"], ["logs/*", "*.log", "appdata/*"]), "2.0.0")
        self.assertTrue(W.pruefen(self.tmp, pr["oeffentlich"], "alle", ["logs/*", "*.log", "appdata/*"])["ok"])

    def test_ausnahmen_unterscheiden_gross_klein_ueberall(self):
        """Gleiches Ergebnis unter Windows und Linux (fnmatchcase, „/“)."""
        self.schreiben("a.txt", b"1")
        self.schreiben("X/Notiz.LOG", b"2")
        self.schreiben("Logs/b.txt", b"3")
        self.schreiben("logs/c.txt", b"4")
        aus = ["*.log", "logs/*"]
        ist = W.dateiliste(self.tmp, "alle", aus)
        self.assertEqual(sorted(ist), ["Logs/b.txt", "X/Notiz.LOG", "a.txt"])
        self.assertEqual(ist, P._dateiliste(self.tmp, aus))
        self.assertEqual(W.dateiliste(self.tmp, "alle", ["logs\\*"]), W.dateiliste(self.tmp, "alle", ["logs/*"]))

    def test_abweichungen_erkannt(self):
        self.baum()
        aus = ["logs/*", "*.log", "appdata/*"]
        pr = self.profil("alle", aus)
        W.signieren(self.tmp, pr, "Test-Kennwort-123", "1.0.0")
        self.schreiben("neu.txt", b"zusatz")
        os.remove(os.path.join(self.tmp, "bild.png"))
        self.schreiben("unter/b.py", b"x = 2\n")
        shutil.rmtree(os.path.join(self.tmp, "unter", "__pycache__"))
        r = W.pruefen(self.tmp, pr["oeffentlich"], "alle", aus)
        self.assertFalse(r["ok"])
        self.assertEqual(r["arten"], {"neu.txt": "zusätzlich", "bild.png": "fehlt", "unter/b.py": "verändert"})
        with self.assertRaises(P.SignaturFehler):
            P.pruefen(self.tmp, pr["oeffentlich"], aus)

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_symlink_ist_fehler(self):
        self.baum()
        aus = ["logs/*", "*.log", "appdata/*"]
        pr = self.profil("alle", aus)
        W.signieren(self.tmp, pr, "Test-Kennwort-123", "1.0.0")
        os.symlink(os.path.join(self.tmp, "a.txt"), os.path.join(self.tmp, "unter", "link.txt"))
        r = W.pruefen(self.tmp, pr["oeffentlich"], "alle", aus)
        self.assertFalse(r["ok"])
        self.assertIn("Verknüpfung", r["fehler"])
        with self.assertRaises(P.SignaturFehler):
            P.pruefen(self.tmp, pr["oeffentlich"], aus)
        with self.assertRaises(ValueError):
            W.signieren(self.tmp, pr, "Test-Kennwort-123", "1.0.1")

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_symlink_auch_wenn_ausgenommen(self):
        self.schreiben("a.txt")
        os.symlink(os.path.join(self.tmp, "a.txt"), os.path.join(self.tmp, "x.log"))
        for f in (lambda: W.dateiliste(self.tmp, "alle", ["*.log", "appdata/*"]),
                  lambda: P._dateiliste(self.tmp, ["*.log", "appdata/*"])):
            with self.assertRaises((ValueError, P.SignaturFehler)):
                f()

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_symlink_ordner_und_signaturdatei(self):
        os.mkdir(os.path.join(self.tmp, "echt"))
        os.symlink(os.path.join(self.tmp, "echt"), os.path.join(self.tmp, "ordnerlink"))
        with self.assertRaises(ValueError):
            W.dateiliste(self.tmp, "alle", ["appdata/*"])
        os.remove(os.path.join(self.tmp, "ordnerlink"))
        os.symlink(os.path.join(self.tmp, "nirgends"), os.path.join(self.tmp, "SIGNATUR.json"))
        with self.assertRaises(ValueError):
            W.dateiliste(self.tmp, "alle", ["appdata/*"])
        self.assertFalse(W.pruefen(self.tmp, W.WERKZEUG_SCHLUESSEL, "alle", ["appdata/*"])["ok"])

    @unittest.skipUnless(SYMLINK, "Symlinks nicht möglich")
    def test_ausgenommener_ordner_wird_nicht_betreten(self):
        self.schreiben("a.txt")
        self.schreiben(".git/objekt")
        os.symlink(os.path.join(self.tmp, "a.txt"), os.path.join(self.tmp, ".git", "link"))
        self.assertEqual(sorted(W.dateiliste(self.tmp, "alle", ["appdata/*"])), ["a.txt"])
        self.assertEqual(sorted(P._dateiliste(self.tmp, ["appdata/*"])), ["a.txt"])

    @unittest.skipUnless(FIFO, "FIFOs nicht möglich")
    def test_fifo_ist_fehler(self):
        self.schreiben("a.txt")
        os.mkfifo(os.path.join(self.tmp, "rohr"))
        with self.assertRaises(ValueError):
            W.dateiliste(self.tmp, "alle", ["appdata/*"])
        with self.assertRaises(P.SignaturFehler):
            P._dateiliste(self.tmp, ["appdata/*"])

    def test_kollision_gross_klein(self):
        self.schreiben("Datei.txt")
        try:
            self.schreiben("datei.txt")
        except OSError:
            self.skipTest("Dateisystem unterscheidet Groß/Klein nicht")
        if len([n for n in os.listdir(self.tmp) if n.lower() == "datei.txt"]) < 2:
            self.skipTest("Dateisystem unterscheidet Groß/Klein nicht")
        with self.assertRaises(ValueError):
            W.dateiliste(self.tmp, "alle", ["appdata/*"])
        with self.assertRaises(P.SignaturFehler):
            P._dateiliste(self.tmp, ["appdata/*"])


# ---------------------------------------------------------------------------
# 5: Token bei Weiterleitungen
# ---------------------------------------------------------------------------
class _Server:
    def __init__(self, antwort):
        self.anfragen = []
        aussen = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                aussen.anfragen.append(dict(self.headers.items()))
                code, kopf, inhalt = antwort(self.path)
                self.send_response(code)
                for k, v in kopf.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(inhalt)))
                self.end_headers()
                self.wfile.write(inhalt)
            do_POST = do_GET
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def schliessen(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class WeiterleitungTests(Basis):
    TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2

    def setUp(self):
        super().setUp()
        self.fremd = _Server(lambda p: (200, {}, b"datei-inhalt"))
        self.ziel = f"http://127.0.0.1:{self.fremd.port}/datei"
        self.api = _Server(self.api_antwort)
        # Testaufbau: "localhost" spielt die GitHub-API, "127.0.0.1" einen fremden Host
        self._p = [mock.patch.object(W, "_SCHEMATA", ("http", "https")),
                   mock.patch.object(W, "_API_HOSTS", frozenset({"localhost"})),
                   mock.patch.object(W, "_DOWNLOAD_HOSTS", frozenset({"127.0.0.1"}))]
        for p in self._p:
            p.start()

    def tearDown(self):
        for p in self._p:
            p.stop()
        self.api.schliessen()
        self.fremd.schliessen()
        super().tearDown()

    def api_antwort(self, pfad):
        if pfad.startswith("/weiter"):
            return 302, {"Location": self.ziel}, b""
        if pfad.startswith("/schleife"):
            return 302, {"Location": "/schleife"}, b""
        if pfad.startswith("/boese"):
            return 302, {"Location": "http://boese.example/x"}, b""
        if pfad.startswith("/kette"):
            n = int(pfad.rsplit("/", 1)[1])
            return 302, {"Location": f"/kette/{n + 1}"}, b""
        if pfad.startswith("/fehler"):
            return 401, {}, b"Bearer " + self.TOKEN.encode()
        return 200, {}, b"{}"

    def api_url(self, pfad):
        return f"http://localhost:{self.api.port}{pfad}"

    def test_token_nicht_beim_fremden_host(self):
        daten = W._anfrage(self.api_url("/weiter"), self.TOKEN)
        self.assertEqual(daten, b"datei-inhalt")
        self.assertEqual(self.api.anfragen[0].get("Authorization"), f"Bearer {self.TOKEN}")
        self.assertEqual(len(self.fremd.anfragen), 1)
        self.assertNotIn("Authorization", self.fremd.anfragen[0])
        self.assertNotIn(self.TOKEN, json.dumps(self.fremd.anfragen))

    def test_download_ohne_token_weiter(self):
        W._herunterladen(self.api_url("/weiter"), self.TOKEN, limit=1000)
        self.assertNotIn("Authorization", self.fremd.anfragen[0])

    def test_nicht_vorgesehener_host(self):
        with self.assertRaises(ValueError):
            W._anfrage(self.api_url("/boese"), self.TOKEN)

    def test_schleife_und_zu_viele(self):
        with self.assertRaises(ValueError):
            W._anfrage(self.api_url("/schleife"), self.TOKEN)
        with self.assertRaises(ValueError):
            W._anfrage(self.api_url("/kette/0"), self.TOKEN)
        self.assertLessEqual(len(self.api.anfragen), W._MAX_WEITERLEITUNGEN + 2)

    def test_schreibende_anfrage_folgt_nicht(self):
        with self.assertRaises(ValueError):
            W._anfrage(self.api_url("/weiter"), self.TOKEN, "POST", b"{}")
        self.assertEqual(self.fremd.anfragen, [])

    def test_fehlermeldung_ohne_token(self):
        with self.assertRaises(ValueError) as cm:
            W._anfrage(self.api_url("/fehler"), self.TOKEN)
        self.assertNotIn(self.TOKEN, str(cm.exception))
        with mock.patch.object(W, "GITHUB_API", f"http://localhost:{self.api.port}"), self.assertRaises(ValueError) as cm:
            W._gh("/fehler", self.TOKEN)
        self.assertEqual(str(cm.exception), "GitHub-Token ungültig oder abgelaufen.")

    def test_token_nie_an_download_host(self):
        W._anfrage(self.ziel, self.TOKEN)
        self.assertNotIn("Authorization", self.fremd.anfragen[0])


class AdressTests(unittest.TestCase):
    def test_nur_https_und_kein_downgrade(self):
        with self.assertRaises(ValueError):
            W._adresse_pruefen("http://api.github.com/x")
        with mock.patch.object(W, "_SCHEMATA", ("http", "https")):
            with self.assertRaises(ValueError):
                W._adresse_pruefen("http://codeload.github.com/x", vorher="https://api.github.com/y")
        with self.assertRaises(ValueError):
            W._adresse_pruefen("https://user:pw@api.github.com/")
        with self.assertRaises(ValueError):
            W._adresse_pruefen("https://api.github.com.boese.example/")
        self.assertEqual(W._adresse_pruefen("https://codeload.github.com/x")[0], "codeload.github.com")

    def test_schwaerzen(self):
        W._geheim_bekannt.add("einGeheimesToken123")
        t = W.schwaerzen("Fehler mit ghp_abcdefghijklmnopqrstuvwxyz und github_pat_11AAAA_bbbbbbbbbbbbbb "
                         "und Bearer xyz und einGeheimesToken123")
        for s in ("ghp_abc", "github_pat_11", "Bearer xyz", "einGeheimesToken123"):
            self.assertNotIn(s, t)
        W._geheim_bekannt.clear()


# ---------------------------------------------------------------------------
# 6: Token-Speicher
# ---------------------------------------------------------------------------
class _FakeKeyring:
    priority = 5

    def __init__(self):
        self.werte = {}

    def set_password(self, d, n, w):
        self.werte[(d, n)] = w

    def get_password(self, d, n):
        return self.werte.get((d, n))

    def delete_password(self, d, n):
        self.werte.pop((d, n), None)


TOKEN = "github_pat_" + "Z9y8X7w6V5" * 4


@unittest.skipIf(os.name == "nt", "Windows nutzt DPAPI (eigener Test)")
class TokenTests(Basis):
    def profile_text(self):
        with open(os.path.join(W.daten_ordner(), "profile.json"), encoding="utf-8") as f:
            return f.read()

    def test_ohne_sicheren_speicher_nur_sitzung(self):
        with mock.patch.object(W, "_keyring", return_value=None):
            z = W.aktion("token_speichern", {"token": TOKEN})
            self.assertEqual(z["token_speicher"], "sitzung")
            self.assertIn("nur für diese Sitzung", z["meldung"])
            self.assertNotIn("verschlüsselt", z["meldung"])
            self.assertNotIn(TOKEN, self.profile_text())
            self.assertNotIn(base64.b64encode(TOKEN.encode()).decode(), self.profile_text())
            self.assertEqual(W.geheim_lesen(W.profile_laden().get("github_token")), TOKEN)
            self.assertNotIn(TOKEN, json.dumps(W.aktion("zustand", {})))

    def test_schluesselbund(self):
        kr = _FakeKeyring()
        with mock.patch.object(W, "_keyring", return_value=kr):
            z = W.aktion("token_speichern", {"token": TOKEN})
            self.assertEqual(z["token_speicher"], "schluesselbund")
            self.assertNotIn(TOKEN, self.profile_text())
            self.assertEqual(W.geheim_lesen(W.profile_laden()["github_token"]), TOKEN)
            with self.assertRaises(ValueError):   # leeres Feld löscht nicht versehentlich
                W.aktion("token_speichern", {"token": ""})
            W.aktion("token_speichern", {"token": "", "entfernen": True})
            self.assertEqual(kr.werte, {})

    def test_klartext_altbestand_migration(self):
        W.profile_speichern({"github_token": "klar:" + base64.b64encode(TOKEN.encode()).decode()})
        z = W.aktion("zustand", {})
        self.assertEqual(z["token_speicher"], "klartext")
        self.assertNotIn(TOKEN, json.dumps(z))
        kr = _FakeKeyring()
        with mock.patch.object(W, "_keyring", return_value=kr):
            z = W.aktion("token_migrieren", {})
            self.assertEqual(z["token_speicher"], "schluesselbund")
            self.assertNotIn("klar:", self.profile_text())
            self.assertEqual(kr.get_password(W._KEYRING_DIENST, W._KEYRING_NAME), TOKEN)
        W.profile_speichern({"github_token": "klar:" + base64.b64encode(TOKEN.encode()).decode()})
        with mock.patch.object(W, "_keyring", return_value=None):
            z = W.aktion("token_migrieren", {})
            self.assertEqual(z["token_speicher"], "sitzung")
            self.assertNotIn("klar:", self.profile_text())

    def test_unsichere_keyring_backends_abgelehnt(self):
        class PlaintextKeyring(_FakeKeyring):
            pass
        fake = mock.MagicMock()
        fake.get_keyring.return_value = PlaintextKeyring()
        with mock.patch.dict(sys.modules, {"keyring": fake}):
            self.assertIsNone(W._keyring())
        fake.get_keyring.return_value = _FakeKeyring()
        with mock.patch.dict(sys.modules, {"keyring": fake}):
            self.assertIsNotNone(W._keyring())

    def test_profile_datei_rechte(self):
        W.profile_speichern({})
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(W.daten_ordner(), "profile.json")).st_mode), 0o600)


@unittest.skipUnless(os.name == "nt", "nur Windows")
class DpapiTests(Basis):
    def test_dpapi(self):
        z = W.aktion("token_speichern", {"token": TOKEN})
        self.assertEqual(z["token_speicher"], "dpapi")
        with open(os.path.join(W.daten_ordner(), "profile.json"), encoding="utf-8") as f:
            self.assertNotIn(TOKEN, f.read())
        self.assertEqual(W.geheim_lesen(W.profile_laden()["github_token"]), TOKEN)


# ---------------------------------------------------------------------------
# 7 + 8: Tags, Herkunft, Workflow
# ---------------------------------------------------------------------------
class TagTests(unittest.TestCase):
    def gh_mit(self, tags):
        aufrufe = []

        def gh(pfad, token, methode="GET", daten=None, **k):
            aufrufe.append((methode, pfad, daten))
            if "/git/ref/tags/" in pfad:
                name = pfad.rsplit("/", 1)[1]
                if name in tags:
                    return {"object": tags[name]}
                raise W.GitHubFehler("nicht gefunden", 404)
            if "/git/tags/" in pfad:
                return {"object": {"type": "commit", "sha": "c" * 40}}
            return {}
        return gh, aufrufe

    def test_vorhandener_tag_wird_nicht_verschoben(self):
        gh, aufrufe = self.gh_mit({"v1.0.0": {"type": "commit", "sha": "a" * 40}})
        with mock.patch.object(W, "_gh", gh):
            with self.assertRaises(ValueError):
                W.github_tag_setzen("o/r", "t", "1.0.0", "b" * 40)
            with self.assertRaises(ValueError):
                W.github_tag_frei("o/r", "t", "1.0.0", "b" * 40, False)
            # Tag auf dem noch unsignierten Stand: Abbruch, wenn ein neuer Commit nötig wäre
            with self.assertRaisesRegex(ValueError, "noch nicht signierten Stand"):
                W.github_tag_frei("o/r", "t", "1.0.0", "a" * 40, True)
            W.github_tag_frei("o/r", "t", "1.0.0", "a" * 40, False)   # schon signiert, Tag passt
            W.github_tag_frei("o/r", "t", "1.0.1", "a" * 40, True)    # Tag gibt es noch nicht
            for version in ("", "\ufeff1.0.0", "v1.0"):
                with self.assertRaises(ValueError):
                    W.github_tag_frei("o/r", "t", version, "a" * 40, True)
            self.assertEqual(W.github_tag_setzen("o/r", "t", "1.0.0", "a" * 40), "v1.0.0")
        self.assertFalse([a for a in aufrufe if a[0] in ("POST", "PATCH")])

    def test_abfragefehler_gilt_nicht_als_kein_tag(self):
        for fehler in (W.GitHubFehler("Keine Berechtigung", 403), W.GitHubFehler("GitHub-Fehler 502.", 502),
                       ValueError("GitHub nicht erreichbar (URLError).")):
            with self.subTest(fehler=fehler), mock.patch.object(W, "_gh", side_effect=fehler):
                self.assertRaises(ValueError, W._tag_commit, "o/r", "t", "v1.0.0")
                self.assertRaises(ValueError, W.github_tag_frei, "o/r", "t", "1.0.0", "a" * 40, True)

    def test_annotierter_tag(self):
        gh, _ = self.gh_mit({"v1.0.0": {"type": "tag", "sha": "d" * 40}})
        with mock.patch.object(W, "_gh", gh):
            self.assertEqual(W._tag_commit("o/r", "t", "v1.0.0"), "c" * 40)

    def test_neuer_tag(self):
        gh, aufrufe = self.gh_mit({})
        with mock.patch.object(W, "_gh", gh):
            self.assertEqual(W.github_tag_setzen("o/r", "t", "1.0.1", "b" * 40), "v1.0.1")
        self.assertEqual(aufrufe[-1][0], "POST")


class HerkunftTests(unittest.TestCase):
    EXE = b"MZ" + b"\0" * 100
    COMMIT = "e" * 40

    def rel(self, summe=None, digest=True):
        summe = summe or hashlib.sha256(self.EXE).hexdigest()
        return {"tag_name": "v9.9.9", "body": f"Ungeprüfter Entwurf aus Commit {self.COMMIT}.\n\nSHA-256 der exe: {summe}\n",
                "assets": [{"name": W.EXE_NAME, **({"digest": "sha256:" + summe} if digest else {})}]}

    def pruefen(self, rel, tag=None, status="ahead"):
        with mock.patch.object(W, "_tag_commit", return_value=tag or self.COMMIT), \
                mock.patch.object(W, "_gh", return_value={"status": status}):
            return W.entwurf_herkunft(rel, "t", self.EXE)

    def test_ok(self):
        self.assertEqual(self.pruefen(self.rel()), self.COMMIT)
        self.assertEqual(self.pruefen(self.rel(digest=False), status="identical"), self.COMMIT)

    def test_abweichungen(self):
        with self.assertRaises(ValueError):
            self.pruefen(self.rel(summe="0" * 64))
        with self.assertRaises(ValueError):
            self.pruefen(self.rel(), tag="f" * 40)
        with self.assertRaises(ValueError):
            self.pruefen(self.rel(), status="diverged")
        with self.assertRaises(ValueError):
            self.pruefen({"tag_name": "v9.9.9", "body": "irgendwas", "assets": []})


class ReleaseTextTests(unittest.TestCase):
    def test_text_nach_veroeffentlichung(self):
        t = W.veroeffentlicht_text("9.9.9", "e" * 40, "a" * 64, "https://github.com/x/y/actions/runs/1")
        self.assertNotIn("Ungeprüfter Entwurf", t)
        self.assertIn("signiert und veröffentlicht", t)
        self.assertIn(W.WERKZEUG_SCHLUESSEL, t)
        import re
        self.assertEqual(re.search(r"Commit ([0-9a-f]{40})", t).group(1), "e" * 40)   # weiter maschinell prüfbar
        self.assertEqual(re.search(r"SHA-256 der exe: ([0-9a-f]{64})", t).group(1), "a" * 64)

    def test_veroeffentlichen_ersetzt_text(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        privat = Ed25519PrivateKey.generate()
        exe = b"MZ" + b"\0" * (W._EXE_MIN)
        summe = hashlib.sha256(exe).hexdigest()
        rel = {"id": 7, "tag_name": "v9.9.9", "assets": [{"id": 1, "name": W.EXE_NAME, "url": "u"}],
               "body": f"Ungeprüfter Entwurf aus Commit {'e' * 40}.\n\nSHA-256 der exe: {summe}\n\n"
                       "Gebaut von: https://github.com/Hansi478/Signier-Werkzeug/actions/runs/123\n"}
        aufrufe = []
        with mock.patch.object(W, "privat_laden", return_value=privat), \
                mock.patch.object(W, "WERKZEUG_SCHLUESSEL", W.oeffentlich_text(privat)), \
                mock.patch.object(W, "werkzeug_entwurf", return_value=rel), \
                mock.patch.object(W, "_herunterladen", return_value=exe), \
                mock.patch.object(W, "entwurf_herkunft", return_value="e" * 40), \
                mock.patch.object(W, "_gh_hochladen"), \
                mock.patch.object(W, "_gh", side_effect=lambda *a, **k: aufrufe.append((a, k)) or {}):
            W.werkzeug_veroeffentlichen({"id": "abcdef12"}, "x", "t")
        patch = [a for a, k in aufrufe if len(a) > 2 and a[2] == "PATCH"][0][3]
        self.assertFalse(patch["draft"])
        self.assertIn("signiert und veröffentlicht", patch["body"])
        self.assertIn("actions/runs/123", patch["body"])
        self.assertIn(summe, patch["body"])


class BauStatusTests(unittest.TestCase):
    def status(self, laeufe, jobs=None, entwurf=None, token="t", fehler_ohne_token=False):
        def gh(pfad, tok, *a, **k):
            if fehler_ohne_token and tok is None:
                raise ValueError("Keine Berechtigung")
            if "/workflows/bauen.yml/runs" in pfad:
                return {"workflow_runs": laeufe}
            if pfad.endswith("/jobs"):
                return {"jobs": jobs or []}
            raise ValueError("404")
        with mock.patch.object(W, "_gh", gh), \
                mock.patch.object(W, "werkzeug_entwurf", side_effect=(lambda t: entwurf) if entwurf else ValueError("kein Entwurf")):
            return W.werkzeug_bau_status(token)

    URL = "https://github.com/Hansi478/Signier-Werkzeug/actions/runs/5"   # Schreibweise wie von GitHub geliefert

    def test_laeuft_mit_schritt(self):
        d = self.status([{"id": 5, "head_branch": "v9.9.9", "status": "in_progress", "html_url": self.URL}],
                        jobs=[{"name": "bauen", "steps": [{"name": "Tests", "status": "completed"},
                                                          {"name": "Bauen", "status": "in_progress"}]}])
        self.assertEqual((d["zustand"], d["tag"], d["schritt"], d["url"]), ("laeuft", "v9.9.9", "bauen: Bauen", self.URL))

    def test_fertig_mit_entwurf(self):
        d = self.status([{"id": 5, "head_branch": "v9.9.9", "status": "completed", "conclusion": "success", "html_url": self.URL}],
                        entwurf={"tag_name": "v9.9.9"})
        self.assertEqual((d["zustand"], d["entwurf"]), ("fertig", True))

    def test_fehlgeschlagen_und_keiner(self):
        d = self.status([{"id": 5, "head_branch": "v9.9.9", "status": "completed", "conclusion": "failure", "html_url": self.URL}])
        self.assertEqual(d["zustand"], "fehlgeschlagen")
        self.assertEqual(self.status([{"id": 1, "head_branch": "main", "status": "completed"}])["zustand"], "keiner")

    def test_fremde_adresse_wird_nicht_verlinkt(self):
        for boese in ("https://boese.example/x", "https://github.com/Hansi478/Signier-Werkzeug/actions/runs/5/../../x",
                      "javascript:alert(1)", "https://github.com/andere/repo/actions/runs/5"):
            d = self.status([{"id": 5, "head_branch": "v9.9.9", "status": "queued", "html_url": boese}])
            self.assertEqual((d["zustand"], d["url"]), ("wartet", ""), boese)

    def test_rueckfall_mit_token(self):
        d = self.status([{"id": 5, "head_branch": "v9.9.9", "status": "queued", "html_url": self.URL}], fehler_ohne_token=True)
        self.assertEqual(d["zustand"], "wartet")
        with self.assertRaises(ValueError):
            self.status([], token="", fehler_ohne_token=True)


class WorkflowTests(unittest.TestCase):
    def lesen(self, name):
        with open(os.path.join(WURZEL, ".github", "workflows", name), encoding="utf-8") as f:
            return f.read()

    def test_workflows(self):
        import re
        for name in ("bauen.yml", "pruefen.yml", "sicherheit.yml"):
            with self.subTest(name=name):
                text = self.lesen(name)
                code = "\n".join(z for z in text.splitlines() if not z.lstrip().startswith("#"))
                for zeile in [z.strip() for z in text.splitlines() if z.strip().startswith(("uses:", "- uses:"))]:
                    self.assertRegex(zeile, r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$", zeile)
                self.assertIn("\npermissions:\n  contents: read\n", text)
                self.assertNotIn("pull_request_target", code)
                self.assertNotIn("secrets.", code)
                for block in re.findall(r"run: \|\n((?:\s{10,}.*\n)+)", text):
                    self.assertNotIn("${{", block, "Ausdruck direkt im Skript (Injektion) - über env übergeben")
        bauen = self.lesen("bauen.yml")
        self.assertIn("contents: write", bauen.split("entwurf:")[1])
        self.assertNotIn("contents: write", bauen.split("entwurf:")[0])
        self.assertIn("--verify-tag", bauen)

    def test_dependabot_fuer_actions(self):
        with open(os.path.join(WURZEL, ".github", "dependabot.yml"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('package-ecosystem: "github-actions"', text)
        self.assertIn('package-ecosystem: "pip"', text)
        self.assertIn('directory: "/"', text)
        self.assertTrue(os.path.isfile(os.path.join(WURZEL, "requirements-bau.txt")), "Dependabot findet die Bau-Pakete nicht")

    def test_python_version_fest_und_einheitlich(self):
        import re
        versionen = {n: re.findall(r'python-version:\s*"([^"]+)"', self.lesen(n)) for n in ("bauen.yml", "pruefen.yml", "sicherheit.yml")}
        alle = {v for vs in versionen.values() for v in vs}
        self.assertEqual(len(alle), 1, versionen)
        self.assertRegex(alle.pop(), r"^\d+\.\d+\.\d+$", "Python-Version muss genau festgelegt sein (x.y.z)")

    def test_bau_pakete_mit_pruefsummen(self):
        with open(os.path.join(WURZEL, "requirements-bau.txt"), encoding="utf-8") as f:
            zeilen = [z for z in f.read().splitlines() if z.strip() and not z.startswith("#")]
        self.assertTrue(zeilen)
        for z in zeilen:
            self.assertRegex(z, r"^[A-Za-z0-9_.-]+==\S+( --hash=sha256:[0-9a-f]{64})+$", z)


class PythonAktuellTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("python_aktuell", os.path.join(WURZEL, "tools", "python_aktuell.py"))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)

    def test_neueste_windows_version(self):
        win = [{"platform": "win32", "arch": "x64"}]
        linux = [{"platform": "linux", "arch": "x64"}]
        manifest = [{"version": "3.14.9", "stable": True, "files": linux},      # nur Quelltext/Linux
                    {"version": "3.14.8", "stable": True, "files": win + linux},
                    {"version": "3.14.10rc1", "stable": False, "files": win},
                    {"version": "3.14.7", "stable": True, "files": win},
                    {"version": "3.13.20", "stable": True, "files": win}]
        self.assertEqual(self.m.neueste_windows(manifest, "3.14"), "3.14.8")
        self.assertIsNone(self.m.neueste_windows(manifest, "3.12"))
        self.assertEqual(self.m.festgelegt(os.path.join(WURZEL, ".github", "workflows", "bauen.yml")).count("."), 2)


if __name__ == "__main__":
    unittest.main()
