# -*- coding: utf-8 -*-
"""Bau-Signatur (SIGNATUR-BAU.json): Werkzeug-Ausgabe gegen eine Nachbildung
von _bau_pruefung/_bau_dateiliste aus dem Dashboard (app.py, ab 1.8.8) und
tools/signieren.py. Nur Platzhalter, eigener Test-Schlüssel.

Echte Gegenprobe (optional): Ist SR_DASHBOARD_ORDNER auf einen entpackten
Stand des Dashboards (ab 1.8.8) gesetzt, signiert der Test eine Kopie davon
und ruft dort "python tools/signieren.py pruefen <Schlüssel>" und
"python app.py --bau-pruefen" (SR_UPDATE_SCHLUESSEL) auf - beide müssen
bestehen (Ergebnis 0)."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import signier_werkzeug as W  # noqa: E402

KENNWORT = "Test-Kennwort-123"


# --- Nachbildung des Dashboards (app.py 1.8.8), bewusst unabhängig geschrieben ---
def nb_pruefsumme(pfad):
    with open(pfad, "rb") as f:
        daten = f.read()
    if b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def nb_dateiliste(wurzel):
    import stat as st
    out, unzulaessig = {}, []

    def art(p):
        m = os.lstat(p).st_mode
        return "datei" if st.S_ISREG(m) else ("ordner" if st.S_ISDIR(m) else "keine normale Datei")
    for name in ("Dockerfile", ".dockerignore", "docker-compose.yml"):
        p = os.path.join(wurzel, name)
        if os.path.lexists(p):
            if art(p) == "datei":
                out[name] = nb_pruefsumme(p)
            else:
                unzulaessig.append(name)
    for ordner in ("tools", ".github/workflows"):
        p = os.path.join(wurzel, *ordner.split("/"))
        if not os.path.lexists(p):
            continue
        if art(p) != "ordner":
            unzulaessig.append(ordner)
            continue
        for root, dirs, files in os.walk(p):
            for d in list(dirs):
                if d != "__pycache__" and art(os.path.join(root, d)) != "ordner":
                    unzulaessig.append(os.path.relpath(os.path.join(root, d), wurzel).replace(os.sep, "/"))
            dirs[:] = sorted(d for d in dirs if d != "__pycache__" and art(os.path.join(root, d)) == "ordner")
            for f in sorted(files):
                if f.endswith(".pyc"):
                    continue
                voll = os.path.join(root, f)
                rel = os.path.relpath(voll, wurzel).replace(os.sep, "/")
                if art(voll) != "datei":
                    unzulaessig.append(rel)
                else:
                    out[rel] = nb_pruefsumme(voll)
    return out, unzulaessig


def nb_pruefung(wurzel, schluessel):
    """-> "ok" | "warn" | "fehler" | "fehlt" wie _bau_pruefung."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pfad = os.path.join(wurzel, "SIGNATUR-BAU.json")
    if not os.path.lexists(pfad):
        return "fehlt"
    try:
        with open(pfad, encoding="utf-8") as f:
            sig = json.loads(f.read())
        if sig.get("format") != "sr-bau-signatur-1" or not isinstance(sig.get("dateien"), dict):
            raise ValueError
        version = str(sig.get("version") or "")[:40]
        Ed25519PublicKey.from_public_bytes(base64.b64decode(schluessel)).verify(
            base64.b64decode(str(sig.get("signatur") or "")),
            json.dumps({"format": "sr-bau-signatur-1", "version": version, "dateien": sig["dateien"]},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except Exception:
        return "fehler"
    ist, unzulaessig = nb_dateiliste(wurzel)
    soll = sig["dateien"]
    veraendert = [n for n in soll if n in ist and ist[n] != soll[n]]
    if unzulaessig or [n for n in veraendert if n != "docker-compose.yml"]:
        return "fehler"
    try:
        with open(os.path.join(wurzel, "VERSION"), encoding="utf-8") as f:
            programm = f.read(40).strip()
    except OSError:
        programm = ""
    if veraendert or [n for n in soll if n not in ist] or [n for n in ist if n not in soll] \
            or (programm and version and programm != version):
        return "warn"
    return "ok"


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bau-test-")
        self.wurzel = os.path.join(self.tmp, "stand")
        os.makedirs(self.wurzel)
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata")})
        self._env.start()

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def schreiben(self, rel, daten):
        pfad = os.path.join(self.wurzel, *rel.split("/"))
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        with open(pfad, "wb") as f:
            f.write(daten)

    def dashboard(self, bau=True):
        self.schreiben("app.py", b'UPDATE_ALLOWED_FILES = ("app.py", "VERSION", "SIGNATUR.json")\n'
                                 b'UPDATE_ALLOWED_DIRS = ("templates",)\n')
        self.schreiben("VERSION", b"1.8.8\n")
        self.schreiben("templates/a.html", b"<p>\r\n")
        self.schreiben("tests/test_x.py", b"x = 1\n")
        self.schreiben(".gitignore", b"*.pyc\n")
        if bau:
            self.schreiben("Dockerfile", b"FROM beispiel\r\nRUN true\r\n")
            self.schreiben(".dockerignore", b".git\n")
            self.schreiben("docker-compose.yml", b"services:\n  dashboard:\n    build: .\n")
            self.schreiben("tools/docker_start.sh", b"#!/bin/sh\r\nexec python app.py\r\n")
            self.schreiben("tools/bild.png", b"\x89PNG\r\n\x00\r\n")    # Nullbyte: CRLF bleibt
            self.schreiben("tools/unter/hilfe.py", b"print(1)\r\n")
            self.schreiben("tools/__pycache__/x.cpython-314.pyc", b"\x00")
            self.schreiben("tools/alt.pyc", b"\x00")
            self.schreiben(".github/workflows/w.yml", b"on: push\n")

    def profil(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.privat = Ed25519PrivateKey.generate()
        pr = {"id": "test" + os.urandom(4).hex(), "oeffentlich": W.oeffentlich_text(self.privat), "regel": "speedrace",
              "ausschluss": []}
        W.neu_anlegen(W.schluessel_pfad(pr), self.privat.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(KENNWORT.encode())))
        return pr


class FormatTests(Basis):
    def test_wie_dashboard(self):
        self.dashboard()
        pr = self.profil()
        version, anzahl, inhalt, bau_inhalt, bau_anzahl = W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
        self.assertEqual((version, bau_anzahl), ("1.8.8", 7))
        with open(os.path.join(self.wurzel, "SIGNATUR-BAU.json"), encoding="utf-8") as f:
            text = f.read()
        self.assertEqual(text, bau_inhalt)
        sig = json.loads(text)
        ist, unzulaessig = nb_dateiliste(self.wurzel)
        self.assertEqual(unzulaessig, [])
        self.assertEqual(sig["dateien"], ist)
        self.assertEqual(sorted(ist), [".dockerignore", ".github/workflows/w.yml", "Dockerfile", "docker-compose.yml",
                                       "tools/bild.png", "tools/docker_start.sh", "tools/unter/hilfe.py"])
        # Datei genau wie tools/signieren.py: indent=1, sort_keys, \n am Ende
        self.assertEqual(text, json.dumps({k: sig[k] for k in ("format", "version", "dateien", "signatur")},
                                          indent=1, sort_keys=True) + "\n")
        self.assertEqual(sig["dateien"]["Dockerfile"], hashlib.sha256(b"FROM beispiel\nRUN true\n").hexdigest())
        self.assertEqual(sig["dateien"]["tools/bild.png"], hashlib.sha256(b"\x89PNG\r\n\x00\r\n").hexdigest())
        self.assertEqual(nb_pruefung(self.wurzel, pr["oeffentlich"]), "ok")
        self.assertEqual(W.bau_pruefen(self.wurzel, pr["oeffentlich"])["stufe"], "ok")
        # SIGNATUR.json unverändert wie bisher (enthält keine Bau-Dateien)
        self.assertTrue(W.pruefen(self.wurzel, pr["oeffentlich"], "speedrace")["ok"])
        self.assertNotIn("Dockerfile", json.loads(inhalt)["dateien"])
        self.assertNotIn("SIGNATUR-BAU.json", json.loads(inhalt)["dateien"])

    def test_abweichungen_wie_dashboard(self):
        faelle = [
            ("Dockerfile", b"FROM anders\n", "fehler"),
            ("tools/docker_start.sh", b"boese\n", "fehler"),
            ("docker-compose.yml", b"services: {}\n", "warn"),
            ("tools/neu.sh", b"neu\n", "warn"),
            ("VERSION", b"1.8.9\n", "warn"),
            ("tools/__pycache__/y.pyc", b"egal", "ok"),
            ("tests/test_x.py", b"egal\n", "ok"),
        ]
        for rel, daten, erwartet in faelle:
            with self.subTest(rel=rel):
                shutil.rmtree(self.wurzel)
                os.makedirs(self.wurzel)
                self.dashboard()
                pr = self.profil()
                W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
                self.schreiben(rel, daten)
                self.assertEqual(nb_pruefung(self.wurzel, pr["oeffentlich"]), erwartet)
                self.assertEqual(W.bau_pruefen(self.wurzel, pr["oeffentlich"])["stufe"], erwartet)

    def test_fehlende_datei_ist_hinweis(self):
        self.dashboard()
        pr = self.profil()
        W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
        os.remove(os.path.join(self.wurzel, ".dockerignore"))
        self.assertEqual(nb_pruefung(self.wurzel, pr["oeffentlich"]), "warn")
        self.assertEqual(W.bau_pruefen(self.wurzel, pr["oeffentlich"])["stufe"], "warn")

    def test_fremder_schluessel_und_formattausch(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.dashboard()
        pr = self.profil()
        W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
        anderer = W.oeffentlich_text(Ed25519PrivateKey.generate())
        self.assertEqual(W.bau_pruefen(self.wurzel, anderer)["stufe"], "fehler")
        # eine Update-Signatur lässt sich nicht als Bau-Signatur ausgeben (und umgekehrt)
        sig = json.loads(open(os.path.join(self.wurzel, "SIGNATUR.json"), encoding="utf-8").read())
        sig["format"] = "sr-bau-signatur-1"
        with open(os.path.join(self.wurzel, "SIGNATUR-BAU.json"), "w", encoding="utf-8") as f:
            json.dump(sig, f)
        self.assertEqual(W.bau_pruefen(self.wurzel, pr["oeffentlich"])["stufe"], "fehler")
        self.assertEqual(nb_pruefung(self.wurzel, pr["oeffentlich"]), "fehler")

    def test_ohne_bau_elemente_keine_datei(self):
        self.dashboard(bau=False)
        pr = self.profil()
        _, _, _, bau_inhalt, n = W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
        self.assertIsNone(bau_inhalt)
        self.assertEqual(n, 0)
        self.assertFalse(os.path.exists(os.path.join(self.wurzel, "SIGNATUR-BAU.json")))
        self.assertEqual(W.bau_pruefen(self.wurzel, pr["oeffentlich"])["stufe"], "fehlt")

    @unittest.skipUnless(hasattr(os, "symlink"), "keine Symlinks")
    def test_symlink_bricht_ab(self):
        self.dashboard()
        pr = self.profil()
        try:
            os.symlink(os.path.join(self.wurzel, "app.py"), os.path.join(self.wurzel, "tools", "link.py"))
        except OSError:
            self.skipTest("Symlink nicht möglich")
        self.assertRaises(ValueError, W.signieren_mit_bau, self.wurzel, pr, KENNWORT)
        self.assertFalse(os.path.exists(os.path.join(self.wurzel, "SIGNATUR.json")))   # nichts geschrieben
        self.assertFalse(os.path.exists(os.path.join(self.wurzel, "SIGNATUR-BAU.json")))

    def test_git_baum_muss_passen(self):
        self.dashboard()
        pr = self.profil()
        git = set(nb_dateiliste(self.wurzel)[0]) | {"tools/nur_im_git.sh"}
        self.assertRaises(ValueError, W.signieren_mit_bau, self.wurzel, pr, KENNWORT, git)
        self.assertFalse(os.path.exists(os.path.join(self.wurzel, "SIGNATUR.json")))


class BaumTests(unittest.TestCase):
    def e(self, path, mode="100644", typ="blob"):
        return {"path": path, "mode": mode, "type": typ, "sha": "0" * 40}

    def test_auswahl(self):
        baum = [self.e("Dockerfile"), self.e("app.py"), self.e("tools", "040000", "tree"), self.e("tools/a.sh", "100755"),
                self.e("tools/__pycache__/a.pyc"), self.e("tools/b.pyc"), self.e(".github/workflows/w.yml"),
                self.e(".github/dependabot.yml"), self.e("tests/x.py"), self.e("SIGNATUR-BAU.json")]
        self.assertEqual(W.bau_aus_baum(baum), {"Dockerfile", "tools/a.sh", ".github/workflows/w.yml"})

    def test_links_und_submodule_abbrechen(self):
        for eintrag in (self.e("tools/link", "120000"), self.e("Dockerfile", "120000"), self.e("tools", "120000"),
                        self.e("tools/modul", "160000", "commit"), self.e(".github/workflows", "160000", "commit")):
            with self.subTest(eintrag=eintrag):
                self.assertRaises(ValueError, W.bau_aus_baum, [self.e("Dockerfile"), eintrag])
        W.bau_aus_baum([self.e("tests/link", "120000"), self.e("modul", "160000", "commit")])   # außerhalb egal


class HochladenTests(unittest.TestCase):
    def test_ein_commit_ohne_force(self):
        aufrufe = []
        stand, baum_sha, neu_baum, neu_commit = "a" * 40, "b" * 40, "c" * 40, "d" * 40
        dateien = {"SIGNATUR.json": "{}\n", "SIGNATUR-BAU.json": "{\"x\": 1}\n"}

        def gh(pfad, token, methode="GET", daten=None, **k):
            aufrufe.append((methode, pfad, daten))
            if pfad.endswith("/branches/main"):
                return {"commit": {"sha": stand}}
            if pfad.endswith(f"/git/commits/{stand}"):
                return {"tree": {"sha": baum_sha}}
            if pfad.endswith("/git/blobs"):
                return {"sha": W._git_blob_sha(base64.b64decode(daten["content"]))}
            if pfad.endswith("/git/trees"):
                return {"sha": neu_baum}
            if pfad.endswith("/git/commits"):
                return {"sha": neu_commit}
            if "/git/refs/heads/" in pfad:
                return {}
            raise AssertionError(pfad)
        with mock.patch.object(W, "_gh", side_effect=gh):
            commit = W.github_hochladen_commit("Besitzer/beispiel", "main", "t", dateien, "1.8.8", stand, [])
        self.assertEqual(commit, neu_commit)
        posts = [a for a in aufrufe if a[0] != "GET"]
        self.assertEqual([p[1].rsplit("/", 1)[-1] for p in posts], ["blobs", "blobs", "trees", "commits", "main"])
        self.assertEqual(posts[2][2]["base_tree"], baum_sha)
        self.assertEqual(sorted(e["path"] for e in posts[2][2]["tree"]), ["SIGNATUR-BAU.json", "SIGNATUR.json"])
        self.assertEqual(posts[3][2]["parents"], [stand])
        self.assertEqual(posts[4][0], "PATCH")
        self.assertEqual(posts[4][2], {"sha": neu_commit, "force": False})

    def test_unveraendert_kein_commit(self):
        stand = "a" * 40
        dateien = {"SIGNATUR.json": "{}\n", "SIGNATUR-BAU.json": "{}\n"}
        baum = [{"path": n, "type": "blob", "sha": W._git_blob_sha(t.encode())} for n, t in dateien.items()]
        with mock.patch.object(W, "_gh", return_value={"commit": {"sha": stand}}) as gh:
            self.assertEqual(W.github_hochladen_commit("Besitzer/beispiel", "main", "t", dateien, "1.8.8", stand, baum), stand)
        self.assertEqual(gh.call_count, 1)

    def test_zwischendurch_geaendert(self):
        with mock.patch.object(W, "_gh", return_value={"commit": {"sha": "f" * 40}}):
            self.assertRaises(ValueError, W.github_hochladen_commit, "Besitzer/beispiel", "main", "t",
                              {"SIGNATUR.json": "{}"}, "1.8.8", "a" * 40, [])

    def test_git_blob_sha(self):
        self.assertEqual(W._git_blob_sha(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")   # wie git hash-object


@unittest.skipUnless(os.environ.get("SR_DASHBOARD_ORDNER"), "SR_DASHBOARD_ORDNER nicht gesetzt (echte Gegenprobe)")
class EchteGegenprobe(Basis):
    def test_signieren_py_und_bau_pruefen(self):
        shutil.rmtree(self.wurzel)
        shutil.copytree(os.environ["SR_DASHBOARD_ORDNER"], self.wurzel,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "SIGNATUR.json", "SIGNATUR-BAU.json"))
        pr = self.profil()
        _, _, _, bau_inhalt, n = W.signieren_mit_bau(self.wurzel, pr, KENNWORT)
        self.assertTrue(bau_inhalt and n > 0)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        r = subprocess.run([sys.executable, os.path.join("tools", "signieren.py"), "pruefen", pr["oeffentlich"]],
                           cwd=self.wurzel, capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Bau-Signatur gültig", r.stdout)
        r = subprocess.run([sys.executable, "app.py", "--bau-pruefen"], cwd=self.wurzel, capture_output=True, text=True,
                           timeout=120, env={**env, "SR_UPDATE_SCHLUESSEL": pr["oeffentlich"]})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(r.stdout.startswith("OK:"), r.stdout)


if __name__ == "__main__":
    unittest.main()
