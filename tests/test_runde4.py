# -*- coding: utf-8 -*-
"""Korrekturen aus der vierten Prüfrunde (Befundliste Runde 4)."""
import base64
import io
import json
import os
import shutil
import sys
import tempfile
import unicodedata
import unittest
import zipfile
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
sys.path.insert(0, HIER)
import qnap_begleiter as Q  # noqa: E402
import signier_werkzeug as W  # noqa: E402
import test_pakete  # noqa: E402

H = "a" * 64


class QnapPaketBauTests(unittest.TestCase):
    """H1, N7: qnap_paket übernimmt nur, was zur Signatur passt."""

    APP = b'UPDATE_ALLOWED_FILES = ("app.py", "VERSION")\nUPDATE_ALLOWED_DIRS = ("templates",)\n# --bau-pruefen\n'
    COMPOSE = b"services:\n  dashboard:\n    build: .\n"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="runde4-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata")})
        self._env.start()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.k = Ed25519PrivateKey.generate()
        self.pr = {"id": "quelle01", "repo": "Besitzer/beispiel", "oeffentlich": W.oeffentlich_text(self.k),
                   "regel": "speedrace", "ausschluss": []}

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def archiv(self, nachher=None, weg=(), regel=None):
        dateien = {"app.py": self.APP, "VERSION": b"1.8.5\n", "templates/a.html": b"<p>\n", "Dockerfile": b"FROM x\n",
                   "docker-compose.yml": self.COMPOSE, "tools/start.sh": b"#!/bin/sh\n"}
        q = os.path.join(self.tmp, "q")
        shutil.rmtree(q, ignore_errors=True)
        for rel, d in dateien.items():
            os.makedirs(os.path.join(q, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(q, rel), "wb") as f:
                f.write(d)
        sig = W.dateiliste(q, regel or "speedrace")
        dateien[W.SIGNATUR_DATEI] = json.dumps({"format": W.FORMAT, "version": "1.8.5", "dateien": sig, "signatur":
                                                base64.b64encode(self.k.sign(W.nachricht("1.8.5", sig))).decode()}).encode()
        dateien[W.BAU_SIGNATUR_DATEI] = W.bau_signatur_bauen(self.k, "1.8.5", W.bau_dateiliste(q)[0]).encode()
        dateien.update(nachher or {})   # nach dem Signieren auf GitHub geändert
        for rel in weg:
            del dateien[rel]
        puf = io.BytesIO()
        with zipfile.ZipFile(puf, "w") as z:
            z.writestr("B-b-abc/", "")
            for rel, d in dateien.items():
                z.writestr("B-b-abc/" + rel, d)
        return puf.getvalue()

    def laden(self, archiv):
        def gh(pfad, token, *a, ziel=None, **k):
            ziel.write(archiv)
            return len(archiv)
        with mock.patch.object(W, "_tag_commit", return_value="e" * 40), mock.patch.object(W, "_gh", side_effect=gh):
            return W.qnap_paket(self.pr, None, "v1.8.5", "programmordner", os.path.join(self.tmp, "ziel"))

    def test_unveraendert(self):
        r = self.laden(self.archiv())
        self.assertEqual(r["bau_stufe"], "ok")
        with zipfile.ZipFile(r["zip"]) as z:
            self.assertEqual(z.read("programmordner/docker-compose.yml"), self.COMPOSE)

    def test_veraenderte_compose_im_tag_abgelehnt(self):
        boese = b"services:\n  dashboard:\n    image: angreifer/boese\n    privileged: true\n"
        with self.assertRaisesRegex(ValueError, "verändert: docker-compose.yml.*nach dem Signieren geändert"):
            self.laden(self.archiv({"docker-compose.yml": boese}))
        self.assertFalse(any(n.endswith(".zip") for n in os.listdir(os.path.join(self.tmp, "ziel"))))

    def test_fehlende_bau_datei_abgelehnt(self):
        with self.assertRaisesRegex(ValueError, "fehlen: tools/start.sh"):
            self.laden(self.archiv(weg=("tools/start.sh",)))

    def test_zusaetzliche_bau_datei_nicht_uebernommen(self):
        r = self.laden(self.archiv({"tools/neu.sh": b"#!/bin/sh\nid\n"}))
        self.assertEqual(r["bau_stufe"], "warn")
        self.assertIn("nicht übernommen: tools/neu.sh", r["bau_text"])
        with zipfile.ZipFile(r["zip"]) as z:
            self.assertNotIn("programmordner/tools/neu.sh", z.namelist())

    def test_github_pruefen_ohne_lokal_angepasst(self):
        q = os.path.join(self.tmp, "g")
        os.makedirs(os.path.join(q, "tools"))
        for rel, d in (("Dockerfile", b"FROM x\n"), ("docker-compose.yml", self.COMPOSE), ("VERSION", b"1.8.5\n")):
            with open(os.path.join(q, rel), "wb") as f:
                f.write(d)
        with open(os.path.join(q, W.BAU_SIGNATUR_DATEI), "w") as f:
            f.write(W.bau_signatur_bauen(self.k, "1.8.5", W.bau_dateiliste(q)[0]))
        with open(os.path.join(q, "docker-compose.yml"), "wb") as f:
            f.write(b"services: {}\n")
        self.assertIn("lokal angepasst", W.bau_pruefen(q, self.pr["oeffentlich"])["text"])
        self.assertIn("nach dem Signieren geändert", W.bau_pruefen(q, self.pr["oeffentlich"], vor_ort=False)["text"])

    def test_nfd_namen_in_der_signatur(self):
        """N7: auf macOS signiert (NFD), im Tag NFC - die Datei kommt trotzdem in die ZIP."""
        self.pr.update(regel="alle")
        nfc, nfd = unicodedata.normalize("NFC", "Übersicht.txt"), unicodedata.normalize("NFD", "Übersicht.txt")
        dateien = {"VERSION": b"1.8.5\n", nfc: b"Inhalt\n"}
        summen = {(nfd if n == nfc else n): W.hashlib.sha256(d).hexdigest() for n, d in dateien.items()}
        dateien[W.SIGNATUR_DATEI] = json.dumps({"format": W.FORMAT, "version": "1.8.5", "dateien": summen, "signatur":
                                                base64.b64encode(self.k.sign(W.nachricht("1.8.5", summen))).decode()}).encode()
        puf = io.BytesIO()
        with zipfile.ZipFile(puf, "w") as z:
            z.writestr("B-b-abc/", "")
            for rel, d in dateien.items():
                z.writestr("B-b-abc/" + rel, d)
        r = self.laden(puf.getvalue())
        self.assertEqual(r["unsigniert"], [])
        with zipfile.ZipFile(r["zip"]) as z:
            self.assertIn("programmordner/" + nfc, z.namelist())


class PaketlisteStrengTests(unittest.TestCase):
    """M1, N1, N2: Paketliste nur mit Anforderungen und Prüfsummen, Anzeige vollständig."""

    def test_echtes_format_angenommen(self):
        text = ("# Automatisch erzeugt\n# Programmversion: 1.8.13\n\nblinker==1.9.0 \\\n    --hash=sha256:" + H + " \\\n"
                "    --hash=sha256:" + "b" * 64 + "\ncolorama==0.4.6 ; sys_platform == \"win32\" \\\n    --hash=sha256:" + H
                + "\nuvicorn[standard]==0.30.0 \\\n    --hash=sha256:" + H + "\n    # via flask\n")
        p = W.pakete_zeilen_pruefen(text)
        self.assertEqual(p["blinker"], ("1.9.0", frozenset({H, "b" * 64})))
        self.assertEqual(p["colorama"][0], "0.4.6")
        self.assertIn("uvicorn", p)
        self.assertTrue(W.pakete_zeilen_pruefen(test_pakete.LOCK.decode()))

    def test_optionen_und_urls_abgelehnt(self):
        gut = "beispiel==1.2.3 \\\n    --hash=sha256:" + H + "\n"
        for falsch in ("--index-url https://boese.example/simple\n" + gut,
                       "-i https://boese.example/simple\n" + gut,
                       gut + "--extra-index-url https://boese.example/simple\n",
                       gut + "--find-links https://boese.example/\n",
                       gut + "--trusted-host boese.example\n",
                       gut + "-r https://boese.example/mehr.txt\n",
                       gut + "-c andere.txt\n",
                       gut + "-e git+https://boese.example/x.git#egg=x\n",
                       gut + "x @ https://boese.example/x.whl --hash=sha256:" + H + "\n",
                       gut + "ohne-pruefsumme==1.0\n",
                       gut + "beispiel==1.2.4 \\\n    --hash=sha256:" + H + "\n",                  # doppelt
                       "beispiel==1.2.3 \\\n    --hash=sha256:" + H + " \\\n    --index-url https://boese.example/\n",
                       "beispiel==1.2.3 \\\n    --hash=md5:" + "a" * 32 + "\n",
                       "beispiel>=1.2.3 \\\n    --hash=sha256:" + H + "\n"):
            with self.subTest(falsch=falsch[:50]):
                self.assertRaisesRegex(ValueError, "erlaubt sind nur|doppelt", W.pakete_zeilen_pruefen, falsch)

    def test_pruefsummen_bei_gleicher_version(self):
        alt = "beispiel==1.2.3 \\\n    --hash=sha256:" + H + "\n"
        neu = "beispiel==1.2.3 \\\n    --hash=sha256:" + "c" * 64 + "\n"
        self.assertEqual(W.pakete_unterschiede(alt, neu), ["beispiel 1.2.3: Prüfsummen geändert (1 neu, 1 entfallen) - bitte prüfen"])
        self.assertEqual(W.pakete_unterschiede(alt, alt), [])

    def test_wegfall_und_unbekannt(self):
        zeile = ("# cloudflared: 2026.10.0 amd64=" + "1" * 64 + " arm64=" + "2" * 64 + " armhf=" + "3" * 64
                 + " windows-amd64=" + "4" * 64 + "\n")
        self.assertEqual(W._cloudflared_unterschied(zeile, "x\n"), ["cloudflared-Zeile entfällt (bisher 2026.10.0)"])
        self.assertIn("unbekannt", W._cloudflared_unterschied(None, zeile, bekannt=False)[0])
        deb = "# debian: trixie 20261024T000000Z\n"
        self.assertEqual(W._debian_text(deb, "x\n"), "Debian-Zeile entfällt (bisher trixie, Stand 24.10.2026)")
        self.assertIn("bisher unbekannt", W._debian_text(None, deb, bekannt=False))


class PaketlisteAblaufTests(test_pakete.AblaufTests):
    def test_pip_optionen_nicht_signiert(self):
        self.dateien["pakete"][W.PAKETE_DATEI] = test_pakete.LOCK + b"--index-url https://boese.example/simple\n"
        self.assertRaisesRegex(ValueError, "erlaubt sind nur", self.lauf, "pakete_pruefen")

    def test_vorige_liste_nicht_ermittelbar(self):
        self.dateien["pakete"][W.PAKETE_DATEI] = test_pakete.LOCK + b"# debian: trixie 20261024T000000Z\n"
        self.verlauf_fehler = True
        d, _ = self.lauf("pakete_pruefen")
        self.assertIn("bisher unbekannt", d["debian"])

    def test_wegfall_wird_angezeigt(self):
        alt = test_pakete.LOCK + b"# debian: trixie 20260926T000000Z\n"
        sig = W.pakete_signatur_bauen(self.privat, "9.9.9", W.pakete_pruefsumme(alt), "2030-01-01")
        self.dateien["vorher"] = {W.PAKETE_DATEI: alt, W.PAKETE_SIGNATUR_DATEI: sig.encode()}
        d, _ = self.lauf("pakete_pruefen")
        self.assertEqual(d["seit_signiert"], ["Debian-Zeile entfällt (bisher trixie, Stand 26.09.2026)"])

    def test_signieren_ohne_verlaufsabfrage(self):
        self.verlauf_abgefragt = False
        self.lauf("pakete_signieren", kennwort=test_pakete.KENNWORT, summe=test_pakete.SUMME)
        self.assertFalse(self.verlauf_abgefragt)

    def test_seite_pruefen_ohne_schluesseldatei(self):
        teil = W.SEITE.split('$("s-pakete-pruefen").onclick', 1)[1].split("});", 1)[0]
        self.assertNotIn("profilPruefen", teil)
        self.assertIn("seit_signiert", W.SEITE)


class QnapAblaufTests(unittest.TestCase):
    """M2, N4-N6, N8."""

    def test_compose_schritte_im_installieren(self):
        ids = [s["id"] for s in Q._schritte("installieren")]
        self.assertEqual(ids[ids.index("entpacken") + 1:ids.index("entpacken") + 3], ["compose_vergleich", "compose_uebernehmen"])
        self.assertTrue(Q.SCHRITTE["compose_uebernehmen"]["optional"])
        pr = {"programmordner": "/share/BEISPIEL/programmordner", "root": True}
        z = {"alt": "programmordner.alt-20260101-1200"}
        v = Q.SCHRITTE["compose_vergleich"]["befehl"](pr, {}, z, False)
        self.assertIn("diff -u 'programmordner/docker-compose.yml' 'programmordner.alt-20260101-1200/docker-compose.yml'", v)
        self.assertNotIn("cp", v)
        u = Q.SCHRITTE["compose_uebernehmen"]["befehl"](pr, {}, z, False)
        self.assertIn("cp -p -- 'programmordner.alt-20260101-1200/docker-compose.yml' 'programmordner/docker-compose.yml'", u)
        self.assertRaises(ValueError, Q.SCHRITTE["compose_uebernehmen"]["befehl"], pr, {}, {}, False)   # ohne Rückweg nichts
        for b in (v, u):
            self.assertTrue(b.isascii() and "$" not in b and "*" not in b, b)

    def test_aufraeumen_zeigt_reste(self):
        self.assertEqual(Q.ABLAEUFE["aufraeumen"]["schritte"][-1], "uebersicht")
        self.assertIn("kaputt", " ".join(Q.SCHRITTE["uebersicht"]["erklaerung"]))

    def test_erklaerung_version_aktuell(self):
        text = " ".join(Q.SCHRITTE["version"]["erklaerung"])
        self.assertNotIn("sind aber nicht signiert", text)
        self.assertIn("SIGNATUR-BAU.json", text)

    def test_scp_ohne_benutzerpfad(self):
        tmp = tempfile.mkdtemp(prefix="runde4-scp-")
        try:
            ordner = os.path.join(tmp, "Max!", "Signier-Werkzeug")
            os.makedirs(os.path.join(ordner, "qnap"))
            zust = {"profil": {"host": "192.0.2.10", "port": 22, "benutzer": "admin", "root": True,
                               "programmordner": "/share/BEISPIEL/programmordner", "compose": "plugin"}}
            b = Q.Begleiter(lambda: zust, lambda z: None, ordner, prog={"cmd": r"C:\Windows\System32\cmd.exe",
                            "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe", "scp": r"C:\Windows\System32\OpenSSH\scp.exe"})
            lauf = {"paket": {"zip": os.path.join(ordner, "qnap", "programmordner-1a2b3c4d.zip"),
                              "zipname": "programmordner.signier-20260101-1200.zip"}}
            befehl, _p, zeile = b._planen(zust, lauf, Q.SCHRITTE["hochladen"], zust["profil"])
            self.assertNotIn("Max!", zeile)
            self.assertIn(os.path.join("qnap", "programmordner-1a2b3c4d.zip"), zeile)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class HaertungUndDokuTests(unittest.TestCase):
    """N9-N14."""

    def lesen(self, *teile):
        with open(os.path.join(os.path.dirname(HIER), *teile), encoding="utf-8") as f:
            return f.read()

    def test_powershell_mit_festem_pfad(self):
        self.assertNotIn('["powershell"', self.lesen("signier_werkzeug.py"))
        with mock.patch.object(W.os, "name", "nt"), mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}), \
                mock.patch.object(W.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="")
            W._powershell("1")
        self.assertEqual(run.call_args[0][0][0], os.path.join(r"C:\Windows", "System32", "WindowsPowerShell", "v1.0",
                                                              "powershell.exe"))

    def test_sicherung_erst_nach_kennwortpruefung(self):
        tmp = tempfile.mkdtemp(prefix="runde4-sich-")
        try:
            with mock.patch.dict(os.environ, {"APPDATA": os.path.join(tmp, "appdata")}):
                d = W.aktion("profil_speichern", {"name": "A", "regel": "alle"})
                fremd = d["profile"][-1]["id"]
                W.aktion("schluessel_neu", {"id": fremd, "kennwort": "Test-Kennwort-123"})
                d = W.aktion("profil_speichern", {"name": "B", "regel": "alle"})
                pid = d["profile"][-1]["id"]
                W.aktion("schluessel_neu", {"id": pid, "kennwort": "Test-Kennwort-123"})
                ordner = os.path.join(tmp, "ordner")
                os.makedirs(ordner)
                with open(os.path.join(ordner, "a.txt"), "w") as f:
                    f.write("1")
                W.aktion("signieren_ordner", {"id": fremd, "ordner": ordner, "kennwort": "Test-Kennwort-123"})
                for _ in range(3):
                    self.assertRaises(ValueError, W.aktion, "signieren_ordner", {"id": pid, "ordner": ordner, "kennwort": "falsch"})
                sicherung = os.path.join(W.daten_ordner(), "sicherung")
                self.assertFalse(os.path.isdir(sicherung) and os.listdir(sicherung))
                W.aktion("signieren_ordner", {"id": pid, "ordner": ordner, "kennwort": "Test-Kennwort-123"})
                self.assertEqual(len(os.listdir(sicherung)), 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_doku(self):
        sich = self.lesen("SICHERHEIT.md")
        debian = sich.split("- Debian:", 1)[1].split("\n- ", 1)[0]
        self.assertNotIn("Weicht sie vom Format ab", debian.split("DEBIAN-PAKETE.txt", 1)[1])
        self.assertIn("rm -f", sich)   # Ausnahme der Hilfsdatei genannt
        readme = self.lesen("README.md").split("## QNAP", 1)[1].split("\n## ", 1)[0]
        liste = readme.split("Abläufe:", 1)[1]
        self.assertLess(liste.index("**Aufräumen:**"), liste.index("Vor jedem Neubau"))   # Liste nicht unterbrochen

    def test_bildschirmfotos_ohne_version(self):
        js = self.lesen("docs", "handbuch_bilder.js")
        self.assertIn("Version x.y.z", js)
        self.assertIn("versionPlatzhalter();\n  await seite.screenshot", js.replace("await warte(800); ", ""))


if __name__ == "__main__":
    unittest.main()
