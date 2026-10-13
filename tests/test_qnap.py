# -*- coding: utf-8 -*-
"""Tests für den QNAP-Begleiter (qnap_begleiter.py und die Anbindung in
signier_werkzeug.py). Nur Platzhalter - keine echten Hosts, Namen oder Pfade.
Es wird nie ein echtes ssh gestartet: der Starter ist ein Ersatzobjekt."""
import base64
import hashlib
import http.server
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import qnap_begleiter as Q  # noqa: E402
import signier_werkzeug as W  # noqa: E402

PROG = {"cmd": r"C:\Windows\System32\cmd.exe", "ssh": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "scp": r"C:\Windows\System32\OpenSSH\scp.exe"}
PROFIL = {"host": "192.0.2.10", "port": "22", "benutzer": "admin-benutzer",
          "programmordner": "/share/BEISPIEL/programmordner", "adresse": "http://192.0.2.10:8090", "quelle": "quelle01"}
ANGRIFFE = ["; rm -rf /", "$(id)", "`id`", "a;b", "a|b", "a&b", "a\nb", "a\rb", "a b", "'a'", '"a"', "a$b", "a>b", "a*b"]


def profil(**k):
    pr = Q.profil_pruefen({**PROFIL, **k}, ("quelle01",))
    pr["root"] = k.get("root_wert", pr["root"])
    return pr


class EingabeTests(unittest.TestCase):
    def test_gute_werte(self):
        self.assertEqual(Q.host_pruefen("nas.example"), "nas.example")
        self.assertEqual(Q.host_pruefen("192.0.2.10"), "192.0.2.10")
        self.assertEqual(Q.host_pruefen("2001:db8::1"), "2001:db8::1")
        self.assertEqual(Q.benutzer_pruefen("admin-benutzer"), "admin-benutzer")
        self.assertEqual(Q.port_pruefen(""), 22)
        self.assertEqual(Q.programmordner_pruefen("/share/BEISPIEL/programmordner"), "/share/BEISPIEL/programmordner")

    def test_host_angriffe(self):
        for wert in ANGRIFFE + ["-oProxyCommand=calc", "-p", "", "a/b", "a..b", "x" * 300]:
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.host_pruefen, wert)

    def test_benutzer_angriffe(self):
        for wert in ANGRIFFE + ["-oProxyCommand=calc", ".versteckt", "", "a@b", "a:b", "x" * 80]:
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.benutzer_pruefen, wert)

    def test_port(self):
        for wert in ("0", "65536", "abc", "22; id", "-1"):
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.port_pruefen, wert)

    def test_pfad_angriffe(self):
        for wert in ["/share/" + a for a in ANGRIFFE] + [
                "relativ/pfad", "/share/../etc", "/share/./x", "/share//x", "/share/x/", "/share/x/..", "..", "/",
                "/share/-x", "/share/x\x00", "/share/ä", "/share/x\\y", "~/x", "/share/x%y", "/share/x!y"]:
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.pfad_pruefen, wert)

    def test_programmordner_gesperrt(self):
        for wert in ("/share", "/share/Daten", "/share/BEISPIEL/daten", "/share/container-station-data",
                     "/share/BEISPIEL/.versteckt", "/share/BEISPIEL/programm.alt-20260101-1200"):
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.programmordner_pruefen, wert)

    def test_adresse(self):
        self.assertEqual(Q.adresse_pruefen(""), "")
        self.assertEqual(Q.adresse_pruefen("http://192.0.2.10:8090"), "http://192.0.2.10:8090")
        for wert in ("ftp://192.0.2.10", "http://nutzer:pw@192.0.2.10", "javascript:alert(1)", "http://", "http://a b",
                     "http://192.0.2.10:99999", "file:///etc/passwd"):
            with self.subTest(wert=wert):
                self.assertRaises(ValueError, Q.adresse_pruefen, wert)

    def test_profil_quelle_muss_existieren(self):
        self.assertRaises(ValueError, Q.profil_pruefen, {**PROFIL, "quelle": "gibtsnicht"}, ("quelle01",))

    def test_kein_freitext_fuer_befehle(self):
        pr = Q.profil_pruefen({**PROFIL, "befehl": "rm -rf /", "kommando": "id"}, ("quelle01",))
        self.assertEqual(set(pr), {"host", "port", "benutzer", "programmordner", "adresse", "quelle", "bin_ordner",
                                   "compose", "root"})


class BefehlTests(unittest.TestCase):
    def befehl(self, sid, pr, lauf=None, z=None):
        return Q.SCHRITTE[sid]["befehl"](pr, lauf or {}, z or {}, False)

    def test_quoting(self):
        self.assertEqual(Q.q("/share/a b"), "'/share/a b'")
        for wert in ("a'b", "a\nb", "a\x00"):
            self.assertRaises(ValueError, Q.q, wert)
        pr = profil(root_wert=True)
        self.assertEqual(self.befehl("ordner", pr), "ls -la '/share/BEISPIEL/programmordner'")
        self.assertEqual(self.befehl("zustand", pr), "cd '/share/BEISPIEL/programmordner' && docker compose ps")

    def test_sudo_ja_nein(self):
        self.assertEqual(self.befehl("bauen", profil(root_wert=False)),
                         "cd '/share/BEISPIEL/programmordner' && sudo docker compose build --no-cache")
        self.assertEqual(self.befehl("starten", profil(root_wert=True)),
                         "cd '/share/BEISPIEL/programmordner' && docker compose up -d")
        self.assertRaises(ValueError, self.befehl, "bauen", profil())   # root noch unbekannt
        self.assertIn("[sudo] ", Q.SCHRITTE["bauen"]["befehl"](profil(), {}, {}, True))   # nur Anzeige

    def test_compose_varianten(self):
        self.assertEqual(Q.compose(profil(root_wert=True, compose="standalone")), "docker-compose")
        self.assertEqual(Q.compose(profil(root_wert=False, compose="plugin")), "sudo docker compose")
        pr = profil(root_wert=False, compose="standalone", bin_ordner="/share/BEISPIEL/.qpkg/container-station/bin")
        self.assertEqual(Q.compose(pr), "sudo '/share/BEISPIEL/.qpkg/container-station/bin/docker-compose'")
        pr["compose"] = "plugin"
        self.assertEqual(Q.compose(pr), "sudo '/share/BEISPIEL/.qpkg/container-station/bin/docker' compose")
        self.assertEqual(self.befehl("images", pr), "sudo '/share/BEISPIEL/.qpkg/container-station/bin/docker' image prune -f")

    def test_verbindung_und_werkzeuge_wie_vorgegeben(self):
        pr = profil()
        self.assertEqual(self.befehl("verbindung", pr), "echo Verbindung-OK; id -u; uname -a")
        self.assertIn("docker compose version || docker-compose version", self.befehl("werkzeuge", pr))

    def test_beiseite_entpacken(self):
        pr = profil(root_wert=False)
        b = self.befehl("beiseite", pr, {"geplant_alt": "programmordner.alt-20260101-1200"})
        self.assertEqual(b, "cd '/share/BEISPIEL' && if [ -e 'programmordner.alt-20260101-1200' ]; then "
                            "echo 'ABBRUCH: programmordner.alt-20260101-1200 gibt es schon'; "
                            "else sudo mv -- 'programmordner' 'programmordner.alt-20260101-1200' && ls -la; fi")
        self.assertRaises(ValueError, self.befehl, "entpacken", pr)   # ohne geprüfte ZIP
        b = self.befehl("entpacken", pr, {"paket": {"sha256": "a" * 64}})
        self.assertIn("echo '" + "a" * 64 + "  programmordner.zip' | sha256sum -c - && ", b)
        self.assertIn("unzip -q 'programmordner.zip'", b)
        self.assertNotIn("sudo unzip", b)

    def test_aufraeumen_nur_erlaubte_ziele(self):
        """Kein Befehl nennt etwas anderes als Programmordner, …alt-, ….kaputt- oder die eigene ZIP;
        nie Platzhalterzeichen, nie rm -f/-rf, rm -r nur auf …alt-Ordner."""
        pr = profil(root_wert=False)
        z = {"alt": "programmordner.alt-20260101-1200"}
        lauf = {"paket": {"sha256": "b" * 64}, "geplant_alt": "programmordner.alt-20260101-1300",
                "geplant_kaputt": "programmordner.kaputt-20260101-1300"}
        erlaubt = {"'/share/BEISPIEL'", "'/share/BEISPIEL/programmordner'", "'programmordner'", "'programmordner.zip'",
                   "'programmordner.alt-20260101-1200'", "'programmordner.alt-20260101-1300'",
                   "'programmordner.kaputt-20260101-1300'"}
        import re
        for sid, s in Q.SCHRITTE.items():
            if not s.get("befehl"):
                continue
            with self.subTest(schritt=sid):
                b = s["befehl"](pr, lauf, z, False)
                for teil in re.findall(r"'[^']*'", b):
                    if teil.startswith("'ABBRUCH") or teil == "'" + "b" * 64 + "  programmordner.zip'":
                        continue
                    self.assertIn(teil, erlaubt, b)
                for verboten in ("*", "?", "rm -f", "rm -rf", "Daten", "container-station-data", "$", "`", '"'):
                    self.assertNotIn(verboten, b.replace("'" + "b" * 64, ""))
                if "rm -r" in b:
                    self.assertIn("rm -r -- 'programmordner.alt-20260101-1200'", b)

    def test_alt_loeschen_braucht_bekannten_alt_ordner(self):
        pr = profil(root_wert=True)
        for alt in ("", "programmordner", "Daten", "programmordner.alt-*", "anderer.alt-20260101-1200",
                    "programmordner.alt-20260101-1200/..", "../programmordner.alt-20260101-1200"):
            with self.subTest(alt=alt):
                self.assertRaises(ValueError, self.befehl, "alt_loeschen", pr, None, {"alt": alt})
                self.assertRaises(ValueError, self.befehl, "zurueckholen", pr, None, {"alt": alt})


class WindowsZeileTests(unittest.TestCase):
    def test_ssh_zeile(self):
        pr = profil(root_wert=True)
        argv = Q.ssh_argv(pr, "ls -la '/share/BEISPIEL/programmordner'", PROG)
        self.assertEqual(argv, [PROG["ssh"], "-t", "-p", "22", "--", "admin-benutzer@192.0.2.10",
                                "ls -la '/share/BEISPIEL/programmordner'"])
        prog, zeile = Q.befehlszeile(argv, PROG)
        self.assertEqual(prog, PROG["cmd"])
        self.assertEqual(zeile, '"C:\\Windows\\System32\\cmd.exe" /d /v:off /k ""C:\\Windows\\System32\\OpenSSH\\ssh.exe" '
                                '"-t" "-p" "22" "--" "admin-benutzer@192.0.2.10" "ls -la \'/share/BEISPIEL/programmordner\'""')

    def test_scp_ziel_ipv6(self):
        pr = profil(host="2001:db8::1")
        argv = Q.scp_argv(pr, r"C:\Daten\programmordner.zip", "/share/BEISPIEL/programmordner.zip", PROG)
        self.assertEqual(argv[-1], "admin-benutzer@[2001:db8::1]:/share/BEISPIEL/programmordner.zip")
        self.assertEqual(argv[1:4], ["-P", "22", "--"])

    def test_cmd_sonderzeichen_gesperrt(self):
        for a in ("a%PATH%b", "a!x!", 'a"b', "a\nb", "a\\", ""):
            with self.subTest(a=a):
                self.assertRaises(ValueError, Q.befehlszeile, [PROG["ssh"], a], PROG)

    def test_starten_nur_unter_windows(self):
        if os.name != "nt":
            self.assertRaises(ValueError, Q.konsole_starten, PROG["cmd"], "x", ".")

    @unittest.skipUnless(os.name == "nt", "nur Windows")
    def test_popen_ohne_shell(self):
        with mock.patch.object(Q.subprocess, "Popen") as popen, mock.patch.object(Q.os.path, "isfile", return_value=True):
            Q.konsole_starten(PROG["cmd"], "zeile", "C:\\")
        args, kw = popen.call_args
        self.assertEqual(args, ("zeile",))
        self.assertEqual(kw["executable"], PROG["cmd"])
        self.assertNotIn("shell", kw)


class Ablauf(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="qnap-test-")
        self.zustand = {}
        self.gestartet = []
        self.b = Q.Begleiter(lambda: json.loads(json.dumps(self.zustand)), self._speichern, self.tmp,
                             starter=lambda prog, zeile, ordner: self.gestartet.append(zeile), prog=PROG,
                             jetzt=lambda: 1767268800.0)
        self.b.profil_speichern(PROFIL, ("quelle01",))

    def _speichern(self, z):
        self.zustand = json.loads(json.dumps(z))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def paket(self, pr, tag, name):
        return {"tag": tag, "version": tag[1:], "commit": "c" * 40, "zip": os.path.join(self.tmp, name + ".zip"),
                "sha256": "d" * 64, "signiert": 3, "dateien": 5, "unsigniert": ["Dockerfile"], "unsigniert_anzahl": 1}

    def schritt(self, sid, ergebnis="geklappt", **extra):
        """Ein Schritt so, wie die Oberfläche ihn ausführt."""
        s = next(x for x in self.b.ansicht()["schritte"] if x["id"] == sid)
        if s["art"] != "anleitung":
            v = self.b.vorbereiten(sid)
            self.b.ausfuehren(sid, v["marke"], {"bestaetigt": True, **extra}, self.paket)
        return self.b.rueckmelden(sid, ergebnis, extra)

    def protokoll(self):
        with open(os.path.join(self.tmp, Q.PROTOKOLL_DATEI), encoding="utf-8") as f:
            return f.read()


class ReihenfolgeTests(Ablauf):
    def test_ohne_vorbereiten_oder_bestaetigung_startet_nichts(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.assertRaises(ValueError, self.b.ausfuehren, "verbindung", "", {"bestaetigt": True})
        self.assertRaises(ValueError, self.b.ausfuehren, "verbindung", "falsch", {"bestaetigt": True})
        v = self.b.vorbereiten("verbindung")
        self.assertRaises(ValueError, self.b.ausfuehren, "verbindung", v["marke"], {})   # nicht bestätigt
        self.assertRaises(ValueError, self.b.ausfuehren, "verbindung", v["marke"], {"bestaetigt": True})   # Marke verbraucht
        self.assertEqual(self.gestartet, [])
        v = self.b.vorbereiten("verbindung")
        self.b.ausfuehren("verbindung", v["marke"], {"bestaetigt": True})
        self.assertEqual(self.gestartet, [v["zeile"]])   # genau der angezeigte Befehl

    def test_nur_der_aktuelle_schritt(self):
        self.b.beginnen("installieren")
        for sid in ("verbindung", "bauen", "alt_loeschen"):
            self.assertRaises(ValueError, self.b.vorbereiten, sid)
        self.schritt("vorbereitung")
        self.assertRaises(ValueError, self.b.vorbereiten, "werkzeuge")
        v = self.b.vorbereiten("verbindung")
        self.b.ausfuehren("verbindung", v["marke"], {"bestaetigt": True})
        # der nächste ist erst nach der Rückmeldung frei
        self.assertRaises(ValueError, self.b.vorbereiten, "werkzeuge")
        self.b.rueckmelden("verbindung", "geklappt", {"root": "nein"})
        self.b.vorbereiten("werkzeuge")

    def test_rueckmeldung_erst_nach_ausfuehren(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.assertRaises(ValueError, self.b.rueckmelden, "verbindung", "geklappt", {"root": "ja"})
        self.assertRaises(ValueError, self.b.rueckmelden, "verbindung", "uebersprungen", {})   # nicht optional
        self.assertRaises(ValueError, self.b.rueckmelden, "verbindung", "egal", {})

    def test_fehler_haelt_an(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        d = self.schritt("verbindung", "fehler")
        self.assertTrue(d["hilfe"])
        self.assertEqual(d["lauf"]["index"], 1)
        self.assertRaises(ValueError, self.b.vorbereiten, "werkzeuge")
        self.schritt("verbindung", root="ja")
        self.assertEqual(self.b.ansicht()["lauf"]["index"], 2)

    def test_root_und_variante_werden_abgefragt(self):
        self.b.beginnen("neubau")
        self.schritt("vorbereitung")
        v = self.b.vorbereiten("verbindung")
        self.b.ausfuehren("verbindung", v["marke"], {"bestaetigt": True})
        self.assertRaises(ValueError, self.b.rueckmelden, "verbindung", "geklappt", {})
        self.b.rueckmelden("verbindung", "geklappt", {"root": "nein"})
        v = self.b.vorbereiten("werkzeuge")
        self.b.ausfuehren("werkzeuge", v["marke"], {"bestaetigt": True})
        self.assertRaises(ValueError, self.b.rueckmelden, "werkzeuge", "geklappt", {})
        self.b.rueckmelden("werkzeuge", "geklappt", {"compose": "standalone"})
        self.schritt("ordner")
        self.assertEqual(self.b.vorbereiten("zustand")["befehl"], "cd '/share/BEISPIEL/programmordner' && sudo docker-compose ps")

    def test_veranstaltungs_warnung(self):
        self.b.beginnen("neubau")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="ja")
        self.schritt("werkzeuge", compose="plugin")
        for sid in ("ordner", "zustand", "bauen"):
            self.schritt(sid)
        v = self.b.vorbereiten("starten")
        self.assertEqual(v["bestaetigung"], "veranstaltung")
        self.assertRaises(ValueError, self.b.ausfuehren, "starten", v["marke"], {"bestaetigt": True})
        v = self.b.vorbereiten("starten")
        self.b.ausfuehren("starten", v["marke"], {"bestaetigt": True, "veranstaltung": True})

    def test_profil_fest_waehrend_ablauf(self):
        self.b.beginnen("neubau")
        self.assertRaises(ValueError, self.b.profil_speichern, PROFIL, ("quelle01",))
        self.assertRaises(ValueError, self.b.beginnen, "neubau")
        self.b.abbrechen()
        self.b.profil_speichern(PROFIL, ("quelle01",))

    def test_kein_alle_ausfuehren(self):
        oeffentlich = [n for n in dir(self.b) if not n.startswith("_")]
        self.assertEqual(sorted(oeffentlich), sorted(["abbrechen", "alt_vergessen", "ansicht", "ausfuehren", "beginnen", "jetzt",
                                               "lock", "ordner", "profil_speichern", "prog", "protokollieren",
                                               "rueckmelden", "starter", "vorbereiten"]))


class InstallierenTests(Ablauf):
    def bis_beiseite(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="nein")
        self.schritt("werkzeuge", compose="plugin")
        self.schritt("version", tag="v1.8.5")
        self.schritt("hochladen")
        self.schritt("ordner")
        self.schritt("zustand")
        self.schritt("anhalten", veranstaltung=True)

    def test_ganzer_ablauf(self):
        self.bis_beiseite()
        v = self.b.vorbereiten("beiseite")
        self.assertEqual(v["name"], "programmordner")
        self.assertRaises(ValueError, self.b.ausfuehren, "beiseite", v["marke"], {"bestaetigt": True, "name": "programm"})
        v = self.b.vorbereiten("beiseite")
        self.b.ausfuehren("beiseite", v["marke"], {"bestaetigt": True, "name": "programmordner"})
        self.b.rueckmelden("beiseite", "geklappt", {})
        alt = self.b.ansicht()["alt"]
        self.assertRegex(alt, r"^programmordner\.alt-\d{8}-\d{4}$")
        for sid in ("entpacken", "bauen", "starten", "kontrolle"):
            self.schritt(sid)
        v = self.b.vorbereiten("alt_loeschen")
        self.assertEqual(v["befehl"], f"cd '/share/BEISPIEL' && sudo rm -r -- '{alt}' && ls -la")
        self.assertRaises(ValueError, self.b.ausfuehren, "alt_loeschen", v["marke"], {"bestaetigt": True})
        v = self.b.vorbereiten("alt_loeschen")
        self.b.ausfuehren("alt_loeschen", v["marke"], {"bestaetigt": True, "name": alt})
        self.b.rueckmelden("alt_loeschen", "geklappt", {})
        self.assertEqual(self.b.ansicht()["alt"], "")
        self.b.rueckmelden("zip_loeschen", "uebersprungen", {})
        d = self.b.rueckmelden("images", "uebersprungen", {})
        self.assertTrue(d["fertig"])
        self.assertIsNone(d["lauf"])
        # scp lädt die geprüfte ZIP in den Elternordner, unter festem Namen
        scp = [z for z in self.gestartet if "scp.exe" in z]
        self.assertEqual(len(scp), 1)
        self.assertIn('"admin-benutzer@192.0.2.10:/share/BEISPIEL/programmordner.zip"', scp[0])
        self.assertEqual(len(self.gestartet), 12)   # jeder SSH-/scp-Schritt einzeln

    def test_version_nur_tag(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="ja")
        self.schritt("werkzeuge", compose="plugin")
        for tag in ("main", "v1.8", "1.8.5", "v1.8.5; id", ""):
            v = self.b.vorbereiten("version")
            self.assertRaises(ValueError, self.b.ausfuehren, "version", v["marke"], {"bestaetigt": True, "tag": tag}, self.paket)
        self.assertRaises(ValueError, self.b.vorbereiten, "hochladen")

    def test_fehlerhafte_version_haelt_an(self):
        self.b.beginnen("installieren")
        self.schritt("vorbereitung")
        self.schritt("verbindung", root="ja")
        self.schritt("werkzeuge", compose="plugin")
        v = self.b.vorbereiten("version")

        def schlecht(*a):
            raise ValueError("Signatur ungültig")
        self.assertRaises(ValueError, self.b.ausfuehren, "version", v["marke"], {"bestaetigt": True, "tag": "v1.8.5"}, schlecht)
        self.assertEqual(self.b.ansicht()["schritte"][3]["status"], "fehler")
        self.assertRaises(ValueError, self.b.rueckmelden, "version", "geklappt", {})
        self.assertRaises(ValueError, self.b.vorbereiten, "hochladen")

    def test_rueckweg(self):
        self.bis_beiseite()
        v = self.b.vorbereiten("beiseite")
        self.b.ausfuehren("beiseite", v["marke"], {"bestaetigt": True, "name": "programmordner"})
        self.b.rueckmelden("beiseite", "geklappt", {})
        alt = self.b.ansicht()["alt"]
        self.schritt("entpacken", "fehler")
        self.b.abbrechen()
        self.assertEqual(self.b.ansicht()["alt"], alt)   # bleibt gemerkt
        self.assertRaises(ValueError, self.b.beginnen, "installieren")   # Rückweg nicht überschreiben
        self.b.beginnen("zurueck")
        self.schritt("verbindung", root="ja")
        self.b.rueckmelden("anhalten", "uebersprungen", {})
        self.b.rueckmelden("wegstellen", "uebersprungen", {})
        v = self.b.vorbereiten("zurueckholen")
        self.assertEqual(v["befehl"], f"cd '/share/BEISPIEL' && if [ -e 'programmordner' ]; then echo 'ABBRUCH: "
                                      f"programmordner gibt es noch'; else mv -- '{alt}' 'programmordner' && ls -la; fi")
        self.b.ausfuehren("zurueckholen", v["marke"], {"bestaetigt": True, "name": alt})
        self.b.rueckmelden("zurueckholen", "geklappt", {})
        self.assertEqual(self.b.ansicht()["alt"], "")
        self.b.vorbereiten("starten")

    def test_zurueck_ohne_alt_ordner(self):
        self.assertRaises(ValueError, self.b.beginnen, "zurueck")


class ProtokollTests(Ablauf):
    def test_keine_passwoerter(self):
        self.b.beginnen("neubau")
        geheim = {"passwort": "Geheim-Passwort-123", "kennwort": "Geheim-Passwort-123", "token": "ghp_Geheim123"}
        s = self.b.ansicht()["schritte"][0]
        self.b.rueckmelden(s["id"], "geklappt", geheim)
        v = self.b.vorbereiten("verbindung")
        self.b.ausfuehren("verbindung", v["marke"], {"bestaetigt": True, **geheim})
        self.b.rueckmelden("verbindung", "geklappt", {"root": "ja", **geheim})
        text = self.protokoll()
        self.assertNotIn("Geheim", text)
        self.assertIn("echo Verbindung-OK; id -u; uname -a", text)
        self.assertIn("hat geklappt", text)
        for zeile in text.splitlines():
            self.assertEqual(len(zeile.split("\t")), 5, zeile)
        self.assertNotIn("Geheim", json.dumps(self.zustand))

    def test_rotation(self):
        with mock.patch.object(Q, "PROTOKOLL_MAX", 100):
            for i in range(20):
                self.b.protokollieren("a", "b", "c", "x" * 20)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, Q.PROTOKOLL_DATEI + ".1")))
        self.assertLess(os.path.getsize(os.path.join(self.tmp, Q.PROTOKOLL_DATEI)), 400)

    def test_zeilenumbruch_im_protokoll(self):
        self.b.protokollieren("a\nb", "c", "d\re", "f")
        self.assertEqual(len(self.protokoll().splitlines()), 1)


class HttpTests(unittest.TestCase):
    def setUp(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                code = {"/": 200, "/weiter": 302, "/kaputt": 500}.get(self.path, 404)
                self.send_response(code)
                if code == 302:
                    self.send_header("Location", "http://198.51.100.1/")
                self.end_headers()
        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.basis = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def test_status(self):
        self.assertEqual(Q.http_pruefen(self.basis + "/"), {"ok": True, "text": "Dashboard antwortet (HTTP 200)."})
        r = Q.http_pruefen(self.basis + "/weiter")   # nicht gefolgt (198.51.100.1 wäre nicht erreichbar)
        self.assertTrue(r["ok"])
        self.assertIn("302", r["text"])
        self.assertFalse(Q.http_pruefen(self.basis + "/kaputt")["ok"])
        self.assertRaises(ValueError, Q.http_pruefen, "")
        port = self.server.server_address[1]
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.assertFalse(Q.http_pruefen(f"http://127.0.0.1:{port}/", timeout=2)["ok"])


class PaketTests(unittest.TestCase):
    """qnap_paket: signierte Version laden, prüfen, saubere ZIP bauen."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="qnap-paket-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata")})
        self._env.start()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.privat = Ed25519PrivateKey.generate()
        self.pr = {"id": "quelle01", "repo": "Besitzer/beispiel", "oeffentlich": W.oeffentlich_text(self.privat),
                   "regel": "alle", "ausschluss": ["Dockerfile", "tools/*"]}

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def zipball(self, version="1.8.5", aendern=None, sig_version=None):
        dateien = {"app.py": b"print(1)\n", "VERSION": (version + "\n").encode(), "templates/a.html": b"<p>\n",
                   "Dockerfile": b"FROM x\n", "tools/start.sh": b"#!/bin/sh\n"}
        # Prüfsummen so, wie das Werkzeug sie bildet: über einen echten Ordner
        ordner = os.path.join(self.tmp, "quelle")
        shutil.rmtree(ordner, ignore_errors=True)
        for rel, daten in dateien.items():
            os.makedirs(os.path.join(ordner, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(ordner, rel), "wb") as f:
                f.write(daten)
        signiert = W.dateiliste(ordner, "alle", self.pr["ausschluss"])
        v = sig_version or version
        sig = json.dumps({"format": W.FORMAT, "version": v, "dateien": signiert,
                          "signatur": base64.b64encode(self.privat.sign(W.nachricht(v, signiert))).decode()})
        dateien[W.SIGNATUR_DATEI] = sig.encode()
        if aendern:
            dateien.update(aendern)
        puffer = io.BytesIO()
        with zipfile.ZipFile(puffer, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Besitzer-beispiel-abc1234/", "")
            for rel, daten in dateien.items():
                info = zipfile.ZipInfo("Besitzer-beispiel-abc1234/" + rel)
                info.external_attr = (0o100755 if rel.endswith(".sh") else 0o100644) << 16
                z.writestr(info, daten)
        return puffer.getvalue()

    def laden(self, archiv, tag="v1.8.5"):
        def gh(pfad, token, *a, ziel=None, **k):
            self.assertEqual(pfad, "/repos/Besitzer/beispiel/zipball/" + "e" * 40)
            ziel.write(archiv)
            return len(archiv)
        with mock.patch.object(W, "_tag_commit", return_value="e" * 40), mock.patch.object(W, "_gh", side_effect=gh):
            return W.qnap_paket(self.pr, None, tag, "programmordner", os.path.join(self.tmp, "ziel"))

    def test_gute_version(self):
        r = self.laden(self.zipball())
        self.assertEqual((r["version"], r["commit"], r["signiert"], r["dateien"]), ("1.8.5", "e" * 40, 3, 6))
        self.assertEqual(r["unsigniert"], ["Dockerfile", "tools/start.sh"])
        with open(r["zip"], "rb") as f:
            daten = f.read()
        self.assertEqual(hashlib.sha256(daten).hexdigest(), r["sha256"])
        with zipfile.ZipFile(io.BytesIO(daten)) as z:
            namen = z.namelist()
            self.assertTrue(all(n.startswith("programmordner/") for n in namen), namen)
            self.assertIn("programmordner/templates/", namen)
            modi = {i.filename: (i.external_attr >> 16) & 0o777 for i in z.infolist()}
        self.assertEqual(modi["programmordner/tools/start.sh"], 0o755)
        self.assertEqual(modi["programmordner/app.py"], 0o644)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "ziel")), ["programmordner.zip"])   # nichts liegen geblieben

    def test_veraendert_abgelehnt(self):
        self.assertRaises(ValueError, self.laden, self.zipball(aendern={"app.py": b"print(2)\n"}))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ziel", "programmordner.zip")))

    def test_version_muss_zum_tag_passen(self):
        self.assertRaises(ValueError, self.laden, self.zipball(), "v1.8.6")
        self.assertRaises(ValueError, self.laden, self.zipball(version="1.8.5", sig_version="1.8.4"))

    def test_fremder_schluessel(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        archiv = self.zipball()
        self.pr["oeffentlich"] = W.oeffentlich_text(Ed25519PrivateKey.generate())
        self.assertRaises(ValueError, self.laden, archiv)

    def test_unzulaessige_angaben(self):
        for tag, name in (("main", "programmordner"), ("v1.8.5", "../x"), ("v1.8.5", "a b")):
            self.assertRaises(ValueError, W.qnap_paket, self.pr, None, tag, name, self.tmp)


class AnbindungTests(unittest.TestCase):
    """aktion("qnap_…") im Werkzeug: eigene Datei qnap.json, Schlüssel unberührt."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="qnap-aktion-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": self.tmp})
        self._env.start()
        W._sitzung["token"] = ""
        W.profile_speichern({"profile": [{"id": "quelle01", "name": "Beispiel", "repo": "Besitzer/beispiel",
                                          "zweig": "main", "regel": "alle", "oeffentlich": "x" * 44, "ausschluss": []}]})
        with open(W._profile_datei(), "rb") as f:
            self.profile_vorher = f.read()

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_profil_und_ablauf(self):
        d = W.aktion("qnap_zustand", {})
        self.assertIsNone(d["profil"])
        self.assertEqual(d["quellen"], [{"id": "quelle01", "name": "Beispiel", "repo": "Besitzer/beispiel"}])
        self.assertRaises(ValueError, W.aktion, "qnap_profil_speichern", {**PROFIL, "host": "; rm -rf /"})
        d = W.aktion("qnap_profil_speichern", PROFIL)
        self.assertEqual(d["profil"]["programmordner"], "/share/BEISPIEL/programmordner")
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, W.PROGRAMM, "qnap.json")))
        with open(W._profile_datei(), "rb") as f:
            self.assertEqual(f.read(), self.profile_vorher)   # profile.json unverändert
        W.aktion("qnap_beginnen", {"ablauf": "neubau"})
        self.assertRaises(ValueError, W.aktion, "qnap_vorbereiten", {"schritt": "bauen"})
        self.assertRaises(ValueError, W.aktion, "qnap_unbekannt", {})
        self.assertEqual(os.listdir(os.path.join(self.tmp, W.PROGRAMM, "schluessel")), [])

    def test_seite_hat_reiter_und_platzhalter(self):
        self.assertIn('data-reiter="qnap"', W.SEITE)
        self.assertIn('id="r-qnap"', W.SEITE)
        self.assertIn("192.0.2.10", W.SEITE)   # nur Dokumentations-Adressen als Platzhalter
        self.assertNotIn("Alle Schritte ausführen", W.SEITE)


if __name__ == "__main__":
    unittest.main()
