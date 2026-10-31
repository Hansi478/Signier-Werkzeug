# -*- coding: utf-8 -*-
"""Neue Paketliste erstellen lassen: Action paketliste.yml des Dashboards starten und verfolgen."""
import os
import sys
import unittest
from unittest import mock

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HIER))
import signier_werkzeug as W  # noqa: E402

PR = {"id": "dashboard1", "regel": "speedrace", "repo": "Besitzer/beispiel", "zweig": "main"}
LAUF = "https://github.com/Besitzer/beispiel/actions/runs/123"


class StartenTests(unittest.TestCase):
    def test_startet_genau_die_action(self):
        aufrufe = []

        def gh(pfad, token, methode="GET", daten=None, **k):
            aufrufe.append((pfad, methode, daten))
            return {}
        with mock.patch.object(W, "_gh", side_effect=gh), mock.patch.object(W, "_zweig_stand", return_value="a" * 40):
            d = W.pakete_bau_starten(PR, "t")
        self.assertEqual(aufrufe, [("/repos/Besitzer/beispiel/actions/workflows/paketliste.yml/dispatches", "POST",
                                    {"ref": "main"})])
        self.assertEqual(d["stand"], "a" * 40)
        self.assertRegex(d["seit"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_ohne_zweig_pakete(self):
        def zweig(*a):
            raise W.GitHubFehler("nicht gefunden", 404)
        with mock.patch.object(W, "_gh", return_value={}), mock.patch.object(W, "_zweig_stand", side_effect=zweig):
            self.assertEqual(W.pakete_bau_starten(PR, "t")["stand"], "")

    def test_fehler_verstaendlich(self):
        for code, text in ((403, "Actions: Read and write"), (404, "gibt es"), (422, "workflow_dispatch")):
            with self.subTest(code=code), mock.patch.object(W, "_zweig_stand", return_value="a" * 40), \
                    mock.patch.object(W, "_gh", side_effect=W.GitHubFehler("x", code)):
                self.assertRaisesRegex(ValueError, text, W.pakete_bau_starten, PR, "t")

    def test_nur_speedrace(self):
        self.assertRaisesRegex(ValueError, "nur für Profile", W.pakete_bau_starten, {**PR, "regel": "alle"}, "t")


class StatusTests(unittest.TestCase):
    def status(self, laeufe, zweig="a" * 40, jobs=None):
        def gh(pfad, token, *a, **k):
            if "/jobs" in pfad:
                return {"jobs": jobs or []}
            self.assertIn("/actions/workflows/paketliste.yml/runs?event=workflow_dispatch", pfad)
            return {"workflow_runs": laeufe}
        with mock.patch.object(W, "_gh", side_effect=gh), mock.patch.object(W, "_zweig_stand", return_value=zweig):
            return W.pakete_bau_status(PR, "t", "2026-10-31T10:00:00Z", "a" * 40)

    def test_alter_lauf_zaehlt_nicht(self):
        d = self.status([{"id": 1, "created_at": "2026-10-30T10:00:00Z", "status": "completed", "conclusion": "success"}])
        self.assertEqual(d["zustand"], "wartet")

    def test_laeuft_mit_schritt(self):
        d = self.status([{"id": 2, "created_at": "2026-10-31T10:00:05Z", "status": "in_progress", "html_url": LAUF}],
                        jobs=[{"name": "liste", "steps": [{"name": "Tests", "status": "in_progress"}]}])
        self.assertEqual((d["zustand"], d["schritt"], d["url"]), ("laeuft", "liste: Tests", LAUF))

    def test_fertig_neu_oder_nicht(self):
        lauf = [{"id": 3, "created_at": "2026-10-31T10:00:05Z", "status": "completed", "conclusion": "success",
                 "html_url": "https://example.org/x"}]
        d = self.status(lauf, zweig="b" * 40)
        self.assertEqual((d["zustand"], d["neu"], d["url"]), ("fertig", True, ""))   # fremde Adresse nicht verlinkt
        self.assertFalse(self.status(lauf)["neu"])   # Zweig unverändert: keine neue Liste

    def test_fehlgeschlagen(self):
        d = self.status([{"id": 4, "created_at": "2026-10-31T10:01:00Z", "status": "completed", "conclusion": "failure"}])
        self.assertEqual((d["zustand"], d["neu"]), ("fehlgeschlagen", False))

    def test_ungueltiger_zeitpunkt(self):
        self.assertRaises(ValueError, W.pakete_bau_status, PR, "t", "gestern", "")


class SeiteTests(unittest.TestCase):
    def test_knopf_und_abfrage(self):
        for teil in ('id="s-pakete-bauen"', 'api("pakete_bau_starten"', 'api("pakete_bau_status"', "Actions: Read and write"):
            self.assertIn(teil, W.SEITE)


if __name__ == "__main__":
    unittest.main()
