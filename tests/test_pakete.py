# -*- coding: utf-8 -*-
"""Paketliste signieren (SIGNATUR-PAKETE.json, Format sr-pakete-signatur-1)."""
import base64
import json
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
# Testbeispiel der Übergabe (byte-genau)
LOCK = ("# Automatisch erzeugt mit tools/lock_erzeugen.py - NICHT von Hand ändern.\n"
        "# Programmversion: 9.9.9   (bei jeder neuen Version neu erzeugen)\n\n"
        "beispiel==1.2.3 \\\n    --hash=sha256:" + "a" * 64 + "\n").encode("utf-8")
SUMME = "fc285dc41458c4df60992baaca36140eb30d90af228bd483c68f5b4cee8ea8f2"
ERWARTET = ('{\n "erstellt": "2030-01-01",\n "format": "sr-pakete-signatur-1",\n "lock_sha256": "' + SUMME + '",\n'
            ' "programmversion": "9.9.9",\n "signatur": "rwOui8UgQv/uuGLz+KHt/6O9j+Mpn50AZRenQxfZAmVXEtEZ1NQdO3xMzSsR9L5Csh2dvORZgM9xuUG09sK9Dw=="\n}\n')


def test_schluessel():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)


class FormatTests(unittest.TestCase):
    def test_testbeispiel_byte_genau(self):
        k = test_schluessel()
        self.assertEqual(W.oeffentlich_text(k), "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=")
        self.assertEqual(W.pakete_pruefsumme(LOCK), SUMME)
        self.assertEqual(W.pakete_pruefsumme(LOCK.replace(b"\n", b"\r\n")), SUMME)   # CRLF wie LF
        self.assertEqual(W.pakete_nachricht("9.9.9", SUMME, "2030-01-01").decode(),
                         '{"erstellt":"2030-01-01","format":"sr-pakete-signatur-1","lock_sha256":"' + SUMME
                         + '","programmversion":"9.9.9"}')
        self.assertEqual(W.pakete_signatur_bauen(k, "9.9.9", SUMME, "2030-01-01"), ERWARTET)

    def test_version_aus_kopfzeile(self):
        self.assertEqual(W.pakete_version(LOCK), "9.9.9")
        for falsch in (b"beispiel==1\n", b"# Programmversion:\n", b"# Programmversion: neu\n", b"\xff\xfe"):
            self.assertRaises(ValueError, W.pakete_version, falsch)

    def test_gueltigkeit_wie_im_dashboard(self):
        oeff = W.oeffentlich_text(test_schluessel())
        daten = ERWARTET.encode()
        self.assertTrue(W.pakete_signatur_gueltig(daten, oeff, SUMME, "9.9.9"))
        self.assertFalse(W.pakete_signatur_gueltig(daten, oeff, "0" * 64, "9.9.9"))   # andere Liste
        self.assertFalse(W.pakete_signatur_gueltig(daten, oeff, SUMME, "9.9.8"))   # andere Version
        sig = json.loads(ERWARTET)
        sig["signatur"] = sig["signatur"][:20] + "\n" + sig["signatur"][20:]   # Base64 streng
        self.assertFalse(W.pakete_signatur_gueltig(json.dumps(sig).encode(), oeff, SUMME, "9.9.9"))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.assertFalse(W.pakete_signatur_gueltig(daten, W.oeffentlich_text(Ed25519PrivateKey.generate()), SUMME, "9.9.9"))

    def test_cloudflared_zeile(self):
        a, b, c = "a" * 64, "b" * 64, "c" * 64
        text = f"# Programmversion: 1.8.12\n# cloudflared: 2026.10.0 amd64={a} arm64={b} armhf={c}\n"
        self.assertEqual(W.pakete_cloudflared(text),
                         {"version": "2026.10.0", "sha256": {"amd64": a, "arm64": b, "armhf": c}})
        self.assertIsNone(W.pakete_cloudflared("# Programmversion: 1.8.12\n"))
        for falsch in (f"# cloudflared: 2026.10.0 amd64={a} arm64={b}",                 # Architektur fehlt
                       f"# cloudflared: 2026.10.0 amd64={a} arm64={b} armhf={c} x86=1",  # zusätzlich
                       f"# cloudflared: 2026.10.0 amd64={a} arm64={b} armhf={c[:-1]}",   # zu kurz
                       f"# cloudflared: 2026.10.0 amd64={a.upper()} arm64={b} armhf={c}",
                       f"# cloudflared: latest amd64={a} arm64={b} armhf={c}",
                       f"# cloudflared: 2026.10.0 amd64={a} amd64={b} armhf={c}",
                       f"# cloudflared: 2026.10.0 amd64={a} arm64={b} armhf={c}\n# cloudflared: 2026.9.0 amd64={a} arm64={b} armhf={c}"):
            with self.subTest(falsch=falsch):
                self.assertRaisesRegex(ValueError, "cloudflared-Zeile", W.pakete_cloudflared, falsch)
        neu = f"# cloudflared: 2026.10.0 amd64={a} arm64={b} armhf={c}\n"
        self.assertEqual(W._cloudflared_unterschied(None, neu), ["cloudflared 2026.10.0 (neu in der Liste)"])
        self.assertEqual(W._cloudflared_unterschied(neu.replace("2026.10.0", "2026.9.1"), neu),
                         ["cloudflared 2026.9.1 → 2026.10.0"])
        self.assertEqual(W._cloudflared_unterschied(neu, neu), [])
        self.assertIn("Prüfsummen geändert", W._cloudflared_unterschied(neu.replace(a, "d" * 64), neu)[0])

    def test_unterschiede(self):
        alt = "pypdf==6.20.1 \\\n    --hash=sha256:x\nalt_paket==1.0\nFlask==3.0.0\n"
        neu = "pypdf==6.21.1 \\\n    --hash=sha256:y\nflask==3.0.0\nneu-paket[extra]==2.0 ; python_version >= '3'\n"
        self.assertEqual(W.pakete_unterschiede(alt, neu),
                         ["pypdf 6.20.1 → 6.21.1", "neu-paket 2.0 (neu)", "alt-paket 1.0 (entfällt)"])


class AblaufTests(unittest.TestCase):
    """GitHub nachgestellt: Zweig „pakete“, Tag v9.9.9 mit gültiger SIGNATUR.json."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pakete-")
        self._env = mock.patch.dict(os.environ, {"APPDATA": os.path.join(self.tmp, "appdata")})
        self._env.start()
        d = W.aktion("profil_speichern", {"name": "Dashboard", "regel": "speedrace", "repo": "Besitzer/beispiel"})
        pid = d["profile"][-1]["id"]
        d = W.aktion("schluessel_neu", {"id": pid, "kennwort": KENNWORT})
        self.pr = next(p for p in d["profile"] if p["id"] == pid)
        self.privat = W.privat_laden(W.schluessel_pfad(self.pr), KENNWORT)
        alt = b"beispiel==1.2.2 \\\n    --hash=sha256:" + b"b" * 64 + b"\n"
        dateien = {"requirements.lock": W.pakete_pruefsumme(alt), "app.py": "0" * 64}
        sig = json.dumps({"format": W.FORMAT, "version": "9.9.9", "dateien": dateien,
                          "signatur": base64.b64encode(self.privat.sign(W.nachricht("9.9.9", dateien))).decode()})
        self.dateien = {"pakete": {W.PAKETE_DATEI: LOCK}, "tag": {W.SIGNATUR_DATEI: sig.encode(), "requirements.lock": alt}}
        self.tag = "7" * 40

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lauf(self, aktion, **p):
        hoch = mock.Mock(return_value="c" * 40)

        def baum(repo, token, commit):
            return [{"path": n, "type": "blob", "sha": W._git_blob_sha(b), "size": len(b)}
                    for n, b in self.dateien["tag" if commit == self.tag else "vorher" if commit == "8" * 40
                                             else "pakete"].items()]

        def gh(pfad, token, *a, **k):
            if "/commits?" in pfad:   # Verlauf von PAKETE.lock auf dem Zweig
                return [{"sha": "5" * 40}] + ([{"sha": "8" * 40}] if "vorher" in self.dateien else [])
            for gruppe in self.dateien.values():
                for b in gruppe.values():
                    if pfad.endswith("/git/blobs/" + W._git_blob_sha(b)):
                        return {"content": base64.encodebytes(b).decode(), "encoding": "base64"}
            raise AssertionError(pfad)
        with mock.patch.object(W, "_zweig_stand", return_value="5" * 40) as zweig, \
                mock.patch.object(W, "github_baum", side_effect=baum), mock.patch.object(W, "_gh", side_effect=gh), \
                mock.patch.object(W, "_tag_commit", side_effect=lambda r, t, n: self.tag if n == "v9.9.9" else None), \
                mock.patch.object(W, "github_hochladen_commit", hoch), mock.patch.object(W, "geheim_lesen", return_value="t"):
            erg = W.aktion(aktion, {"id": self.pr["id"], **p})
        self.assertEqual(zweig.call_args[0][1], "pakete")
        return erg, hoch

    def test_pruefen_und_signieren(self):
        d, hoch = self.lauf("pakete_pruefen")
        self.assertEqual((d["version"], d["summe"], d["bereits"]), ("9.9.9", SUMME, False))
        self.assertEqual(d["unterschiede"], ["beispiel 1.2.2 → 1.2.3"])
        hoch.assert_not_called()
        d, hoch = self.lauf("pakete_signieren", kennwort=KENNWORT, summe=SUMME)
        self.assertIn("signiert", d["meldung"])
        repo, zweig, _t, dateien, *_ = hoch.call_args[0]
        self.assertEqual((repo, zweig, list(dateien)), ("Besitzer/beispiel", "pakete", [W.PAKETE_SIGNATUR_DATEI]))
        self.assertTrue(W.pakete_signatur_gueltig(dateien[W.PAKETE_SIGNATUR_DATEI].encode(), self.pr["oeffentlich"],
                                                  SUMME, "9.9.9"))
        # liegt sie dort: bereits signiert, nichts hochgeladen
        self.dateien["pakete"][W.PAKETE_SIGNATUR_DATEI] = dateien[W.PAKETE_SIGNATUR_DATEI].encode()
        d, hoch = self.lauf("pakete_signieren", kennwort=KENNWORT, summe=SUMME)
        self.assertIn("bereits signiert", d["meldung"])
        hoch.assert_not_called()

    def test_cloudflared_im_ablauf(self):
        zeile = "# cloudflared: 2026.10.0 amd64=" + "a" * 64 + " arm64=" + "b" * 64 + " armhf=" + "c" * 64 + "\n"
        self.dateien["vorher"] = {W.PAKETE_DATEI: LOCK + zeile.replace("2026.10.0", "2026.9.1").encode()}
        self.dateien["pakete"][W.PAKETE_DATEI] = LOCK + zeile.encode()
        d, _ = self.lauf("pakete_pruefen")
        self.assertEqual(d["cloudflared"], "2026.10.0")
        self.assertIn("cloudflared 2026.9.1 → 2026.10.0", d["unterschiede"])
        self.dateien["pakete"][W.PAKETE_DATEI] = LOCK + b"# cloudflared: kaputt\n"
        self.assertRaisesRegex(ValueError, "cloudflared-Zeile", self.lauf, "pakete_pruefen")

    def test_abbrueche(self):
        # andere Liste als angezeigt
        self.assertRaisesRegex(ValueError, "seit der Anzeige", self.lauf, "pakete_signieren", kennwort=KENNWORT, summe="0" * 64)
        # Tag fehlt
        self.dateien["pakete"][W.PAKETE_DATEI] = LOCK.replace(b"9.9.9", b"9.9.8")
        self.assertRaisesRegex(ValueError, "Tag v9.9.8 gibt es nicht", self.lauf, "pakete_pruefen")
        # Tag ohne gültige Signatur
        self.dateien["pakete"][W.PAKETE_DATEI] = LOCK
        self.dateien["tag"][W.SIGNATUR_DATEI] = b"{}"
        self.assertRaisesRegex(ValueError, "keine gültige Signatur", self.lauf, "pakete_pruefen")
        # keine Liste
        del self.dateien["pakete"][W.PAKETE_DATEI]
        self.assertRaisesRegex(ValueError, "Keine Paketliste", self.lauf, "pakete_pruefen")

    def test_nur_speedrace(self):
        d = W.aktion("profil_speichern", {"name": "Andere", "regel": "alle", "repo": "Besitzer/x"})
        pr = d["profile"][-1]
        self.assertRaisesRegex(ValueError, "nur für Profile", W.pakete_stand, pr, "t")

    def test_seite(self):
        for teil in ('id="s-pakete-pruefen"', 'api("pakete_signieren"', "summe: paketeSumme"):
            self.assertIn(teil, W.SEITE)


if __name__ == "__main__":
    unittest.main()
