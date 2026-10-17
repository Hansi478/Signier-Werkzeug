# -*- coding: utf-8 -*-
"""Prüfmodul zum Einbauen in eigene Software (Format "sr-signatur-1" des
Signier-Werkzeugs). Braucht nur das Paket "cryptography".

    from signatur_pruefen import pruefen
    pruefen("C:/Pfad/zur/neuen/Version", "<öffentlicher Schlüssel, 44 Zeichen>",
            ausschluss=["logs/*"])          # wirft SignaturFehler, wenn etwas nicht passt

Prüft die Ed25519-Signatur und die Prüfsumme JEDER Datei (Profil-Regel
„alle Dateien außer Ausnahmen“; .git, .github, __pycache__, *.pyc und
SIGNATUR.json sind immer ausgenommen). Es gilt dieselbe Regel wie beim
Signieren im Signier-Werkzeug (Test tests/test_sicherheit.py vergleicht beide):
- Ausnahmen sind fnmatch-Muster mit „/“ als Trenner; Groß-/Kleinschreibung
  zählt auf jedem Betriebssystem (fnmatchcase),
- zusätzliche, fehlende und veränderte Dateien sind Fehler,
- kompilierte Python-Dateien (__pycache__/, *.pyc) außerhalb ausgenommener
  Ordner sind ein Fehler: sie werden nicht geprüft, Python lädt sie aber -
  vor der Prüfung löschen,
- Verknüpfungen (Symlinks, Junctions), FIFOs, Sockets und Geräte sind Fehler -
  auch wenn sie unter eine Ausnahme fielen; ein ausgenommener Ordner („…/*“)
  wird gar nicht betreten,
- zwei Pfade, die unter Windows gleich wären (Groß-/Kleinschreibung,
  Unicode-Normalform), sind ein Fehler.
Wichtig: prüfen, BEVOR die neue Version installiert oder gestartet wird. Den
öffentlichen Schlüssel als Voreinstellung im Programm hinterlegen; ersetzen
darf ihn nur der Betreiber (Umgebungsvariable/Admin-Einstellung), nie eine
Datei, die mit einem Update kommt. Jede Ausnahme aus pruefen() ist ein
SignaturFehler und heißt: nicht installieren.
"""
import base64
import fnmatch
import hashlib
import json
import os
import stat
import unicodedata

FORMAT = "sr-signatur-1"
BINAER = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf")
STANDARD_AUSSCHLUSS = [".git/*", ".github/*", "*/__pycache__/*", "__pycache__/*", "*.pyc", "SIGNATUR.json"]
MAX_DATEI = 512 * 1024 * 1024
MAX_SIGNATUR = 4 * 1024 * 1024
_MAX_TIEFE = 64
_REPARSE_POINT = 0x400
_NAME_SURROGATE = 0x20000000   # IO_REPARSE_TAG_NAME_SURROGATE (Symlink, Junction …)


class SignaturFehler(Exception):
    pass


def _art(st):
    if stat.S_ISLNK(st.st_mode):
        return "verknuepfung"
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        # Windows: Symlinks und Junctions sind „Name-Surrogates“ (lstat öffnet sie
        # selbst und liefert ihr Tag). Andere Reparse-Points (OneDrive-Platzhalter,
        # Deduplizierung) löst Windows auf - Tag 0, normale Datei/normaler Ordner.
        # Ohne st_reparse_tag (sehr altes Python): vorsichtshalber Verknüpfung.
        tag = getattr(st, "st_reparse_tag", None)
        if tag is None or tag & _NAME_SURROGATE:
            return "verknuepfung"
    if stat.S_ISREG(st.st_mode):
        return "datei"
    if stat.S_ISDIR(st.st_mode):
        return "ordner"
    return "sonstiges"


def _lesen(pfad, limit):
    """Nur eine normale Datei, ohne Verknüpfungen zu folgen (lstat vorher,
    fstat am Deskriptor: dieselbe Datei)."""
    name = os.path.basename(pfad)
    vorher = os.lstat(pfad)
    if _art(vorher) != "datei":
        raise SignaturFehler(f"Keine normale Datei: {name}")
    fd = os.open(pfad, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (vorher.st_dev, vorher.st_ino):
            raise SignaturFehler(f"Datei während des Lesens ausgetauscht: {name}")
        teile, n = [], 0
        while True:
            b = os.read(fd, 1024 * 1024)
            if not b:
                return b"".join(teile)
            n += len(b)
            if n > limit:
                raise SignaturFehler(f"Datei zu groß: {name}")
            teile.append(b)
    finally:
        os.close(fd)


def _pruefsumme(pfad):
    daten = _lesen(pfad, MAX_DATEI)
    if not pfad.lower().endswith(BINAER) and b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def _eintrag_art(pfad, rel):
    try:
        art = _art(os.lstat(pfad))
    except OSError as e:
        raise SignaturFehler(f"Nicht lesbar: {rel} ({e.__class__.__name__})")
    if art == "verknuepfung":
        raise SignaturFehler(f"Verknüpfung im Ordner: {rel}")
    if art == "sonstiges":
        raise SignaturFehler(f"Kein normaler Dateityp: {rel}")
    return art


def _muster(ausschluss):
    return STANDARD_AUSSCHLUSS + [m.strip().replace("\\", "/") for m in (ausschluss or []) if m.strip()]


def _dateiliste(wurzel, ausschluss, kompilate=None):
    muster = _muster(ausschluss)
    eintraege = []
    sig = os.path.join(wurzel, "SIGNATUR.json")
    if os.path.lexists(sig) and _eintrag_art(sig, "SIGNATUR.json") != "datei":
        raise SignaturFehler("SIGNATUR.json ist keine normale Datei")

    def laufen(rel_basis, tiefe):
        if tiefe > _MAX_TIEFE:
            raise SignaturFehler(f"Ordner zu tief verschachtelt: {rel_basis}")
        ordner = os.path.join(wurzel, *rel_basis.split("/")) if rel_basis else wurzel
        for name in sorted(os.listdir(ordner)):
            rel = f"{rel_basis}/{name}" if rel_basis else name
            voll = os.path.join(ordner, name)
            ist_ordner = _eintrag_art(voll, rel) == "ordner"
            if kompilate is not None and (name == "__pycache__" if ist_ordner else name.endswith(".pyc")):
                kompilate.append(rel)
            if ist_ordner:
                if not any(m.endswith("*") and fnmatch.fnmatchcase(rel + "/", m) for m in muster):
                    laufen(rel, tiefe + 1)
            elif not any(fnmatch.fnmatchcase(rel, m) or fnmatch.fnmatchcase(name, m) for m in muster):
                eintraege.append((rel, voll))
    laufen("", 0)
    dateien, ordner = {}, set()
    for rel, _ in eintraege:
        if "\\" in rel or any(ord(c) < 32 or ord(c) == 127 for c in rel):
            raise SignaturFehler(f"Unzulässiger Dateiname: {rel!r}")
        k = unicodedata.normalize("NFC", rel).casefold()
        if k in dateien:
            raise SignaturFehler(f"Pfade kollidieren (unter Windows gleich): {dateien[k]} und {rel}")
        dateien[k] = rel
        teile = k.split("/")
        ordner.update("/".join(teile[:i]) for i in range(1, len(teile)))
    for k in ordner & set(dateien):
        raise SignaturFehler(f"Datei und Ordner kollidieren (unter Windows gleich): {dateien[k]}")
    return {rel: _pruefsumme(voll) for rel, voll in eintraege}


def pruefen(wurzel, oeffentlicher_schluessel, ausschluss=None):
    """-> Version laut Signatur; wirft SignaturFehler."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = json.loads(_lesen(os.path.join(wurzel, "SIGNATUR.json"), MAX_SIGNATUR).decode("utf-8"))
        if not isinstance(sig, dict) or sig.get("format") != FORMAT or not isinstance(sig.get("dateien"), dict):
            raise ValueError
    except (OSError, ValueError, UnicodeDecodeError, RecursionError, SignaturFehler):
        raise SignaturFehler("SIGNATUR.json fehlt oder ist ungültig")
    version = str(sig.get("version") or "")
    nachricht = json.dumps({"format": FORMAT, "version": version, "dateien": sig["dateien"]},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(oeffentlicher_schluessel, validate=True)).verify(
            base64.b64decode(str(sig.get("signatur") or ""), validate=True), nachricht)
    except (InvalidSignature, ValueError, TypeError):
        raise SignaturFehler("Signatur ungültig")
    kompilate = []
    try:
        ist = _dateiliste(wurzel, ausschluss, kompilate)
    except OSError as e:
        raise SignaturFehler(f"Bestand nicht lesbar ({e.__class__.__name__})")
    if kompilate:
        raise SignaturFehler("Kompilierte Python-Dateien gefunden (nicht geprüft, würden aber geladen): "
                             + ", ".join(kompilate[:10]) + " - vor der Prüfung löschen")
    # Namen in Unicode-Normalform NFC vergleichen (macOS liefert z. B. NFD)
    ist = {unicodedata.normalize("NFC", n): h for n, h in ist.items()}
    soll = {unicodedata.normalize("NFC", n): h for n, h in sig["dateien"].items()}
    abweichend = sorted(n for n in set(ist) | set(soll) if ist.get(n) != soll.get(n))
    if abweichend:
        raise SignaturFehler("Dateien passen nicht zur Signatur: " + ", ".join(
            f"{n} ({'fehlt' if n not in ist else 'zusätzlich' if n not in soll else 'verändert'})" for n in abweichend[:10]))
    return version
