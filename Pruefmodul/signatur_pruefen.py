# -*- coding: utf-8 -*-
"""Prüfmodul zum Einbauen in eigene Software (Format "sr-signatur-1" des
Signier-Werkzeugs). Braucht nur das Paket "cryptography".

    from signatur_pruefen import pruefen
    pruefen("C:/Pfad/zur/neuen/Version", "<öffentlicher Schlüssel, 44 Zeichen>",
            ausschluss=["logs/*"])          # wirft SignaturFehler, wenn etwas nicht passt

Prüft die Ed25519-Signatur und die Prüfsumme JEDER Datei (Profil-Regel
„alle Dateien außer Ausnahmen“; .git, __pycache__, *.pyc und SIGNATUR.json
sind immer ausgenommen). Zusätzliche oder fehlende Dateien gelten als Fehler.
Wichtig: prüfen, BEVOR die neue Version installiert oder gestartet wird, und
den öffentlichen Schlüssel fest im Programm hinterlegen (nicht aus einer
Datei, die ein Angreifer ändern könnte).
"""
import base64
import fnmatch
import hashlib
import json
import os

FORMAT = "sr-signatur-1"
BINAER = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf")
STANDARD_AUSSCHLUSS = [".git/*", ".github/*", "*/__pycache__/*", "__pycache__/*", "*.pyc", "SIGNATUR.json"]


class SignaturFehler(Exception):
    pass


def _pruefsumme(pfad):
    with open(pfad, "rb") as f:
        daten = f.read()
    if not pfad.lower().endswith(BINAER) and b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def _dateiliste(wurzel, ausschluss):
    muster = STANDARD_AUSSCHLUSS + list(ausschluss or [])
    out = {}
    for root, dirs, files in os.walk(wurzel):
        for d in dirs:
            if os.path.islink(os.path.join(root, d)):
                raise SignaturFehler(f"Verknüpfung im Ordner: {d}")
        for f in files:
            voll = os.path.join(root, f)
            rel = os.path.relpath(voll, wurzel).replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, m) or fnmatch.fnmatch(f, m) for m in muster):
                continue
            if os.path.islink(voll):
                raise SignaturFehler(f"Verknüpfung im Ordner: {rel}")
            out[rel] = _pruefsumme(voll)
    return out


def pruefen(wurzel, oeffentlicher_schluessel, ausschluss=None):
    """-> Version laut Signatur; wirft SignaturFehler."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        with open(os.path.join(wurzel, "SIGNATUR.json"), encoding="utf-8") as f:
            sig = json.load(f)
        if sig.get("format") != FORMAT or not isinstance(sig.get("dateien"), dict):
            raise ValueError
    except (OSError, ValueError):
        raise SignaturFehler("SIGNATUR.json fehlt oder ist ungültig")
    version = str(sig.get("version") or "")
    nachricht = json.dumps({"format": FORMAT, "version": version, "dateien": sig["dateien"]},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(oeffentlicher_schluessel, validate=True)).verify(
            base64.b64decode(str(sig.get("signatur") or ""), validate=True), nachricht)
    except (InvalidSignature, ValueError, TypeError):
        raise SignaturFehler("Signatur ungültig")
    ist = _dateiliste(wurzel, ausschluss)
    abweichend = sorted(n for n in set(ist) | set(sig["dateien"]) if ist.get(n) != sig["dateien"].get(n))
    if abweichend:
        raise SignaturFehler("Dateien passen nicht zur Signatur: " + ", ".join(abweichend[:10]))
    return version
