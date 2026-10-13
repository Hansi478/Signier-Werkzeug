# -*- coding: utf-8 -*-
"""Signier-Werkzeug - Software-Versionen signieren und prüfen (Ed25519).

Bedienung über eine Seite im eigenen Browser (nur auf diesem Rechner
erreichbar, 127.0.0.1, mit Zufallsschlüssel in der Adresse). Mehrere
Profile (je Software ein Schlüssel), Signieren eines Ordners oder direkt
eines GitHub-Repositorys (laden, signieren, SIGNATUR.json hochladen).

Format "sr-signatur-1": SIGNATUR.json enthält die SHA-256-Prüfsumme jeder
Datei (Textdateien mit LF-Zeilenenden) und eine Ed25519-Signatur über
{"format","version","dateien"} (JSON, sortiert, ohne Leerzeichen).

Private Schlüssel liegen mit Kennwort verschlüsselt in
%APPDATA%\\Signier-Werkzeug\\schluessel. Das GitHub-Token: unter Windows mit
DPAPI verschlüsselt (nur für diesen Windows-Benutzer lesbar), sonst im
Schlüsselbund des Betriebssystems (Paket "keyring") oder - ohne sicheren
Speicher - nur für die laufende Sitzung im Arbeitsspeicher (siehe SICHERHEIT.md).
"""
import base64
import fnmatch
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath, PureWindowsPath

import qnap_begleiter as Q

PROGRAMM = "Signier-Werkzeug"
VERSION = "1.2.5"
FORMAT = "sr-signatur-1"
SIGNATUR_DATEI = "SIGNATUR.json"
BINAER = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf")
STANDARD_AUSSCHLUSS = [".git/*", ".github/*", "*/__pycache__/*", "__pycache__/*", "*.pyc", SIGNATUR_DATEI]
GITHUB_API = "https://api.github.com"
_ID_RE = re.compile(r"^[a-z0-9]{8,32}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_ZWEIG_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_TAG_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._-]{0,38}$")
# Eigene Updates: Releases dieses Repositorys, signiert mit dem Schlüssel des
# Herausgebers (fest eingebaut - ohne gültige Signatur kein Update)
WERKZEUG_REPO = "Hansi478/signier-werkzeug"
WERKZEUG_SCHLUESSEL = "7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc="
EXE_NAME = "Signier-Werkzeug.exe"
_VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")
_EXE_MIN, _EXE_MAX = 5 * 1024 * 1024, 150 * 1024 * 1024
MB = 1024 * 1024
MAX_DATEI_LESEN = 512 * MB          # größte Datei, die signiert/geprüft wird
MAX_SIGNATUR_BYTES = 4 * MB         # SIGNATUR.json (wie im Dashboard)
_MAX_TIEFE = 64                     # Ordnertiefe beim Durchlaufen eines Bestands


def daten_ordner():
    basis = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    pfad = os.path.join(basis, PROGRAMM)
    os.makedirs(os.path.join(pfad, "schluessel"), mode=0o700, exist_ok=True)
    if os.name != "nt":
        for p in (pfad, os.path.join(pfad, "schluessel")):
            try:
                os.chmod(p, 0o700)
            except OSError:
                pass
    return pfad


# ---------------------------------------------------------------------------
# Sichere Dateizugriffe: keinen Verknüpfungen folgen, nur normale Dateien,
# exklusiv angelegte Zufallsnamen, atomares Ersetzen
# ---------------------------------------------------------------------------
_O_BINAER = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_REPARSE_POINT = 0x400   # FILE_ATTRIBUTE_REPARSE_POINT (Windows: Symlinks, Junctions)


def _art(st):
    """Art eines Eintrags laut lstat: 'datei', 'ordner', 'verknuepfung' oder
    'sonstiges' (FIFO, Socket, Gerät …)."""
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return "verknuepfung"
    if stat.S_ISREG(st.st_mode):
        return "datei"
    if stat.S_ISDIR(st.st_mode):
        return "ordner"
    return "sonstiges"


def regulaer_lesen(pfad, limit=MAX_DATEI_LESEN):
    """Inhalt einer normalen Datei, ohne einer Verknüpfung zu folgen. Geprüft
    vor dem Öffnen (lstat) und am geöffneten Deskriptor (fstat, dieselbe
    Datei), damit ein Austausch dazwischen auffällt. O_NONBLOCK: eine
    untergeschobene FIFO blockiert das Öffnen nicht."""
    name = os.path.basename(pfad)
    try:
        vorher = os.lstat(pfad)
    except FileNotFoundError:
        raise
    except OSError as e:
        raise ValueError(f"{name} ist nicht lesbar ({e.__class__.__name__}).")
    if _art(vorher) != "datei":
        raise ValueError(f"{name} ist keine normale Datei (Verknüpfung oder Sondertyp) - abgelehnt.")
    try:
        fd = os.open(pfad, os.O_RDONLY | _O_BINAER | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC)
    except OSError as e:
        raise ValueError(f"{name} ist nicht lesbar ({e.__class__.__name__}).")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (vorher.st_dev, vorher.st_ino):
            raise ValueError(f"{name} wurde während des Lesens ausgetauscht - abgelehnt.")
        if st.st_size > limit:
            raise ValueError(f"{name} ist zu groß.")
        teile, n = [], 0
        while True:
            b = os.read(fd, MB)
            if not b:
                return b"".join(teile)
            n += len(b)
            if n > limit:
                raise ValueError(f"{name} ist zu groß.")
            teile.append(b)
    finally:
        os.close(fd)


def _alles_schreiben(fd, daten):
    ansicht = memoryview(daten)
    while ansicht:
        ansicht = ansicht[os.write(fd, ansicht):]


def _ziel_pruefen(lstat_fn, name):
    """Am Ziel darf nichts liegen oder nur eine normale Datei (kein Symlink,
    keine Junction, kein Ordner). Nicht os.path.exists(): das folgt Verknüpfungen."""
    try:
        st = lstat_fn()
    except FileNotFoundError:
        return
    if _art(st) != "datei":
        raise ValueError(f"{name} ist keine normale Datei (z. B. eine Verknüpfung) - es wird nichts geschrieben.")


def neu_anlegen(pfad, daten, modus=0o600):
    """Neue Datei exklusiv anlegen (O_EXCL: scheitert, wenn dort schon etwas
    liegt - auch eine Verknüpfung, der dann nicht gefolgt wird)."""
    fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINAER | _O_CLOEXEC, modus)
    try:
        if os.name != "nt":
            os.fchmod(fd, modus)
        _alles_schreiben(fd, daten)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.remove(pfad)
        except OSError:
            pass
        raise
    os.close(fd)


def _tmp_name(name):
    return f".{name}.{secrets.token_hex(8)}.tmp"   # nicht vorhersehbar


def atomar_schreiben(ordner, name, daten, modus=0o644, pruefen=None):
    """`daten` als ordner/name schreiben: erst vollständig in eine neue,
    zufällig benannte Datei im selben Ordner (exklusiv, folgt keiner
    Verknüpfung), gegenlesen und mit `pruefen(daten)` validieren, dann
    atomar ersetzen. os.replace ersetzt nur den Verzeichniseintrag - nie das
    Ziel einer Verknüpfung oder den Inhalt eines Hardlinks. Bei jedem Fehler
    bleibt der alte Stand und keine Teildatei zurück."""
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError("Ungültiger Dateiname.")
    if pruefen:
        pruefen(daten)
    if os.name == "nt":
        return _atomar_windows(ordner, name, daten, modus, pruefen)
    return _atomar_posix(ordner, name, daten, modus, pruefen)


def _atomar_posix(ordner, name, daten, modus, pruefen):
    # Alle Schritte relativ zum geöffneten Ordner (dir_fd): ein Austausch des
    # Ordnerpfads zwischendurch lenkt das Schreiben nicht um.
    dfd = os.open(ordner, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_CLOEXEC)
    tmp = None
    try:
        _ziel_pruefen(lambda: os.lstat(name, dir_fd=dfd), name)
        tmp = _tmp_name(name)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _O_CLOEXEC, modus, dir_fd=dfd)
        try:
            os.fchmod(fd, modus)
            _alles_schreiben(fd, daten)
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW | _O_CLOEXEC, dir_fd=dfd)
        try:
            gelesen = b"".join(iter(lambda: os.read(fd, MB), b""))
        finally:
            os.close(fd)
        if gelesen != daten:
            raise ValueError(f"{name} konnte nicht korrekt geschrieben werden.")
        if pruefen:
            pruefen(gelesen)
        _ziel_pruefen(lambda: os.lstat(name, dir_fd=dfd), name)
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        os.fsync(dfd)
    finally:
        if tmp:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        os.close(dfd)


def _atomar_windows(ordner, name, daten, modus, pruefen):
    # Windows: kein dir_fd. O_CREAT|O_EXCL entspricht CREATE_NEW (scheitert an
    # allem Vorhandenen, folgt keiner Verknüpfung); MoveFileEx ersetzt nur den Eintrag.
    ziel = os.path.join(ordner, name)
    _ziel_pruefen(lambda: os.lstat(ziel), name)
    tmp = os.path.join(ordner, _tmp_name(name))
    try:
        neu_anlegen(tmp, daten, modus)
        if regulaer_lesen(tmp, len(daten) + 1) != daten:
            raise ValueError(f"{name} konnte nicht korrekt geschrieben werden.")
        _ziel_pruefen(lambda: os.lstat(ziel), name)
        os.replace(tmp, ziel)
        tmp = None
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Signierter Bestand: EINE Regel für Signieren und Prüfen
# ---------------------------------------------------------------------------
# - Regel "speedrace": nur die Einträge, die ein Update des Dashboards übernimmt
#   (UPDATE_ALLOWED_FILES/UPDATE_ALLOWED_DIRS aus dessen app.py); in diesen Ordnern
#   sind __pycache__/ und *.pyc ausgenommen (genau wie im Dashboard).
# - Regel "alle": alle Dateien außer STANDARD_AUSSCHLUSS und den Ausnahmen des
#   Profils. Ein ausgenommener Ordner (Muster wie ".git/*") wird nicht betreten.
# - SIGNATUR.json gehört nie zum Bestand, muss aber eine normale Datei sein.
# - Jeder Eintrag, der dabei gesehen wird, wird per lstat geprüft: Verknüpfungen
#   (Symlinks, Junctions), FIFOs, Sockets und Geräte sind ein FEHLER - auch wenn
#   sie unter eine Ausnahme fielen. Nichts wird stillschweigend übersprungen.
# - Pfade: "/" als Trenner; "\" und Steuerzeichen sind verboten; zwei Pfade, die
#   unter Windows dieselbe Datei wären (Groß-/Kleinschreibung, Unicode-Normalform),
#   sind ein Fehler.
# Prüfsumme (unverändert, kompatibel mit dem Dashboard): SHA-256, Textdateien
# mit LF-Zeilenenden. Pruefmodul/signatur_pruefen.py setzt dieselbe Regel um
# (Test tests/test_sicherheit.py vergleicht beide).
def pruefsumme(pfad):
    daten = regulaer_lesen(pfad)
    if not pfad.lower().endswith(BINAER) and b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def _speedrace_erlaubt(wurzel):
    """Erlaubte Update-Einträge aus der app.py des Ordners (Speedrace-Dashboard)."""
    try:
        quelle = regulaer_lesen(os.path.join(wurzel, "app.py"), 64 * MB).decode("utf-8")
        dateien = re.findall(r'"([^"]+)"', re.search(r"UPDATE_ALLOWED_FILES = \(([^)]*)\)", quelle).group(1))
        ordner = re.findall(r'"([^"]+)"', re.search(r"UPDATE_ALLOWED_DIRS = \(([^)]*)\)", quelle).group(1))
    except (OSError, AttributeError, UnicodeDecodeError):
        raise ValueError("Keine app.py des Speedrace-Dashboards in diesem Ordner gefunden.")
    return dateien, ordner


def _pfad_schluessel(rel):
    """Vergleichsform eines Pfads, wie Windows ihn sieht."""
    return unicodedata.normalize("NFC", rel).casefold()


def _eintrag_art(pfad, rel):
    try:
        art = _art(os.lstat(pfad))
    except OSError as e:
        raise ValueError(f"Nicht lesbar: {rel} ({e.__class__.__name__}).")
    if art == "verknuepfung":
        raise ValueError(f"Verknüpfung (Symlink/Junction) im Bestand: {rel} - nicht erlaubt.")
    if art == "sonstiges":
        raise ValueError(f"Kein normaler Dateityp (FIFO, Socket, Gerät): {rel} - nicht erlaubt.")
    return art


def _durchlaufen(wurzel, rel_basis, ausgenommen, out, tiefe=0):
    if tiefe > _MAX_TIEFE:
        raise ValueError(f"Ordner zu tief verschachtelt: {rel_basis}")
    ordner = os.path.join(wurzel, *rel_basis.split("/")) if rel_basis else wurzel
    try:
        namen = sorted(os.listdir(ordner))
    except OSError as e:
        raise ValueError(f"Ordner nicht lesbar: {rel_basis or '.'} ({e.__class__.__name__}).")
    for name in namen:
        rel = f"{rel_basis}/{name}" if rel_basis else name
        voll = os.path.join(ordner, name)
        art = _eintrag_art(voll, rel)
        if art == "ordner":
            if not ausgenommen(rel, name, True):
                _durchlaufen(wurzel, rel, ausgenommen, out, tiefe + 1)
        elif not ausgenommen(rel, name, False):
            out.append((rel, voll))


def _eindeutig(eintraege):
    """Doppelte bzw. unter Windows kollidierende Pfade -> ValueError."""
    dateien, ordner = {}, set()
    for rel, _ in eintraege:
        if "\\" in rel or any(ord(c) < 32 or ord(c) == 127 for c in rel):
            raise ValueError(f"Unzulässiger Dateiname im Bestand: {rel!r}")
        k = _pfad_schluessel(rel)
        if k in dateien:
            raise ValueError(f"Pfade kollidieren (unter Windows gleich): {dateien[k]} und {rel}")
        dateien[k] = rel
        teile = k.split("/")
        ordner.update("/".join(teile[:i]) for i in range(1, len(teile)))
    for k in ordner & set(dateien):
        raise ValueError(f"Datei und Ordner kollidieren (unter Windows gleich): {dateien[k]}")


def dateiliste(wurzel, regel="alle", ausschluss=None):
    """{relativer Pfad (mit /): Prüfsumme} des signierten Bestands - die
    zentrale Regel für Signieren und Prüfen (siehe oben). ValueError bei
    Verknüpfungen, Sondertypen, Kollisionen."""
    eintraege = []
    sig = os.path.join(wurzel, SIGNATUR_DATEI)
    if os.path.lexists(sig) and _eintrag_art(sig, SIGNATUR_DATEI) != "datei":
        raise ValueError(f"{SIGNATUR_DATEI} ist keine normale Datei - abgelehnt.")
    if regel == "speedrace":
        dateien, ordner = _speedrace_erlaubt(wurzel)

        def py_cache(rel, name, ist_ordner):
            return name == "__pycache__" if ist_ordner else name.endswith(".pyc")
        for name in sorted(os.listdir(wurzel)):
            if name == SIGNATUR_DATEI:
                continue
            voll = os.path.join(wurzel, name)
            art = _eintrag_art(voll, name)
            if name in dateien:
                if art != "datei":
                    raise ValueError(f"{name} ist keine normale Datei - nicht erlaubt.")
                eintraege.append((name, voll))
            elif name in ordner:
                if art != "ordner":
                    raise ValueError(f"{name} ist kein Ordner - nicht erlaubt.")
                _durchlaufen(wurzel, name, py_cache, eintraege, 1)
    else:
        muster = STANDARD_AUSSCHLUSS + [m.strip() for m in (ausschluss or []) if m.strip()]

        def ausgenommen(rel, name, ist_ordner):
            if ist_ordner:   # nur Muster, die alles darunter treffen ("…/*")
                return any(m.endswith("*") and fnmatch.fnmatch(rel + "/", m) for m in muster)
            return any(fnmatch.fnmatch(rel, m) or fnmatch.fnmatch(name, m) for m in muster)
        _durchlaufen(wurzel, "", ausgenommen, eintraege)
    _eindeutig(eintraege)
    return {rel: pruefsumme(voll) for rel, voll in eintraege}


def nachricht(version, dateien):
    return json.dumps({"format": FORMAT, "version": version, "dateien": dateien},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ordner_version(wurzel):
    try:
        return regulaer_lesen(os.path.join(wurzel, "VERSION"), 4096).decode("utf-8").strip()[:40]
    except (OSError, ValueError, UnicodeDecodeError):
        return ""


def _privat_aus_pem(pem, kennwort):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        privat = serialization.load_pem_private_key(pem, kennwort.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("Kennwort falsch oder Schlüsseldatei beschädigt.")
    if not isinstance(privat, Ed25519PrivateKey):
        raise ValueError("Das ist kein Ed25519-Schlüssel.")
    return privat


def privat_laden(pfad, kennwort):
    try:
        pem = regulaer_lesen(pfad, 64 * 1024)
    except OSError:
        raise ValueError("Schlüsseldatei nicht gefunden.")
    return _privat_aus_pem(pem, kennwort)


def oeffentlich_text(privat):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(privat.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)).decode("ascii")


def _signatur_json_pruefen(daten):
    sig = json.loads(daten.decode("utf-8"))
    if not isinstance(sig, dict) or sig.get("format") != FORMAT or not isinstance(sig.get("dateien"), dict):
        raise ValueError("SIGNATUR.json hat ein ungültiges Format.")
    return sig


def signieren(wurzel, profil, kennwort, version=None):
    privat = privat_laden(schluessel_pfad(profil), kennwort)
    if oeffentlich_text(privat) != profil.get("oeffentlich"):
        raise ValueError("Der Schlüssel passt nicht zum öffentlichen Schlüssel des Profils.")
    version = (version if version is not None else ordner_version(wurzel))[:40]
    dateien = dateiliste(wurzel, profil.get("regel", "alle"), profil.get("ausschluss"))
    if not dateien:
        raise ValueError("Keine Dateien zum Signieren gefunden.")
    signatur = privat.sign(nachricht(version, dateien))
    inhalt = json.dumps({"format": FORMAT, "version": version, "dateien": dateien,
                         "signatur": base64.b64encode(signatur).decode("ascii")}, indent=1, sort_keys=True) + "\n"
    atomar_schreiben(wurzel, SIGNATUR_DATEI, inhalt.encode("utf-8"), 0o644, _signatur_json_pruefen)
    return version, len(dateien), inhalt


def pruefen(wurzel, oeffentlich, regel="alle", ausschluss=None):
    """-> {"ok", "version", "anzahl", "abweichend", "arten", "fehler"}"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = _signatur_json_pruefen(regulaer_lesen(os.path.join(wurzel, SIGNATUR_DATEI), MAX_SIGNATUR_BYTES))
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in sig["dateien"].items()):
            raise ValueError
    except FileNotFoundError:
        return {"ok": False, "fehler": "Keine SIGNATUR.json in diesem Ordner."}
    except (OSError, ValueError, UnicodeDecodeError) as e:
        text = str(e) if "keine normale Datei" in str(e) else "Keine gültige SIGNATUR.json in diesem Ordner."
        return {"ok": False, "fehler": text}
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(oeffentlich, validate=True)).verify(
            base64.b64decode(sig.get("signatur") or "", validate=True), nachricht(str(sig.get("version") or ""), sig["dateien"]))
    except (InvalidSignature, ValueError, TypeError):
        return {"ok": False, "version": sig.get("version"), "fehler": "Signatur ungültig (anderer Schlüssel oder verändert)."}
    try:
        ist = dateiliste(wurzel, regel, ausschluss)
    except ValueError as e:
        return {"ok": False, "version": sig.get("version"), "fehler": str(e)}
    soll = sig["dateien"]
    arten = {n: ("fehlt" if n not in ist else "zusätzlich" if n not in soll else "verändert")
             for n in set(ist) | set(soll) if ist.get(n) != soll.get(n)}
    abweichend = sorted(arten)
    return {"ok": not abweichend, "version": sig.get("version"), "anzahl": len(ist), "abweichend": abweichend[:50],
            "arten": {n: arten[n] for n in abweichend[:50]},
            "fehler": "Diese Dateien passen nicht zur Signatur." if abweichend else ""}


# ---------------------------------------------------------------------------
# Profile und Geheimnisse
# ---------------------------------------------------------------------------
_lock = threading.RLock()


def _profile_datei():
    return os.path.join(daten_ordner(), "profile.json")


def profile_laden():
    try:
        daten = regulaer_lesen(_profile_datei(), 16 * MB)
    except FileNotFoundError:
        return {}
    try:
        d = json.loads(daten.decode("utf-8"))
        return d if isinstance(d, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def profile_speichern(d):
    daten = json.dumps(d, indent=1, ensure_ascii=False).encode("utf-8")
    atomar_schreiben(daten_ordner(), "profile.json", daten, 0o600, lambda b: json.loads(b.decode("utf-8")))


def schluessel_pfad(profil):
    if not _ID_RE.match(str(profil.get("id") or "")):
        raise ValueError("Ungültiges Profil.")
    return os.path.join(daten_ordner(), "schluessel", profil["id"] + ".pem")


def _dpapi(daten, schuetzen):
    """Windows-DPAPI (nur dieser Windows-Benutzer kann es lesen)."""
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    puffer = ctypes.create_string_buffer(daten, len(daten))
    ein, aus = BLOB(len(daten), puffer), BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if schuetzen else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(ein), None, None, None, None, 0x1, ctypes.byref(aus)):
        raise OSError("DPAPI fehlgeschlagen")
    try:
        return ctypes.string_at(aus.pbData, aus.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(aus.pbData)


# GitHub-Token - wo es liegt:
#   Windows:          "dpapi:…" in profile.json, mit DPAPI verschlüsselt (dauerhaft)
#   macOS/Linux:      im Schlüsselbund des Betriebssystems über das Paket "keyring",
#                     in profile.json nur der Vermerk "keyring:" (dauerhaft)
#   ohne beides:      nur im Arbeitsspeicher dieser Sitzung (nicht dauerhaft)
#   Altbestand "klar:…" (Base64, also KLARTEXT) wird erkannt, nie mehr geschrieben
#   und auf Wunsch in einen der sicheren Speicher übernommen (Aktion token_migrieren).
_KEYRING_DIENST, _KEYRING_NAME = PROGRAMM, "github_token"
_sitzung = {"token": ""}
_geheim_bekannt = set()     # zum Schwärzen in Fehlermeldungen


def _merken(t):
    if t and len(t) >= 8:
        _geheim_bekannt.add(t)
    return t


def _keyring():
    """Sicherer Schlüsselbund des Betriebssystems oder None (kein Klartext-Backend)."""
    if os.name == "nt":
        return None
    try:
        import keyring
        kr = keyring.get_keyring()
    except Exception:
        return None
    art = f"{type(kr).__module__}.{type(kr).__name__}".lower()
    if getattr(kr, "priority", 0) <= 0 or any(w in art for w in ("fail", "null", "plaintext", "keyrings.alt")):
        return None
    return kr


def token_speicher_art():
    return "dpapi" if os.name == "nt" else ("schluesselbund" if _keyring() else "sitzung")


def geheim_speichern(text):
    """-> Wert für profile.json (bei "sitzung": "", das Token bleibt nur im Speicher)."""
    _merken(text)
    if os.name == "nt":
        return "dpapi:" + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")
    kr = _keyring()
    if kr:
        kr.set_password(_KEYRING_DIENST, _KEYRING_NAME, text)
        return "keyring:"
    _sitzung["token"] = text
    return ""


def geheim_entfernen():
    _sitzung["token"] = ""
    kr = _keyring()
    if kr:
        try:
            kr.delete_password(_KEYRING_DIENST, _KEYRING_NAME)
        except Exception:
            pass


def geheim_lesen(wert):
    wert = str(wert or "")
    if wert.startswith("dpapi:") and os.name == "nt":
        return _merken(_dpapi(base64.b64decode(wert[6:]), False).decode("utf-8"))
    if wert == "keyring:":
        kr = _keyring()
        try:
            return _merken((kr.get_password(_KEYRING_DIENST, _KEYRING_NAME) or "") if kr else "")
        except Exception:
            return ""
    if wert.startswith("klar:"):   # Altbestand (unsicher) - bis zur Übernahme weiter nutzbar
        try:
            return _merken(base64.b64decode(wert[5:]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return ""
    return _sitzung["token"]


_TOKEN_MUSTER = re.compile(r"(github_pat_[A-Za-z0-9_]{10,}|gh[pousr]_[A-Za-z0-9]{10,}|Bearer\s+\S+)")


def schwaerzen(text):
    """Tokens aus Texten entfernen, bevor sie angezeigt werden."""
    text = _TOKEN_MUSTER.sub("***", str(text))
    for t in list(_geheim_bekannt):
        text = text.replace(t, "***")
    return text


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
# Das Token geht NUR an die API-Hosts. Weiterleitungen werden nicht automatisch
# verfolgt, sondern einzeln geprüft: nur https, nur bekannte GitHub-Hosts, höchstens
# fünf, keine Schleifen; bei jedem Wechsel des Hosts fällt das Token weg (auch für
# alle weiteren Sprünge). Downloads laufen so ohne Token weiter.
_API_HOSTS = frozenset({"api.github.com", "uploads.github.com"})
_DOWNLOAD_HOSTS = frozenset({"github.com", "codeload.github.com", "objects.githubusercontent.com",
                             "github-releases.githubusercontent.com", "release-assets.githubusercontent.com"})
_SCHEMATA = ("https",)
_MAX_WEITERLEITUNGEN = 5
_JSON_MAX = 64 * MB


class HttpFehler(ValueError):
    def __init__(self, code):
        super().__init__(f"GitHub-Fehler {code}.")
        self.code = code


class _KeineAutoWeiterleitung(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None   # 3xx kommt als HTTPError zurück und wird in _anfrage geprüft


def _oeffner():
    return urllib.request.build_opener(_KeineAutoWeiterleitung)


def _adresse_pruefen(url, vorher=None):
    """-> (Host, Port) einer erlaubten Adresse, sonst ValueError."""
    t = urllib.parse.urlsplit(url)
    host = (t.hostname or "").lower()
    if t.scheme not in _SCHEMATA or not host or t.username or t.password:
        raise ValueError("Unzulässige Adresse (nur https zu GitHub).")
    if vorher and urllib.parse.urlsplit(vorher).scheme == "https" and t.scheme != "https":
        raise ValueError("Weiterleitung von https auf http abgelehnt.")
    if host not in _API_HOSTS | _DOWNLOAD_HOSTS:
        raise ValueError(f"Verbindung zu einem nicht vorgesehenen Server ({host}) abgelehnt.")
    return host, t.port


def _lesen(r, limit, ziel):
    laenge = r.headers.get("Content-Length")
    if laenge and laenge.isdigit() and int(laenge) > limit:
        raise ValueError("Antwort von GitHub zu groß - abgebrochen.")
    teile, n = [], 0
    while True:
        b = r.read(MB)
        if not b:
            break
        n += len(b)
        if n > limit:
            raise ValueError("Antwort von GitHub zu groß - abgebrochen.")
        if ziel is not None:
            ziel.write(b)
        else:
            teile.append(b)
    return n if ziel is not None else b"".join(teile)


def _anfrage(url, token=None, methode="GET", daten=None, kopf=None, timeout=60, limit=_JSON_MAX, ziel=None):
    """HTTP-Anfrage mit geprüften Weiterleitungen -> Bytes (bzw. Anzahl, wenn
    `ziel` ein Dateiobjekt ist). Fehler: HttpFehler(code) bzw. ValueError,
    beide ohne Header oder Token."""
    host, port = _adresse_pruefen(url)
    token_ziel = (host, port) if token and host in _API_HOSTS else None
    besucht, vorher = set(), None
    for _ in range(_MAX_WEITERLEITUNGEN + 1):
        host, port = _adresse_pruefen(url, vorher)
        if url in besucht:
            raise ValueError("Weiterleitungsschleife - abgebrochen.")
        besucht.add(url)
        h = {"User-Agent": PROGRAMM, **(kopf or {})}
        if token_ziel and (host, port) == token_ziel:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(url, data=daten, method=methode, headers=h)
        try:
            with _oeffner().open(req, timeout=timeout) as r:
                return _lesen(r, limit, ziel)
        except urllib.error.HTTPError as e:
            ort = e.headers.get("Location") if e.headers else None
            code = e.code
            e.close()
            if code not in (301, 302, 303, 307, 308) or not ort:
                raise HttpFehler(code) from None
            if methode not in ("GET", "HEAD"):
                raise ValueError("Unerwartete Weiterleitung bei einer schreibenden GitHub-Anfrage - abgebrochen.") from None
            vorher, url = url, urllib.parse.urljoin(url, ort)
            if token_ziel and _adresse_pruefen(url, vorher) != token_ziel:
                token_ziel = None   # anderer Host: das Token ist für diese Kette erledigt
        except (urllib.error.URLError, OSError) as e:
            raise ValueError(f"GitHub nicht erreichbar ({e.__class__.__name__}).") from None
    raise ValueError("Zu viele Weiterleitungen - abgebrochen.")


_API_FEHLER = {401: "GitHub-Token ungültig oder abgelaufen.", 403: "Keine Berechtigung (Token braucht „Contents: Read and write“).",
               404: "Repository oder Zweig nicht gefunden (bei privatem Repository: Token nötig).",
               409: "GitHub meldet einen Konflikt - bitte erneut versuchen.",
               422: "GitHub hat die Anfrage abgelehnt."}


def _gh(pfad, token, methode="GET", daten=None, roh=False, timeout=60, limit=_JSON_MAX, ziel=None):
    kopf = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if daten is not None else {})}
    try:
        inhalt = _anfrage(GITHUB_API + pfad, token, methode, json.dumps(daten).encode("utf-8") if daten is not None else None,
                          kopf, timeout, limit, ziel)
    except HttpFehler as e:
        raise ValueError(_API_FEHLER.get(e.code, f"GitHub-Fehler {e.code}.")) from None
    if roh or ziel is not None:
        return inhalt
    return json.loads(inhalt.decode("utf-8") or "{}")


def _zweig_stand(repo, zweig, token):
    d = _gh(f"/repos/{repo}/branches/{urllib.parse.quote(zweig, safe='')}", token)
    return d["commit"]["sha"]


# Grenzen für den Import eines GitHub-Archivs (zipball). Großzügig für ein
# normales Repository (Speedrace-Dashboard: rund 160 Dateien, 50 MB, größte
# Datei 20 MB), aber ZIP-Bomben und unangemessen große Archive werden schon vor
# dem Entpacken (laut Verzeichnis) und währenddessen (gezählte Bytes) abgelehnt.
# Anpassbar hier oder je Aufruf über den Parameter `grenzen`.
ZIP_GRENZEN = {
    "archiv_bytes": 300 * MB,     # komprimiertes Archiv (Download)
    "eintraege": 20000,           # Einträge im Archiv
    "datei_bytes": 200 * MB,      # eine entpackte Datei
    "gesamt_bytes": 1024 * MB,    # alle entpackten Dateien zusammen
    "verhaeltnis": 200,           # entpackt : komprimiert je Eintrag (ab 1 MB entpackt)
    "pfad_zeichen": 240,          # Länge des relativen Pfads
    "tiefe": 32,                  # Ordnerebenen
    "je_ordner": 5000,            # Einträge in einem Ordner
}
_WIN_RESERVIERT = re.compile(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9¹²³]|LPT[0-9¹²³])(\.[^.]*)?$", re.I)
_WIN_VERBOTEN = frozenset('<>:"|?*\\')


def zip_pfad_teile(rel, grenzen=None):
    """Bestandteile eines relativen ZIP-Pfads; ValueError, wenn er unter POSIX
    ODER Windows absolut, laufwerksbezogen (C:, C:..), UNC (\\\\server),
    mit Backslash, ".."/"." oder sonst für Windows unzulässig wäre."""
    g = {**ZIP_GRENZEN, **(grenzen or {})}
    fehler = ValueError(f"Unzulässiger Pfad im Archiv: {rel[:80]!r} - nichts wird übernommen.")
    if not rel or "\x00" in rel or "\\" in rel:
        raise fehler
    w = PureWindowsPath(rel)
    if PurePosixPath(rel).is_absolute() or w.drive or w.root or w.anchor:
        raise fehler
    teile = rel.split("/")
    for t in teile:
        if t in ("", ".", "..") or t[-1] in " ." or _WIN_RESERVIERT.match(t) \
                or any(ord(c) < 32 or ord(c) == 127 or c in _WIN_VERBOTEN for c in t):
            raise fehler
    if len(rel) > g["pfad_zeichen"] or len(teile) > g["tiefe"]:
        raise ValueError(f"Pfad im Archiv zu lang oder zu tief: {rel[:80]!r} - nichts wird übernommen.")
    return teile


def _enthalten(basis, pfad):
    """Endgültiger Schreibpfad (aufgelöst) muss unterhalb von basis liegen."""
    r = Path(pfad).resolve()
    if r == basis or not r.is_relative_to(basis):
        raise ValueError("Pfad im Archiv führt aus dem Zielordner heraus - nichts wird übernommen.")
    return r


def _ordner_anlegen(basis, teile):
    akt = str(basis)
    for t in teile:
        akt = os.path.join(akt, t)
        try:
            os.mkdir(akt, 0o700)
        except FileExistsError:
            pass
        if _art(os.lstat(akt)) != "ordner":
            raise ValueError("Unerwarteter Eintrag beim Entpacken - nichts wird übernommen.")
        _enthalten(basis, akt)
    return akt


def _zip_plan(z, g):
    """Alle Einträge VOR dem Entpacken prüfen -> (Ordner, [(info, teile)])."""
    infos = z.infolist()
    if len(infos) > g["eintraege"]:
        raise ValueError("Das Archiv hat zu viele Einträge - abgelehnt.")
    praefix, arten, eltern, je_ordner, gesamt = None, {}, set(), {}, 0
    ordner, dateien = [], []
    for info in infos:
        name = info.filename
        if "\\" in info.orig_filename:
            raise ValueError("Backslash in einem Pfad des Archivs - abgelehnt.")
        if info.flag_bits & 0x1:
            raise ValueError("Verschlüsselte Einträge im Archiv - abgelehnt.")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ValueError("Unzulässige Kompression im Archiv - abgelehnt.")
        ist_ordner = name.endswith("/")
        typ = stat.S_IFMT(info.external_attr >> 16)
        if typ not in (0, stat.S_IFREG, stat.S_IFDIR) or (typ and (typ == stat.S_IFDIR) != ist_ordner):
            raise ValueError(f"Verknüpfung oder Sondertyp im Archiv: {name[:80]!r} - abgelehnt.")
        if (info.external_attr & 0x10) and not ist_ordner:
            raise ValueError(f"Widersprüchlicher Eintrag im Archiv: {name[:80]!r} - abgelehnt.")
        kopf, trenner, rest = name.partition("/")
        if praefix is None:
            zip_pfad_teile(kopf, g)
            praefix = kopf
        if kopf != praefix or not trenner:
            raise ValueError("Unerwarteter Aufbau des Archivs (ein gemeinsamer Hauptordner fehlt) - abgelehnt.")
        rel = rest[:-1] if ist_ordner else rest
        if not rel:
            if ist_ordner:
                continue
            raise ValueError("Unerwarteter Aufbau des Archivs - abgelehnt.")
        teile = zip_pfad_teile(rel, g)
        k = _pfad_schluessel(rel)
        if k in arten:
            raise ValueError(f"Doppelter bzw. unter Windows gleicher Pfad im Archiv: {rel[:80]!r} - abgelehnt.")
        for i in range(1, len(teile)):
            pk = _pfad_schluessel("/".join(teile[:i]))
            if arten.get(pk) == "datei":
                raise ValueError(f"Datei und Ordner kollidieren im Archiv: {rel[:80]!r} - abgelehnt.")
            eltern.add(pk)
        if not ist_ordner and k in eltern:
            raise ValueError(f"Datei und Ordner kollidieren im Archiv: {rel[:80]!r} - abgelehnt.")
        arten[k] = "ordner" if ist_ordner else "datei"
        ek = _pfad_schluessel("/".join(teile[:-1]))
        je_ordner[ek] = je_ordner.get(ek, 0) + 1
        if je_ordner[ek] > g["je_ordner"]:
            raise ValueError("Zu viele Einträge in einem Ordner des Archivs - abgelehnt.")
        if ist_ordner:
            ordner.append(teile)
            continue
        if info.file_size > g["datei_bytes"]:
            raise ValueError(f"Datei im Archiv zu groß: {rel[:80]!r} - abgelehnt.")
        gesamt += info.file_size
        if gesamt > g["gesamt_bytes"]:
            raise ValueError("Das Archiv ist entpackt zu groß - abgelehnt.")
        if info.file_size > MB and info.file_size > g["verhaeltnis"] * max(info.compress_size, 1):
            raise ValueError(f"Verdächtig hohe Kompression (ZIP-Bombe?): {rel[:80]!r} - abgelehnt.")
        dateien.append((info, teile))
    return ordner, dateien


def zip_entpacken(quelle, ziel, grenzen=None):
    """GitHub-Archiv (Dateiobjekt) in den leeren Ordner `ziel` entpacken.
    Erst wird das ganze Verzeichnis geprüft, dann entpackt; jede Abweichung
    bricht vollständig ab (ValueError) - der Aufrufer verwirft `ziel` dann."""
    g = {**ZIP_GRENZEN, **(grenzen or {})}
    basis = Path(ziel).resolve()
    if os.listdir(basis):
        raise ValueError("Zielordner zum Entpacken ist nicht leer.")
    try:
        with zipfile.ZipFile(quelle) as z:
            ordner, dateien = _zip_plan(z, g)
            for teile in ordner:
                _ordner_anlegen(basis, teile)
            geschrieben = 0
            for info, teile in dateien:
                pfad = os.path.join(_ordner_anlegen(basis, teile[:-1]), teile[-1])
                _enthalten(basis, pfad)
                fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINAER | _O_CLOEXEC, 0o600)
                with os.fdopen(fd, "wb") as dst, z.open(info) as src:
                    n = 0
                    while True:
                        b = src.read(MB)
                        if not b:
                            break
                        n += len(b)
                        geschrieben += len(b)
                        if n > info.file_size or n > g["datei_bytes"] or geschrieben > g["gesamt_bytes"]:
                            raise ValueError("Das Archiv enthält mehr Daten als angegeben - abgelehnt.")
                        dst.write(b)
                if n != info.file_size:
                    raise ValueError("Das Archiv ist unvollständig - abgelehnt.")
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError) as e:
        raise ValueError(f"Das Archiv von GitHub ist beschädigt oder unzulässig ({e.__class__.__name__}) - "
                         "nichts wird übernommen.") from None
    return len(dateien)


def github_laden(repo, zweig, token, ziel, grenzen=None):
    """Stand des Zweigs als Ordner -> (Ordner, Commit). Der Ordner wird neu in
    `ziel` angelegt; bei jedem Fehler wird er vollständig entfernt."""
    if not _REPO_RE.match(repo or "") or not _ZWEIG_RE.match(zweig or ""):
        raise ValueError("Repository bitte als „Besitzer/Name“ angeben, Zweig z. B. „main“.")
    g = {**ZIP_GRENZEN, **(grenzen or {})}
    stand = _zweig_stand(repo, zweig, token)
    if not re.fullmatch(r"[0-9a-f]{40}", stand or ""):
        raise ValueError("Unerwartete Antwort von GitHub (Commit).")
    ordner = tempfile.mkdtemp(prefix="stand-", dir=ziel)
    try:
        with tempfile.TemporaryFile() as archiv:   # ohne Namen im Dateisystem
            _gh(f"/repos/{repo}/zipball/{stand}", token, timeout=300, limit=g["archiv_bytes"], ziel=archiv)
            archiv.seek(0)
            zip_entpacken(archiv, ordner, g)
    except BaseException:
        shutil.rmtree(ordner, ignore_errors=True)
        raise
    return ordner, stand


def github_hochladen(repo, zweig, token, inhalt, version, stand):
    """SIGNATUR.json hochladen -> voller Commit, der sie enthält. Ist sie auf
    GitHub schon genau so vorhanden, gibt es keinen neuen Commit."""
    if _zweig_stand(repo, zweig, token) != stand:
        raise ValueError("Auf GitHub hat sich zwischendurch etwas geändert - bitte noch einmal signieren.")
    pfad = f"/repos/{repo}/contents/{SIGNATUR_DATEI}"
    alt = None
    try:
        alt = _gh(pfad + f"?ref={urllib.parse.quote(zweig, safe='')}", token)
    except ValueError:
        pass
    if alt and alt.get("content"):
        try:
            if base64.b64decode(alt["content"]).decode("utf-8") == inhalt:
                return stand   # unverändert (z. B. noch einmal signiert)
        except (ValueError, UnicodeDecodeError):
            pass
    daten = {"message": f"SIGNATUR.json für Version {version or '?'}", "branch": zweig,
             "content": base64.b64encode(inhalt.encode("utf-8")).decode("ascii")}
    if alt and alt.get("sha"):
        daten["sha"] = alt["sha"]
    d = _gh(pfad, token, "PUT", daten)
    return (d.get("commit") or {}).get("sha", "")


def _tag_commit(repo, token, name):
    """Commit, auf den der Tag zeigt (auch bei annotierten Tags), oder None."""
    try:
        ref = _gh(f"/repos/{repo}/git/ref/tags/{urllib.parse.quote(name, safe='')}", token)
    except ValueError:
        return None
    obj = (ref or {}).get("object") or {} if isinstance(ref, dict) else {}
    for _ in range(5):
        if obj.get("type") != "tag":
            return obj.get("sha")
        obj = (_gh(f"/repos/{repo}/git/tags/{obj.get('sha')}", token) or {}).get("object") or {}
    return None


def github_tag_frei(repo, token, version, stand):
    """Vor dem Hochladen: ein vorhandener Tag v<Version> darf nur schon genau
    auf diesen Stand zeigen - veröffentlichte Versionen werden nie verschoben."""
    if not _TAG_VERSION_RE.match(version or ""):
        return
    vorhanden = _tag_commit(repo, token, f"v{version}")
    if vorhanden and vorhanden != stand:
        raise ValueError(f"Den Tag v{version} gibt es schon (auf {vorhanden[:7]}). Eine veröffentlichte Version wird "
                         "nicht verändert - bitte VERSION erhöhen und neu signieren.")


def github_tag_setzen(repo, token, version, commit):
    """Tag v<Version> auf den signierten Stand setzen -> Tag-Name oder "".
    Programme, die Versionen über Tags finden (z. B. das Update aus GitHub im
    Speedrace Dashboard), laden so den Stand mit der passenden SIGNATUR.json.
    Ein vorhandener Tag auf einem anderen Stand wird NICHT verschoben."""
    if not _TAG_VERSION_RE.match(version or "") or not re.match(r"^[0-9a-f]{40}$", commit or ""):
        return ""
    name = f"v{version}"
    vorhanden = _tag_commit(repo, token, name)
    if vorhanden == commit:
        return name
    if vorhanden:
        raise ValueError(f"Tag {name} zeigt schon auf einen anderen Stand ({vorhanden[:7]}) und wird nicht verschoben.")
    _gh(f"/repos/{repo}/git/refs", token, "POST", {"ref": f"refs/tags/{name}", "sha": commit})
    return name


# ---------------------------------------------------------------------------
# Eigene Versionen: Release signieren und veröffentlichen, Update einspielen
# ---------------------------------------------------------------------------
def _version_tupel(v):
    m = _VERSION_RE.match(str(v or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def _herunterladen(url, token=None, limit=_EXE_MAX, accept="application/octet-stream"):
    """Download über _anfrage: das Token geht nur an die GitHub-API, nie an
    den Download-Server, auf den GitHub weiterleitet."""
    try:
        return _anfrage(url, token, kopf={"Accept": accept}, timeout=300, limit=limit)
    except HttpFehler as e:
        raise ValueError(f"Download fehlgeschlagen (GitHub-Fehler {e.code}).") from None


def _exe_plausibel(daten):
    if not (_EXE_MIN <= len(daten) <= _EXE_MAX) or daten[:2] != b"MZ":
        raise ValueError("Die geladene Datei ist kein plausibles Windows-Programm.")


def werkzeug_signatur_inhalt(privat, version, exe):
    dateien = {EXE_NAME: hashlib.sha256(exe).hexdigest()}   # Programmdatei: Bytes unverändert
    signatur = privat.sign(nachricht(version, dateien))
    return json.dumps({"format": FORMAT, "version": version, "dateien": dateien,
                       "signatur": base64.b64encode(signatur).decode("ascii")}, indent=1, sort_keys=True) + "\n"


def werkzeug_signatur_pruefen(sig_daten, exe, version, oeffentlich=None):
    """Wirft ValueError, wenn exe + SIGNATUR.json nicht genau zur Version passen."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = json.loads(sig_daten.decode("utf-8"))
        if not isinstance(sig, dict) or sig.get("format") != FORMAT:
            raise ValueError
    except (ValueError, UnicodeDecodeError):
        raise ValueError("SIGNATUR.json des Updates ist ungültig.")
    dateien = {EXE_NAME: hashlib.sha256(exe).hexdigest()}
    if sig.get("version") != version or sig.get("dateien") != dateien:
        raise ValueError("Das Update passt nicht zu seiner Signatur (Version oder Prüfsumme) - es wird nicht eingespielt.")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(oeffentlich or WERKZEUG_SCHLUESSEL, validate=True)).verify(
            base64.b64decode(sig.get("signatur") or "", validate=True), nachricht(version, dateien))
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("Die Signatur des Updates ist ungültig - es wird nicht eingespielt.")


def _asset(release, name):
    return next((a for a in release.get("assets") or [] if a.get("name") == name), None)


def werkzeug_entwurf(token):
    """Neuester Entwurf (vom Bau auf GitHub angelegt, noch nicht signiert)."""
    releases = _gh(f"/repos/{WERKZEUG_REPO}/releases?per_page=30", token)
    entwuerfe = [r for r in releases if isinstance(r, dict) and r.get("draft") and _asset(r, EXE_NAME)
                 and _version_tupel(str(r.get("tag_name") or "").lstrip("v"))]
    if not entwuerfe:
        raise ValueError(f"Kein Entwurf zum Signieren gefunden. Erst den Tag (z. B. v{VERSION}) im Repository "
                         f"{WERKZEUG_REPO} setzen und warten, bis der Bau unter „Actions“ fertig ist.")
    return max(entwuerfe, key=lambda r: _version_tupel(r["tag_name"].lstrip("v")))


def werkzeug_bau_starten(token):
    """Tag v<VERSION> auf den neuesten Stand von main setzen -> (Version, Commit).
    Die Version kommt aus signier_werkzeug.py auf main; GitHub baut daraufhin
    den Entwurf. Ein vorhandener Tag wird nie verschoben."""
    stand = _zweig_stand(WERKZEUG_REPO, "main", token)
    datei = _gh(f"/repos/{WERKZEUG_REPO}/contents/signier_werkzeug.py?ref={stand}", token)
    quelltext = base64.b64decode(datei.get("content") or "").decode("utf-8", "replace")
    m = re.search(r'^VERSION = "(.+)"', quelltext, re.M)
    version = m.group(1) if m else ""
    if not _version_tupel(version):
        raise ValueError("In signier_werkzeug.py auf main steht keine gültige VERSION.")
    name = f"v{version}"
    if _tag_commit(WERKZEUG_REPO, token, name):
        raise ValueError(f"Den Tag {name} gibt es schon. Erst VERSION in signier_werkzeug.py erhöhen und committen.")
    _gh(f"/repos/{WERKZEUG_REPO}/git/refs", token, "POST", {"ref": f"refs/tags/{name}", "sha": stand})
    return version, stand


def _gh_hochladen(release_id, name, daten, token):
    url = (f"https://uploads.github.com/repos/{WERKZEUG_REPO}/releases/{int(release_id)}/assets"
           f"?name={urllib.parse.quote(name)}")
    kopf = {"Accept": "application/vnd.github+json", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"}
    try:
        _anfrage(url, token, "POST", daten, kopf, timeout=120, limit=MB)
    except HttpFehler as e:
        raise ValueError(f"SIGNATUR.json konnte nicht hochgeladen werden (GitHub-Fehler {e.code}).") from None


def entwurf_herkunft(rel, token, exe):
    """Herkunft des Entwurfs prüfen, bevor er signiert wird -> Commit.
    - Prüfsumme der geladenen exe = die vom Bau in den Release-Text geschriebene
      (und = der von GitHub ermittelte Digest der Datei, falls angegeben),
    - der Tag zeigt genau auf den Commit, aus dem gebaut wurde,
    - dieser Commit liegt auf main (kein Bau aus einem fremden Zweig)."""
    text = str(rel.get("body") or "")
    m_commit = re.search(r"Commit ([0-9a-f]{40})", text)
    m_summe = re.search(r"SHA-256 der exe: ([0-9a-f]{64})", text)
    if not m_commit or not m_summe:
        raise ValueError("Der Entwurf stammt nicht erkennbar aus dem Bau (Commit oder Prüfsumme fehlen) - nicht signiert.")
    summe = hashlib.sha256(exe).hexdigest()
    digest = str((_asset(rel, EXE_NAME) or {}).get("digest") or "")
    if summe != m_summe.group(1) or (digest and digest != "sha256:" + summe):
        raise ValueError("Die exe im Entwurf passt nicht zur Prüfsumme aus dem Bau - nicht signiert.")
    commit = m_commit.group(1)
    if _tag_commit(WERKZEUG_REPO, token, str(rel.get("tag_name") or "")) != commit:
        raise ValueError("Der Tag des Entwurfs zeigt nicht auf den gebauten Commit - nicht signiert.")
    vergleich = _gh(f"/repos/{WERKZEUG_REPO}/compare/{commit}...main", token)
    if vergleich.get("status") not in ("ahead", "identical"):
        raise ValueError("Der gebaute Commit liegt nicht auf main - nicht signiert.")
    return commit


def veroeffentlicht_text(version, commit, summe, lauf=""):
    """Release-Text nach dem Signieren (ersetzt „Ungeprüfter Entwurf …“).
    Behält „Commit <sha>“ und „SHA-256 der exe: <summe>“ bei, damit die
    Herkunft weiterhin maschinell prüfbar bleibt."""
    fp = hashlib.sha256(base64.b64decode(WERKZEUG_SCHLUESSEL)).hexdigest().upper()
    zeilen = [f"Signier-Werkzeug {version} - signiert und veröffentlicht am "
              f"{time.strftime('%d.%m.%Y %H:%M UTC', time.gmtime())} mit dem Schlüssel des Herausgebers.", "",
              f"Gebaut aus Commit {commit}.", "", f"SHA-256 der exe: {summe}", "",
              f"Signatur: {SIGNATUR_DATEI} (Format {FORMAT}, Ed25519)", "",
              f"Öffentlicher Schlüssel: {WERKZEUG_SCHLUESSEL}",
              "Fingerabdruck: " + " ".join(fp[i:i + 4] for i in range(0, 64, 4)), ""]
    if lauf:
        zeilen += [f"Gebaut von: {lauf}", ""]
    zeilen += ["Prüfen: SHA-256 der exe vergleichen, Fingerabdruck über einen zweiten Weg beim Herausgeber bestätigen, "
               "Herkunft mit „gh attestation verify Signier-Werkzeug.exe --repo " + WERKZEUG_REPO + "“."]
    return "\n".join(zeilen) + "\n"


def werkzeug_veroeffentlichen(profil, kennwort, token):
    """Entwurf laden, Herkunft prüfen, signieren, SIGNATUR.json anhängen, veröffentlichen."""
    privat = privat_laden(schluessel_pfad(profil), kennwort)
    if oeffentlich_text(privat) != WERKZEUG_SCHLUESSEL:
        raise ValueError("Dieser Schlüssel passt nicht zum eingebauten Schlüssel des Werkzeugs.")
    rel = werkzeug_entwurf(token)
    version = rel["tag_name"].lstrip("v")
    exe = _herunterladen(_asset(rel, EXE_NAME)["url"], token)
    _exe_plausibel(exe)
    commit = entwurf_herkunft(rel, token, exe)
    inhalt = werkzeug_signatur_inhalt(privat, version, exe)
    werkzeug_signatur_pruefen(inhalt.encode("utf-8"), exe, version)
    alt = _asset(rel, SIGNATUR_DATEI)
    if alt:
        _gh(f"/repos/{WERKZEUG_REPO}/releases/assets/{int(alt['id'])}", token, "DELETE", roh=True)
    _gh_hochladen(rel["id"], SIGNATUR_DATEI, inhalt.encode("utf-8"), token)
    summe = hashlib.sha256(exe).hexdigest()
    m_lauf = re.search(r"Gebaut von: (https://github\.com/[\w./-]+/actions/runs/\d+)", str(rel.get("body") or ""))
    _gh(f"/repos/{WERKZEUG_REPO}/releases/{int(rel['id'])}", token, "PATCH",
        {"draft": False, "make_latest": "true", "body": veroeffentlicht_text(version, commit, summe, m_lauf.group(1) if m_lauf else "")})
    return version, summe, commit


def werkzeug_bau_status(token=None):
    """Stand des letzten Laufs „Bauen“ (Tag-Push) -> {"tag", "zustand", "schritt", "url", "entwurf"}.
    zustand: "wartet", "laeuft", "fertig", "fehlgeschlagen" oder "keiner". Nur lesende Abfragen;
    das Repository ist öffentlich, daher zuerst ohne Token (ein Token ohne „Actions: Read“ würde abgewiesen)."""
    def lesen(pfad):
        try:
            return _gh(pfad, None, timeout=20)
        except ValueError:
            if not token:
                raise
            return _gh(pfad, token, timeout=20)
    laeufe = (lesen(f"/repos/{WERKZEUG_REPO}/actions/workflows/bauen.yml/runs?event=push&per_page=5") or {}).get("workflow_runs") or []
    lauf = next((r for r in laeufe if _version_tupel(str(r.get("head_branch") or "").lstrip("v"))), None)
    if not lauf:
        return {"zustand": "keiner", "tag": "", "schritt": "", "url": "", "entwurf": False}
    url = str(lauf.get("html_url") or "")
    if not re.fullmatch(rf"https://github\.com/{re.escape(WERKZEUG_REPO)}/actions/runs/\d+", url, re.I):
        url = ""
    status, ergebnis, schritt = lauf.get("status"), lauf.get("conclusion"), ""
    if status != "completed":
        zustand = "wartet" if status in ("queued", "waiting", "requested", "pending") else "laeuft"
        try:
            jobs = (lesen(f"/repos/{WERKZEUG_REPO}/actions/runs/{int(lauf['id'])}/jobs") or {}).get("jobs") or []
            for job in jobs:
                aktiv = next((st for st in job.get("steps") or [] if st.get("status") == "in_progress"), None)
                if aktiv:
                    schritt = f"{job.get('name')}: {aktiv.get('name')}"[:120]
                    break
        except (ValueError, KeyError, TypeError):
            pass
    else:
        zustand = "fertig" if ergebnis == "success" else "fehlgeschlagen"
    entwurf = False
    if zustand == "fertig" and token:
        try:
            entwurf = werkzeug_entwurf(token).get("tag_name") == lauf.get("head_branch")
        except ValueError:
            entwurf = False
    return {"zustand": zustand, "tag": str(lauf.get("head_branch") or "")[:40], "schritt": schritt, "url": url,
            "entwurf": entwurf}


def werkzeug_neueste():
    """Neueste veröffentlichte Version -> (Version, Release) oder (None, None)."""
    try:
        rel = _gh(f"/repos/{WERKZEUG_REPO}/releases/latest", None, timeout=20)
    except ValueError as e:
        if "nicht gefunden" in str(e):
            return None, None
        raise
    version = str(rel.get("tag_name") or "").lstrip("v")
    return (version, rel) if _version_tupel(version) else (None, None)


def _laufende_exe():
    if not getattr(sys, "frozen", False) or os.name != "nt":
        raise ValueError("Updates werden nur in der Signier-Werkzeug.exe eingespielt (nicht im Quelltext).")
    return sys.executable


def werkzeug_update():
    """Neuere signierte Version laden, prüfen und die laufende exe ersetzen
    -> Version. Bei jedem Fehler bleibt die bisherige exe unverändert."""
    exe_pfad = _laufende_exe()
    version, rel = werkzeug_neueste()
    if not version or _version_tupel(version) <= _version_tupel(VERSION):
        raise ValueError("Es gibt keine neuere Version.")
    a_exe, a_sig = _asset(rel, EXE_NAME), _asset(rel, SIGNATUR_DATEI)
    if not a_exe or not a_sig:
        raise ValueError("Das Release ist unvollständig (Programm oder Signatur fehlt).")
    exe = _herunterladen(a_exe["browser_download_url"])
    sig = _herunterladen(a_sig["browser_download_url"], limit=256 * 1024)
    _exe_plausibel(exe)
    werkzeug_signatur_pruefen(sig, exe, version)
    ordner, name = os.path.split(exe_pfad)
    neu, alt = os.path.join(ordner, _tmp_name(name)), exe_pfad + ".alt"
    try:
        neu_anlegen(neu, exe, 0o755)   # exklusiv, zufälliger Name: kein untergeschobenes Ziel
        if regulaer_lesen(neu, _EXE_MAX + 1) != exe:
            raise OSError("geschriebene Datei weicht ab")
        if os.path.lexists(alt):
            if _art(os.lstat(alt)) == "ordner":
                raise OSError(f"{os.path.basename(alt)} ist ein Ordner")
            os.remove(alt)   # entfernt nur den Eintrag (auch eine Verknüpfung selbst)
        os.replace(exe_pfad, alt)   # laufende exe darf umbenannt, aber nicht überschrieben werden
        try:
            os.replace(neu, exe_pfad)
        except OSError:
            os.replace(alt, exe_pfad)
            raise
    except (OSError, ValueError) as e:
        try:
            os.remove(neu)
        except OSError:
            pass
        raise ValueError(f"Das Programm konnte nicht ersetzt werden ({e.__class__.__name__}) - die bisherige Version bleibt.")
    return version


def _alte_exe_entfernen():
    """Nach einem Update: die umbenannte alte exe löschen, sobald sie frei ist."""
    if not getattr(sys, "frozen", False):
        return
    alt = sys.executable + ".alt"
    for _ in range(30):
        if not os.path.lexists(alt):
            return
        try:
            os.remove(alt)
            return
        except OSError:
            time.sleep(2)


# ---------------------------------------------------------------------------
# Windows-Dialoge
# ---------------------------------------------------------------------------
def _powershell(skript):
    if os.name != "nt":
        raise ValueError("Auswahlfenster nur unter Windows - bitte den Pfad eintippen.")
    r = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", skript], capture_output=True, text=True,
                       timeout=600, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return (r.stdout or "").strip()


def ordner_waehlen():
    return _powershell("Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                       "$d.Description = 'Ordner der Version wählen'; if ($d.ShowDialog() -eq 'OK') { $d.SelectedPath }")


def datei_waehlen():
    return _powershell("Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; "
                       "$d.Filter = 'Schlüssel (*.pem)|*.pem|Alle Dateien|*.*'; if ($d.ShowDialog() -eq 'OK') { $d.FileName }")


def ordner_oeffnen(pfad):
    if os.name == "nt" and os.path.isdir(pfad):
        os.startfile(pfad)


# ---------------------------------------------------------------------------
# Aktionen der Oberfläche
# ---------------------------------------------------------------------------
def _profil(d, pid):
    p = next((p for p in d.get("profile") or [] if p.get("id") == pid), None)
    if not p:
        raise ValueError("Profil nicht gefunden.")
    return p


def _ansicht(d):
    profile = []
    for p in d.get("profile") or []:
        try:
            hat = os.path.isfile(schluessel_pfad(p))
        except ValueError:
            hat = False
        profile.append({**{k: p.get(k) for k in ("id", "name", "oeffentlich", "regel", "ausschluss", "repo", "zweig")},
                        "hat_schluessel": hat})
    alt = os.path.join(os.path.expanduser("~"), "speedrace-signatur-privat.pem")
    wert = str(d.get("github_token") or "")
    gespeichert = ("dpapi" if wert.startswith("dpapi:") else "schluesselbund" if wert == "keyring:"
                   else "klartext" if wert.startswith("klar:") else "sitzung" if _sitzung["token"] else "")
    return {"profile": profile, "token": bool(gespeichert), "token_speicher": gespeichert,
            "token_methode": token_speicher_art(), "version": VERSION,
            "daten": daten_ordner(), "alter_schluessel": alt if os.path.isfile(alt) else ""}


def _token_meldung(d):
    art = _ansicht(d)["token_speicher"]
    return {"dpapi": "Token gespeichert (mit Windows-DPAPI verschlüsselt, nur für deinen Windows-Benutzer lesbar).",
            "schluesselbund": "Token im Schlüsselbund des Betriebssystems gespeichert.",
            "sitzung": "Kein sicherer Speicher verfügbar: Das Token gilt nur für diese Sitzung (Arbeitsspeicher) "
                       "und wird nicht dauerhaft gespeichert - nach einem Neustart erneut eingeben."}.get(art, "Token gespeichert.")


# ---------------------------------------------------------------------------
# QNAP-Begleiter (Reiter „QNAP“): Zustand in qnap.json, eigene Logik in
# qnap_begleiter.py. Greift nicht auf Schlüssel oder profile.json zu (außer
# lesend: Repository, öffentlicher Schlüssel und Token für den Download).
# ---------------------------------------------------------------------------
def _qnap_laden():
    try:
        daten = regulaer_lesen(os.path.join(daten_ordner(), "qnap.json"), MB)
    except FileNotFoundError:
        return {}
    try:
        d = json.loads(daten.decode("utf-8"))
        return d if isinstance(d, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _qnap_speichern(d):
    atomar_schreiben(daten_ordner(), "qnap.json", json.dumps(d, indent=1, ensure_ascii=False).encode("utf-8"), 0o600,
                     lambda b: json.loads(b.decode("utf-8")))


def _qnap():
    return Q.Begleiter(_qnap_laden, _qnap_speichern, daten_ordner())


def github_versionen(repo, token):
    """Tags v<x.y.z> eines Repositorys, neueste zuerst."""
    if not _REPO_RE.match(repo or ""):
        raise ValueError("Ungültiges Repository.")
    d = _gh(f"/repos/{repo}/tags?per_page=100", token)
    namen = {str(t.get("name") or "") for t in d if isinstance(t, dict)} if isinstance(d, list) else set()
    return sorted((n for n in namen if Q._TAG_RE.match(n)), key=lambda n: tuple(int(x) for x in n[1:].split(".")),
                  reverse=True)[:30]


def _zip_gueltig(daten):
    with zipfile.ZipFile(io.BytesIO(daten)) as z:
        if z.testzip() is not None:
            raise ValueError("Die gebaute ZIP ist beschädigt.")


def qnap_paket(pr, token, tag, name, ziel):
    """Signierte Version (Tag) laden, prüfen und als saubere ZIP mit genau
    einem Ordner `name` in `ziel` ablegen -> Angaben für die Anzeige.
    ValueError, wenn Signatur, Dateien oder Version nicht passen."""
    repo = pr.get("repo") or ""
    if not _REPO_RE.match(repo) or not Q._TAG_RE.match(tag or "") or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name or ""):
        raise ValueError("Ungültige Angaben für den Download.")
    commit = _tag_commit(repo, token, tag)
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        raise ValueError(f"Den Tag {tag} gibt es in {repo} nicht.")
    os.makedirs(ziel, mode=0o700, exist_ok=True)
    version = tag[1:]
    with tempfile.TemporaryDirectory(prefix="qnap-", dir=ziel) as tmp:
        ordner = os.path.join(tmp, "stand")
        os.mkdir(ordner, 0o700)
        with tempfile.TemporaryFile() as archiv:
            _gh(f"/repos/{repo}/zipball/{commit}", token, timeout=300, limit=ZIP_GRENZEN["archiv_bytes"], ziel=archiv)
            archiv.seek(0)
            zip_entpacken(archiv, ordner)
            archiv.seek(0)
            with zipfile.ZipFile(archiv) as z:   # ausführbare Dateien (z. B. Startskript) behalten ihr Recht
                ausfuehrbar = {i.filename.partition("/")[2] for i in z.infolist()
                               if not i.filename.endswith("/") and (i.external_attr >> 16) & 0o111}
        r = pruefen(ordner, pr.get("oeffentlich") or "", pr.get("regel", "alle"), pr.get("ausschluss"))
        if not r.get("ok"):
            liste = ", ".join(r.get("abweichend") or [])[:300]
            raise ValueError(f"{tag}: {r.get('fehler') or 'Signatur nicht gültig.'}{' (' + liste + ')' if liste else ''} "
                             "Nicht installieren.")
        if str(r.get("version") or "") != version or ordner_version(ordner) != version:
            raise ValueError(f"{tag}: Version in SIGNATUR.json bzw. VERSION passt nicht zum Tag - nicht installieren.")
        signiert = set(json.loads(regulaer_lesen(os.path.join(ordner, SIGNATUR_DATEI), MAX_SIGNATUR_BYTES))["dateien"])
        eintraege = []
        _durchlaufen(ordner, "", lambda rel, n, ist_ordner: False, eintraege)
        dateien = sorted(rel for rel, _ in eintraege)
        zeit = time.localtime()[:6]
        puffer = io.BytesIO()
        with zipfile.ZipFile(puffer, "w", zipfile.ZIP_DEFLATED) as zo:
            ordner_namen = sorted({"/".join(r_.split("/")[:i]) for r_ in dateien for i in range(1, r_.count("/") + 1)})
            for rel in [""] + ordner_namen:
                info = zipfile.ZipInfo(name + "/" + (rel + "/" if rel else ""), date_time=zeit)
                info.external_attr = (0o40755 << 16) | 0x10
                zo.writestr(info, b"")
            for rel in dateien:
                info = zipfile.ZipInfo(name + "/" + rel, date_time=zeit)
                info.external_attr = (0o100755 if rel in ausfuehrbar else 0o100644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zo.writestr(info, regulaer_lesen(os.path.join(ordner, *rel.split("/"))))
        daten = puffer.getvalue()
    atomar_schreiben(ziel, name + ".zip", daten, 0o600, _zip_gueltig)
    unsigniert = [rel for rel in dateien if rel not in signiert and rel != SIGNATUR_DATEI]
    return {"tag": tag, "version": version, "commit": commit, "zip": os.path.join(ziel, name + ".zip"),
            "sha256": hashlib.sha256(daten).hexdigest(), "dateien": len(dateien), "signiert": len(signiert),
            "unsigniert": unsigniert[:200], "unsigniert_anzahl": len(unsigniert)}


def qnap_aktion(name, p):
    with _lock:
        d = profile_laden()
        quellen = {x["id"]: x for x in d.get("profile") or [] if x.get("repo") and x.get("oeffentlich") and x.get("id")}
        token = geheim_lesen(d.get("github_token"))
    b = _qnap()
    liste = [{"id": k, "name": v.get("name"), "repo": v.get("repo")} for k, v in quellen.items()]

    def quelle(pr):
        q = quellen.get((pr or {}).get("quelle"))
        if not q:
            raise ValueError("Im QNAP-Profil ist kein gültiges Signier-Profil (mit Repository und Schlüssel) gewählt.")
        return q
    if name == "qnap_zustand":
        antwort = b.ansicht(p.get("ablauf"))
    elif name == "qnap_profil_speichern":
        antwort = b.profil_speichern(p, quellen)
    elif name == "qnap_beginnen":
        antwort = b.beginnen(str(p.get("ablauf") or ""))
    elif name == "qnap_abbrechen":
        antwort = b.abbrechen()
    elif name == "qnap_alt_vergessen":
        antwort = b.alt_vergessen()
    elif name == "qnap_vorbereiten":
        return b.vorbereiten(str(p.get("schritt") or ""))
    elif name == "qnap_ausfuehren":
        antwort = b.ausfuehren(str(p.get("schritt") or ""), p.get("marke"), p,
                               lambda pr, tag, n: qnap_paket(quelle(pr), token, tag, n, os.path.join(daten_ordner(), "qnap")))
    elif name == "qnap_rueckmelden":
        antwort = b.rueckmelden(str(p.get("schritt") or ""), str(p.get("ergebnis") or ""), p)
    elif name == "qnap_versionen":
        return {"versionen": github_versionen(quelle(b.ansicht()["profil"])["repo"], token)}
    elif name == "qnap_http":
        pr = b.ansicht()["profil"] or {}
        return Q.http_pruefen(pr.get("adresse"))
    else:
        raise ValueError("Unbekannte Aktion.")
    return {**antwort, "quellen": liste}


def aktion(name, p):
    if name.startswith("qnap_"):
        return qnap_aktion(name, p)
    with _lock:
        d = profile_laden()
        if name == "zustand":
            return _ansicht(d)
        if name == "profil_speichern":
            regel = p.get("regel") if p.get("regel") in ("alle", "speedrace") else "alle"
            repo, zweig = str(p.get("repo") or "").strip(), str(p.get("zweig") or "main").strip() or "main"
            if repo and not _REPO_RE.match(repo):
                raise ValueError("Repository bitte als „Besitzer/Name“ angeben.")
            if not _ZWEIG_RE.match(zweig):
                raise ValueError("Ungültiger Zweig.")
            name_ = str(p.get("name") or "").strip()[:60]
            if not name_:
                raise ValueError("Bitte einen Namen für das Profil angeben.")
            werte = {"name": name_, "regel": regel, "repo": repo, "zweig": zweig,
                     "ausschluss": [m.strip() for m in str(p.get("ausschluss") or "").splitlines() if m.strip()][:50]}
            if p.get("id"):
                _profil(d, p["id"]).update(werte)
            else:
                d.setdefault("profile", []).append({"id": secrets.token_hex(8), "oeffentlich": "", **werte})
            profile_speichern(d)
            return _ansicht(d)
        if name == "profil_loeschen":
            pr = _profil(d, p.get("id"))
            if os.path.isfile(schluessel_pfad(pr)):
                ziel = schluessel_pfad(pr) + f".geloescht-{time.strftime('%Y%m%d-%H%M%S')}"
                os.replace(schluessel_pfad(pr), ziel)   # nicht endgültig löschen
            d["profile"] = [x for x in d["profile"] if x is not pr]
            profile_speichern(d)
            return _ansicht(d)
        if name == "schluessel_neu":
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            pr = _profil(d, p.get("id"))
            kw = str(p.get("kennwort") or "")
            if len(kw) < 12:
                raise ValueError("Das Kennwort braucht mindestens 12 Zeichen.")
            if os.path.lexists(schluessel_pfad(pr)):
                raise ValueError("Das Profil hat schon einen Schlüssel - für einen neuen bitte ein neues Profil anlegen.")
            privat = Ed25519PrivateKey.generate()
            pem = privat.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(kw.encode("utf-8")))
            neu_anlegen(schluessel_pfad(pr), pem, 0o600)
            pr["oeffentlich"] = oeffentlich_text(privat)
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Schlüssel erzeugt. Bitte die Schlüsseldatei zusätzlich sichern (USB-Stick)."}
        if name == "schluessel_import":
            pr = _profil(d, p.get("id"))
            quelle = str(p.get("pfad") or "").strip().strip('"')
            try:
                pem = regulaer_lesen(quelle, 64 * 1024)
            except OSError:
                raise ValueError("Datei nicht gefunden.")
            privat = _privat_aus_pem(pem, str(p.get("kennwort") or ""))
            if os.path.lexists(schluessel_pfad(pr)):
                raise ValueError("Das Profil hat schon einen Schlüssel.")
            neu_anlegen(schluessel_pfad(pr), pem, 0o600)   # exklusiv, folgt keiner Verknüpfung
            pr["oeffentlich"] = oeffentlich_text(privat)
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Schlüssel übernommen. Die ursprüngliche Datei bleibt, wo sie ist."}
        if name == "token_speichern":
            t = str(p.get("token") or "").strip()
            if t and not re.fullmatch(r"[A-Za-z0-9_]{20,255}", t):
                raise ValueError("Das sieht nicht wie ein GitHub-Token aus.")
            if not t:
                geheim_entfernen()
            d["github_token"] = geheim_speichern(t) if t else ""
            profile_speichern(d)
            return {**_ansicht(d), "meldung": _token_meldung(d) if t else "Token entfernt."}
        if name == "token_migrieren":
            wert = str(d.get("github_token") or "")
            if not wert.startswith("klar:"):
                raise ValueError("Es ist kein unsicher gespeichertes Token vorhanden.")
            t = geheim_lesen(wert)
            if not t:
                raise ValueError("Das alte Token ist nicht lesbar - bitte entfernen und neu eingeben.")
            d["github_token"] = geheim_speichern(t)
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Altes Klartext-Token übernommen: " + _token_meldung(d)}
        if name == "ordner_waehlen":
            return {"pfad": ordner_waehlen()}
        if name == "datei_waehlen":
            return {"pfad": datei_waehlen()}
        if name == "ordner_oeffnen":
            ordner_oeffnen(daten_ordner() if p.get("was") in ("daten", "qnap") else str(p.get("pfad") or ""))
            return {}
        if name == "werkzeug_veroeffentlichen":
            pr = next((x for x in d.get("profile") or [] if x.get("oeffentlich") == WERKZEUG_SCHLUESSEL), None)
            if not pr or not os.path.isfile(schluessel_pfad(pr)):
                raise ValueError("Kein Profil mit dem Schlüssel des Herausgebers (" + WERKZEUG_SCHLUESSEL[:8] + "…) gefunden.")
            pr = dict(pr)
        else:
            pr = _profil(d, p.get("id")) if name not in ("update_suchen", "update_einspielen", "werkzeug_bau_starten", "werkzeug_bau_status") else None
        token = geheim_lesen(d.get("github_token"))
    if name == "update_suchen":
        version, _rel = werkzeug_neueste()
        neuer = bool(version) and _version_tupel(version) > _version_tupel(VERSION)
        return {"version": version, "aktuell": VERSION, "neuer": neuer,
                "exe": bool(getattr(sys, "frozen", False)) and os.name == "nt"}
    if name == "update_einspielen":
        version = werkzeug_update()
        return {"ok": True, "version": version, "neustart": True,
                "meldung": f"Version {version} geprüft und eingespielt – das Werkzeug startet neu (neues Browserfenster)."}
    if name == "werkzeug_bau_starten":
        if not token:
            raise ValueError("Zum Starten des Baus wird ein GitHub-Token gebraucht (Reiter „GitHub“).")
        version, stand = werkzeug_bau_starten(token)
        return {"ok": True, "meldung": f"Tag v{version} auf {stand[:7]} gesetzt. GitHub baut jetzt unter „Actions“ "
                                       "(einige Minuten), danach hier „Neuen Entwurf signieren und veröffentlichen“."}
    if name == "werkzeug_bau_status":
        return werkzeug_bau_status(token)
    if name == "werkzeug_veroeffentlichen":
        if not token:
            raise ValueError("Zum Veröffentlichen wird ein GitHub-Token gebraucht (Reiter „GitHub“).")
        version, summe, commit = werkzeug_veroeffentlichen(pr, str(p.get("kennwort") or ""), token)
        return {"ok": True, "meldung": f"Signier-Werkzeug {version} aus Commit {commit[:7]} signiert und veröffentlicht "
                                       f"(SHA-256 {summe}). Andere Installationen bieten das Update jetzt an."}
    # Lange Arbeiten ohne Sperre
    if name == "signieren_ordner":
        ordner = str(p.get("ordner") or "").strip().strip('"')
        if not os.path.isdir(ordner):
            raise ValueError("Ordner nicht gefunden.")
        version, anzahl, _ = signieren(ordner, pr, str(p.get("kennwort") or ""))
        return {"meldung": f"SIGNATUR.json geschrieben: Version {version or '(ohne)'}, {anzahl} Dateien.", "ok": True}
    if name == "pruefen_ordner":
        ordner = str(p.get("ordner") or "").strip().strip('"')
        if not os.path.isdir(ordner):
            raise ValueError("Ordner nicht gefunden.")
        return {"pruefung": pruefen(ordner, pr.get("oeffentlich") or "", pr.get("regel", "alle"), pr.get("ausschluss"))}
    if name in ("signieren_github", "pruefen_github"):
        if not pr.get("repo"):
            raise ValueError("Im Profil ist kein GitHub-Repository eingetragen.")
        with tempfile.TemporaryDirectory(prefix="signier-") as tmp:
            ordner, stand = github_laden(pr["repo"], pr.get("zweig") or "main", token, tmp)
            if name == "pruefen_github":
                return {"pruefung": pruefen(ordner, pr.get("oeffentlich") or "", pr.get("regel", "alle"), pr.get("ausschluss")),
                        "stand": stand[:7]}
            if not token:
                raise ValueError("Zum Hochladen wird ein GitHub-Token gebraucht (Reiter „GitHub“).")
            version, anzahl, inhalt = signieren(ordner, pr, str(p.get("kennwort") or ""))
            github_tag_frei(pr["repo"], token, version, stand)
            commit = github_hochladen(pr["repo"], pr.get("zweig") or "main", token, inhalt, version, stand)
            try:
                tag = github_tag_setzen(pr["repo"], token, version, commit)
                tag_text = f" Tag {tag} gesetzt." if tag else ""
            except ValueError as e:
                tag_text = f" Tag konnte nicht gesetzt werden: {e}"
        hoch = "SIGNATUR.json war schon aktuell" if commit == stand else f"SIGNATUR.json hochgeladen (Commit {commit[:7]})"
        return {"ok": True, "meldung": f"Version {version or '(ohne)'} ({anzahl} Dateien, Stand {stand[:7]}) signiert, "
                                       f"{hoch}.{tag_text} Jetzt kann das Update eingespielt werden."}
    raise ValueError("Unbekannte Aktion.")


# ---------------------------------------------------------------------------
# Lokaler Server
# ---------------------------------------------------------------------------
class Server:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.letzter_kontakt = time.time()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self.httpd.server_address[1]

    def _handler(self):
        server = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _host_ok(self):
                return self.headers.get("Host") == f"127.0.0.1:{server.port}"

            def _senden(self, code, inhalt, typ="application/json; charset=utf-8"):
                daten = inhalt.encode("utf-8") if isinstance(inhalt, str) else inhalt
                self.send_response(code)
                self.send_header("Content-Type", typ)
                self.send_header("Content-Length", str(len(daten)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; "
                                 "style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(daten)

            def do_GET(self):
                url = urllib.parse.urlsplit(self.path)
                q = urllib.parse.parse_qs(url.query)
                if not self._host_ok() or url.path != "/" or q.get("t", [""])[0] != server.token:
                    return self._senden(403, "Zugriff verweigert.", "text/plain; charset=utf-8")
                server.letzter_kontakt = time.time()
                self._senden(200, SEITE.replace("__TOKEN__", server.token).replace("__VERSION__", VERSION)
                             .replace("__REPO__", WERKZEUG_REPO),
                             "text/html; charset=utf-8")

            def do_POST(self):
                if not self._host_ok() or self.headers.get("X-Token") != server.token \
                        or self.headers.get("Origin") not in (None, f"http://127.0.0.1:{server.port}"):
                    return self._senden(403, json.dumps({"fehler": "Zugriff verweigert."}))
                server.letzter_kontakt = time.time()
                name = self.path.rsplit("/", 1)[-1]
                try:
                    laenge = min(int(self.headers.get("Content-Length") or 0), 1024 * 1024)
                    p = json.loads(self.rfile.read(laenge).decode("utf-8") or "{}")
                    if name == "ping":
                        return self._senden(200, "{}")
                    if name == "beenden":
                        self._senden(200, "{}")
                        threading.Thread(target=server.httpd.shutdown, daemon=True).start()
                        return
                    antwort = aktion(name, p if isinstance(p, dict) else {})
                    self._senden(200, json.dumps(antwort, ensure_ascii=False))
                    if antwort.get("neustart"):
                        threading.Thread(target=server.neu_starten, daemon=True).start()
                except ValueError as e:
                    self._senden(400, json.dumps({"fehler": schwaerzen(e)}, ensure_ascii=False))
                except Exception as e:
                    self._senden(500, json.dumps({"fehler": schwaerzen(f"Unerwarteter Fehler: {e.__class__.__name__}: {e}")},
                                                 ensure_ascii=False))
        return H

    def neu_starten(self):
        """Nach einem Update: die neue exe starten, diese hier beenden."""
        time.sleep(1)
        try:
            # eigenständig starten (nicht den entpackten Ordner dieses Prozesses mitbenutzen)
            subprocess.Popen([sys.executable], close_fds=True, env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
                             creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        finally:
            self.httpd.shutdown()

    def waechter(self):
        # ohne Konsolenfenster: beenden, wenn die Seite 3 Minuten nichts meldet
        while True:
            time.sleep(15)
            if time.time() - self.letzter_kontakt > 180:
                self.httpd.shutdown()
                return

    def starten(self, browser=True):
        url = f"http://127.0.0.1:{self.port}/?t={self.token}"
        threading.Thread(target=self.waechter, daemon=True).start()
        if browser:
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        self.httpd.serve_forever()


def _sicherheit_selbsttest(tmp):
    """Für den Bau unter Windows: ZIP-Pfade, Kollisionen, atomares Schreiben.
    -> Liste der Fehler (leer = alles in Ordnung)."""
    import io
    fehler = []

    def zip_mit(namen):
        puffer = io.BytesIO()
        with zipfile.ZipFile(puffer, "w") as z:
            z.writestr("repo-abc/", "")
            for n in namen:
                z.writestr("repo-abc/" + n, "x")
        puffer.seek(0)
        return puffer
    aussen = os.path.join(tmp, "aussen")
    os.makedirs(aussen)
    vorher = sorted(os.listdir(aussen))
    for name in ["../ausserhalb.txt", "..\\..\\ausserhalb.txt", "/absolut/datei", "C:\\Windows\\datei", "C:..\\..\\datei",
                 "C:datei", "\\\\server\\share\\datei", "a/../../datei", "CON", "aux.txt", "datei. ", "a:b"]:
        ziel = tempfile.mkdtemp(dir=aussen)
        try:
            zip_entpacken(zip_mit([name]), ziel)
            fehler.append(f"zip:{name!r} angenommen")
        except ValueError:
            pass
        if os.listdir(ziel):
            fehler.append(f"zip:{name!r} hat Dateien hinterlassen")
        shutil.rmtree(ziel)
    if sorted(os.listdir(aussen)) != vorher or os.path.exists(os.path.join(tmp, "ausserhalb.txt")):
        fehler.append("zip: Datei außerhalb geschrieben")
    ziel = tempfile.mkdtemp(dir=aussen)
    try:
        zip_entpacken(zip_mit(["A.txt", "a.txt"]), ziel)
        fehler.append("zip: Groß/Klein-Kollision angenommen")
    except ValueError:
        pass
    ziel = tempfile.mkdtemp(dir=aussen)
    try:
        if zip_entpacken(zip_mit(["ordner/datei.txt", "b.txt"]), ziel) != 2 \
                or open(os.path.join(ziel, "ordner", "datei.txt")).read() != "x":
            fehler.append("zip: gutes Archiv falsch entpackt")
    except ValueError as e:
        fehler.append(f"zip: gutes Archiv abgelehnt ({e})")
    ordner = tempfile.mkdtemp(dir=tmp)
    try:
        atomar_schreiben(ordner, SIGNATUR_DATEI, b"eins")
        atomar_schreiben(ordner, SIGNATUR_DATEI, b"zwei")
        if open(os.path.join(ordner, SIGNATUR_DATEI), "rb").read() != b"zwei" or len(os.listdir(ordner)) != 1:
            fehler.append("atomar: falscher Stand")
        os.mkdir(os.path.join(ordner, "x.json"))
        try:
            atomar_schreiben(ordner, "x.json", b"1")
            fehler.append("atomar: Ordner am Ziel überschrieben")
        except ValueError:
            pass
        if sorted(os.listdir(ordner)) != [SIGNATUR_DATEI, "x.json"]:
            fehler.append("atomar: temporäre Datei liegen geblieben")
    except (OSError, ValueError) as e:
        fehler.append(f"atomar: {e.__class__.__name__}: {e}")
    for wert in ("/share/../x", "/share/x;id", "/share/x y", "/share/Daten", "relativ/x"):   # QNAP-Begleiter
        try:
            Q.programmordner_pruefen(wert)
            fehler.append(f"qnap:{wert!r} angenommen")
        except ValueError:
            pass
    for arg in ("a%PATH%", "a!b", 'a"b'):
        try:
            Q.befehlszeile([arg])
            fehler.append(f"qnap: Befehlszeile mit {arg!r} angenommen")
        except ValueError:
            pass
    return fehler


def selbsttest(ausgabe):
    """Für den Bau: signiert und prüft einen Testordner und prüft die
    Sicherheitsregeln (unter Windows), Ergebnis in eine Datei."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["APPDATA"] = tmp
        open(os.path.join(tmp, "a.txt"), "w").write("Zeile\n")
        privat = Ed25519PrivateKey.generate()
        pr = {"id": "selbsttest01", "oeffentlich": oeffentlich_text(privat), "regel": "alle", "ausschluss": ["Signier-Werkzeug/*"]}
        with open(schluessel_pfad(pr), "wb") as f:
            f.write(privat.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(b"Selbsttest-123")))
        signieren(tmp, pr, "Selbsttest-123", "0.0.1")
        r = pruefen(tmp, pr["oeffentlich"], "alle", pr["ausschluss"])
        dp = ""
        if os.name == "nt":
            dp = " dpapi=" + str(geheim_lesen(geheim_speichern("probe")) == "probe")
        fehler = _sicherheit_selbsttest(tmp)
        ergebnis = "OK" if r["ok"] and not fehler else "FEHLER " + json.dumps({"pruefung": r, "sicherheit": fehler},
                                                                             ensure_ascii=False)
        open(ausgabe, "w", encoding="utf-8").write(ergebnis + dp + " sicherheit=" + ("ok" if not fehler else "fehler") + "\n")


SEITE = r"""<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signier-Werkzeug</title><style>
:root{--bg:#0f1620;--karte:#17212d;--rand:#263544;--text:#e8edf3;--leise:#9fb0c2;--akzent:#3b82f6;--ok:#22c55e;--warn:#f59e0b;--fehler:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,Segoe UI,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--rand)}header h1{font-size:18px;margin:0}
header .rechts{margin-left:auto;display:flex;gap:8px;align-items:center;color:var(--leise);font-size:13px}
main{max-width:980px;margin:0 auto;padding:18px}nav{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
nav button{background:transparent;border:1px solid var(--rand);color:var(--leise)}nav button.aktiv{background:var(--akzent);color:#fff;border-color:var(--akzent)}
.karte{background:var(--karte);border:1px solid var(--rand);border-radius:10px;padding:16px;margin-bottom:14px}
.karte h2{font-size:16px;margin:0 0 10px}label{display:block;font-size:13px;color:var(--leise);margin:10px 0 4px}
input,select,textarea{width:100%;padding:8px 10px;border-radius:8px;border:1px solid var(--rand);background:var(--bg);color:var(--text);font:inherit}
textarea{min-height:70px;font-family:Consolas,monospace;font-size:13px}
button{padding:8px 14px;border-radius:8px;border:1px solid var(--akzent);background:var(--akzent);color:#fff;font:inherit;cursor:pointer}
button.zweit{background:transparent;color:var(--text);border-color:var(--rand)}button:disabled{opacity:.5;cursor:wait}
.zeile{display:flex;gap:8px;align-items:end;flex-wrap:wrap}.zeile>*{flex:1 1 200px}.zeile>button{flex:0 0 auto}
.hinweis{font-size:13px;color:var(--leise)}.mono{font-family:Consolas,monospace;word-break:break-all}
.status{margin-top:12px;padding:10px 12px;border-radius:8px;display:none}.status.ok{display:block;background:#14532d;border:1px solid var(--ok)}
.status.fehler{display:block;background:#450a0a;border:1px solid var(--fehler)}.status.laeuft{display:block;background:#1e293b;border:1px solid var(--rand)}
.profil{display:flex;gap:10px;align-items:center;padding:8px 0;border-top:1px solid var(--rand)}.profil:first-of-type{border-top:0}
.profil b{flex:1}.marke{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--rand);color:var(--leise)}
.marke.gut{border-color:var(--ok);color:var(--ok)}.marke.schlecht{border-color:var(--warn);color:var(--warn)}
.versteckt{display:none !important}button.hervor{box-shadow:0 0 0 3px var(--ok)}.status a{color:#93c5fd}ul{margin:6px 0 0 18px;padding:0}
</style></head><body>
<header><h1>🔏 Signier-Werkzeug</h1><div class="rechts"><button id="update-knopf" class="versteckt">Update</button>
Version __VERSION__ <button class="zweit" id="beenden">Beenden</button></div></header>
<div id="update-leiste" class="versteckt" style="padding:10px 20px;background:#1e293b;border-bottom:1px solid var(--rand)"></div>
<main>
<nav><button data-reiter="signieren" class="aktiv">Signieren</button><button data-reiter="pruefen">Prüfen</button>
<button data-reiter="profile">Profile &amp; Schlüssel</button><button data-reiter="github">GitHub</button>
<button data-reiter="qnap">QNAP</button></nav>

<section id="r-signieren">
 <div class="karte"><h2>Version signieren</h2>
  <label for="s-profil">Profil (Software)</label><select id="s-profil"></select>
  <div class="zeile" style="margin-top:12px"><button id="s-github">Von GitHub laden, signieren und hochladen</button></div>
  <div class="hinweis" id="s-github-info" style="margin-top:6px"></div>
  <details style="margin-top:14px"><summary class="hinweis">… oder einen Ordner auf diesem Rechner signieren</summary>
   <div class="zeile"><div><label for="s-ordner">Ordner</label><input id="s-ordner" placeholder="C:\…\Ordner der Version"></div>
   <button class="zweit" data-waehle="s-ordner">Ordner wählen…</button></div>
   <div class="zeile" style="margin-top:10px"><button id="s-ordner-los">Ordner signieren</button></div></details>
  <div class="status" id="s-status"></div></div>
</section>

<section id="r-pruefen" class="versteckt">
 <div class="karte"><h2>Signatur prüfen</h2>
  <label for="p-profil">Profil (öffentlicher Schlüssel)</label><select id="p-profil"></select>
  <div class="zeile" style="margin-top:12px"><button id="p-github">Stand auf GitHub prüfen</button></div>
  <div class="zeile" style="margin-top:12px"><div><label for="p-ordner">… oder Ordner</label><input id="p-ordner"></div>
  <button class="zweit" data-waehle="p-ordner">Ordner wählen…</button><button class="zweit" id="p-ordner-los">Ordner prüfen</button></div>
  <div class="status" id="p-status"></div></div>
</section>

<section id="r-profile" class="versteckt">
 <div class="karte"><h2>Profile</h2><div id="profilliste"></div>
  <div class="zeile" style="margin-top:12px"><button id="neu-speedrace" class="zweit">+ Profil „Speedrace-Dashboard“</button>
  <button id="neu-allgemein" class="zweit">+ Profil für andere Software</button></div></div>
 <div class="karte versteckt" id="bearbeiten"><h2 id="b-titel">Profil</h2><input type="hidden" id="b-id">
  <div class="zeile"><div><label for="b-name">Name</label><input id="b-name"></div>
  <div><label for="b-regel">Welche Dateien werden signiert?</label><select id="b-regel">
   <option value="speedrace">Speedrace-Dashboard (nur Dateien, die ein Update übernimmt)</option>
   <option value="alle">Alle Dateien außer Ausnahmen</option></select></div></div>
  <div class="zeile"><div><label for="b-repo">GitHub-Repository (Besitzer/Name)</label><input id="b-repo" placeholder="z. B. Hansi478/live-Ergebnisse"></div>
  <div><label for="b-zweig">Zweig</label><input id="b-zweig" value="main"></div></div>
  <div id="b-aus-box"><label for="b-ausschluss">Ausnahmen (eine je Zeile, z. B. <span class="mono">*.log</span> oder <span class="mono">daten/*</span>); .git, __pycache__ und SIGNATUR.json sind immer ausgenommen</label>
  <textarea id="b-ausschluss"></textarea></div>
  <div class="zeile" style="margin-top:12px"><button id="b-speichern">Speichern</button><button class="zweit" id="b-abbrechen">Abbrechen</button></div>
  <div id="b-schluessel" class="versteckt" style="margin-top:16px;border-top:1px solid var(--rand);padding-top:12px">
   <h2>Schlüssel dieses Profils</h2><div id="b-schluessel-info" class="hinweis"></div>
   <div id="b-ohne"><div class="zeile"><div><label for="b-kw1">Kennwort für einen neuen Schlüssel (mind. 12 Zeichen)</label><input id="b-kw1" type="password" autocomplete="new-password"></div>
    <div><label for="b-kw2">Wiederholen</label><input id="b-kw2" type="password" autocomplete="new-password"></div><button id="b-neu">Neuen Schlüssel erzeugen</button></div>
    <div class="zeile" style="margin-top:12px"><div><label for="b-pfad">… oder vorhandenen Schlüssel übernehmen (.pem)</label><input id="b-pfad"></div>
    <button class="zweit" id="b-pfad-waehlen">Datei wählen…</button></div>
    <div class="zeile"><div><label for="b-pfad-kw">Kennwort dieses Schlüssels</label><input id="b-pfad-kw" type="password" autocomplete="off"></div><button class="zweit" id="b-import">Übernehmen</button></div></div>
  </div><div class="status" id="b-status"></div></div>
 <div class="karte"><h2>Sicherung</h2><div class="hinweis">Die privaten Schlüssel liegen (mit Kennwort verschlüsselt) in <span class="mono" id="datenpfad"></span>\schluessel.
  Diesen Ordner zusätzlich auf einen USB-Stick kopieren und das Kennwort sicher aufbewahren. Ohne beides lässt sich nicht mehr signieren
  (dann neues Profil mit neuem Schlüssel anlegen und den neuen öffentlichen Schlüssel eintragen).</div>
  <div class="zeile" style="margin-top:10px"><button class="zweit" id="daten-oeffnen">Ordner öffnen</button></div></div>
</section>

<section id="r-github" class="versteckt">
 <div class="karte"><h2>GitHub-Zugang</h2>
  <div class="hinweis">Zum Hochladen von SIGNATUR.json braucht das Werkzeug ein Token: GitHub → Settings → Developer settings →
  Fine-grained tokens → „Generate new token“ → Repository access: nur die betroffenen Repositories → Permissions:
  <b>Contents: Read and write</b>. Unter Windows wird es mit DPAPI verschlüsselt (nur für deinen Windows-Benutzer lesbar),
  sonst im Schlüsselbund des Betriebssystems - gibt es keinen sicheren Speicher, gilt es nur für diese Sitzung.</div>
  <div class="status fehler versteckt" id="g-klartext">⚠️ Das gespeicherte Token liegt aus einer älteren Version nur
  Base64-kodiert in profile.json - das ist <b>keine Verschlüsselung</b>. <div class="zeile" style="margin-top:8px">
  <button id="g-migrieren">Sicher speichern</button><button class="zweit" id="g-alt-weg">Entfernen</button></div></div>
  <div class="zeile" style="margin-top:10px"><div><label for="g-token">Token</label><input id="g-token" type="password" autocomplete="off" placeholder="github_pat_…"></div>
  <button id="g-speichern">Speichern</button><button class="zweit" id="g-entfernen">Entfernen</button></div>
  <div class="hinweis" id="g-stand" style="margin-top:8px"></div><div class="status" id="g-status"></div></div>
 <div class="karte"><h2>Signier-Werkzeug selbst</h2>
  <div class="hinweis">Updates kommen aus <span class="mono">__REPO__</span> und werden nur mit gültiger Signatur
  (Schlüssel des Herausgebers) eingespielt. Neue Version veröffentlichen: VERSION in <span class="mono">signier_werkzeug.py</span> erhöhen und nach main committen,
  hier „Bau starten“ (setzt den Tag, z. B. <span class="mono">v1.2.1</span>), warten, bis GitHub unter „Actions“ fertig gebaut hat, dann hier signieren. Erst danach sehen andere Installationen das Update.</div>
  <div class="zeile" style="margin-top:10px"><button class="zweit" id="w-suchen">Nach Update suchen</button>
  <button class="zweit" id="w-bauen">Bau starten (Tag setzen)</button>
  <button class="zweit" id="w-baustatus">Bau-Status prüfen</button>
  <button id="w-veroeff">Neuen Entwurf signieren und veröffentlichen</button></div>
  <div class="status" id="w-status"></div></div>
</section>

<section id="r-qnap" class="versteckt">
 <div class="karte"><h2>QNAP-Profil</h2>
  <div class="hinweis">Begleitet die SSH-Schritte für das Speedrace-Dashboard auf einer QNAP: Jeder Schritt wird einzeln erklärt und
  erst nach deiner Bestätigung in einem eigenen Konsolenfenster gestartet (das in Windows eingebaute ssh). Passwort und Host-Schlüssel
  bestätigst du nur dort – das Werkzeug sieht und speichert kein Passwort und legt keine SSH-Schlüssel an.</div>
  <div class="zeile"><div><label for="q-host">Host bzw. IP</label><input id="q-host" placeholder="192.0.2.10" autocomplete="off"></div>
   <div style="flex:0 0 110px"><label for="q-port">Port</label><input id="q-port" value="22" autocomplete="off"></div>
   <div><label for="q-benutzer">Benutzer</label><input id="q-benutzer" placeholder="admin-benutzer" autocomplete="off"></div></div>
  <div class="zeile"><div><label for="q-ordner">Programmordner auf der QNAP (absolut)</label><input id="q-ordner" placeholder="/share/BEISPIEL/programmordner" autocomplete="off"></div>
   <div><label for="q-adresse">Dashboard-Adresse (optional, für die Kontrolle)</label><input id="q-adresse" placeholder="http://192.0.2.10:8090" autocomplete="off"></div></div>
  <div class="zeile"><div><label for="q-quelle">Versionen von (Signier-Profil mit GitHub-Repository)</label><select id="q-quelle"></select></div>
   <div><label for="q-compose">Docker-Variante</label><select id="q-compose"><option value="plugin">docker compose</option><option value="standalone">docker-compose</option></select></div>
   <div><label for="q-bin">Ordner der Docker-Programme (nur falls nötig)</label><input id="q-bin" placeholder="leer lassen" autocomplete="off"></div></div>
  <div class="zeile" style="margin-top:12px"><button id="q-speichern">Profil speichern</button></div>
  <div class="status" id="q-pstatus"></div></div>
 <div class="karte"><h2>Ablauf</h2>
  <div class="zeile"><div><label for="q-ablauf">Was soll passieren?</label><select id="q-ablauf"></select></div>
   <button id="q-beginnen">Ablauf beginnen</button><button class="zweit" id="q-abbrechen">Abbrechen</button></div>
  <label style="display:flex;gap:8px;align-items:center;margin-top:10px"><input type="checkbox" id="q-nur" style="width:auto">
   Nur anleiten (nichts ausführen – Befehle nur lesen und kopieren)</label>
  <div class="zeile" style="margin-top:10px"><button class="zweit" id="q-http">Dashboard-Adresse prüfen</button>
   <button class="zweit" id="q-protokoll">Ordner mit Protokoll öffnen</button>
   <button class="zweit versteckt" id="q-vergessen">Gemerkten alten Ordner vergessen</button></div>
  <div class="hinweis" id="q-info" style="margin-top:8px"></div>
  <div class="status" id="q-status"></div></div>
 <div id="q-schritte"></div>
</section>
</main>
<div id="kw-dialog" class="versteckt" style="position:fixed;inset:0;background:#000a;display:flex;align-items:center;justify-content:center">
 <div class="karte" style="width:min(420px,92vw)"><h2>Kennwort des Schlüssels</h2><div class="hinweis" id="kw-text"></div>
 <input id="kw-feld" type="password" autocomplete="off" style="margin-top:10px"><div class="zeile" style="margin-top:12px">
 <button id="kw-ok">Signieren</button><button class="zweit" id="kw-abbr">Abbrechen</button></div></div></div>
<script>
"use strict";
const TOKEN = "__TOKEN__"; let Z = {profile: []};
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(name, daten) {
  const r = await fetch("/api/" + name, {method: "POST", headers: {"X-Token": TOKEN, "Content-Type": "application/json"}, body: JSON.stringify(daten || {})});
  let d = {}; try { d = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error(d.fehler || ("Fehler " + r.status));
  return d;
}
function status(id, art, text) { const el = $(id); el.className = "status " + art; el.innerHTML = text; }
async function mit(id, knopf, text, f) {
  knopf.disabled = true; status(id, "laeuft", "⏳ " + esc(text));
  try { await f(); } catch (e) { status(id, "fehler", "❌ " + esc(e.message)); } finally { knopf.disabled = false; }
}
document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("aktiv", x === b));
  document.querySelectorAll("main > section").forEach(s => s.classList.toggle("versteckt", s.id !== "r-" + b.dataset.reiter));
});
function zeichnen() {
  const opt = Z.profile.map(p => `<option value="${esc(p.id)}">${esc(p.name)}${p.hat_schluessel ? "" : " (ohne Schlüssel)"}</option>`).join("");
  ["s-profil", "p-profil"].forEach(id => { const alt = $(id).value; $(id).innerHTML = opt || '<option value="">– erst ein Profil anlegen –</option>'; if (alt) $(id).value = alt; });
  $("profilliste").innerHTML = Z.profile.length ? Z.profile.map(p => `<div class="profil"><b>${esc(p.name)}</b>
    <span class="marke">${p.regel === "speedrace" ? "Speedrace" : "alle Dateien"}</span>
    <span class="marke ${p.hat_schluessel ? "gut" : "schlecht"}">${p.hat_schluessel ? "Schlüssel ✓" : "kein Schlüssel"}</span>
    <button class="zweit" data-bearb="${esc(p.id)}">Bearbeiten</button><button class="zweit" data-loesch="${esc(p.id)}">Löschen</button></div>`).join("")
    : '<div class="hinweis">Noch kein Profil.</div>';
  document.querySelectorAll("[data-bearb]").forEach(b => b.onclick = () => bearbeiten(Z.profile.find(p => p.id === b.dataset.bearb)));
  document.querySelectorAll("[data-loesch]").forEach(b => b.onclick = async () => {
    const p = Z.profile.find(x => x.id === b.dataset.loesch);
    if (!confirm(`Profil „${p.name}“ löschen? Die Schlüsseldatei wird nicht gelöscht, nur umbenannt (…geloescht-Datum).`)) return;
    try { Z = await api("profil_loeschen", {id: p.id}); zeichnen(); $("bearbeiten").classList.add("versteckt"); } catch (e) { alert(e.message); }
  });
  $("datenpfad").textContent = Z.daten || "";
  const ART = {dpapi: "mit Windows-DPAPI verschlüsselt gespeichert", schluesselbund: "im Schlüsselbund des Betriebssystems gespeichert",
    sitzung: "nur für diese Sitzung im Arbeitsspeicher (nicht dauerhaft)", klartext: "UNSICHER als Klartext gespeichert"};
  const NEU = {dpapi: "Windows-DPAPI (dauerhaft)", schluesselbund: "Schlüsselbund des Betriebssystems (dauerhaft)", sitzung: "nur diese Sitzung (kein sicherer Speicher verfügbar)"};
  $("g-stand").textContent = (Z.token ? "✓ Token " + (ART[Z.token_speicher] || "gespeichert") + "." : "Noch kein Token gespeichert.")
    + " Neues Token wird gespeichert: " + (NEU[Z.token_methode] || "?") + ".";
  $("g-klartext").classList.toggle("versteckt", Z.token_speicher !== "klartext");
  profilInfo();
}
function profilInfo() {
  const p = Z.profile.find(x => x.id === $("s-profil").value);
  $("s-github-info").textContent = p ? (p.repo ? `Repository ${p.repo}, Zweig ${p.zweig || "main"}` : "Im Profil ist kein GitHub-Repository eingetragen.") : "";
}
$("s-profil").onchange = profilInfo;
function bearbeiten(p, vorlage) {
  p = p || {}; $("bearbeiten").classList.remove("versteckt"); $("b-status").className = "status";
  $("b-titel").textContent = p.id ? "Profil bearbeiten" : "Neues Profil";
  $("b-id").value = p.id || ""; $("b-name").value = p.name || (vorlage === "speedrace" ? "Speedrace-Dashboard" : "");
  $("b-regel").value = p.regel || vorlage || "alle"; $("b-repo").value = p.repo != null ? p.repo : (vorlage === "speedrace" ? "Hansi478/live-Ergebnisse" : "");
  $("b-zweig").value = p.zweig || "main"; $("b-ausschluss").value = (p.ausschluss || []).join("\n");
  $("b-aus-box").classList.toggle("versteckt", $("b-regel").value === "speedrace");
  $("b-schluessel").classList.toggle("versteckt", !p.id);
  if (p.id) {
    $("b-ohne").classList.toggle("versteckt", !!p.hat_schluessel);
    $("b-schluessel-info").innerHTML = p.hat_schluessel
      ? `Öffentlicher Schlüssel (dort eintragen, wo geprüft wird, z. B. SR_UPDATE_SCHLUESSEL):<div class="zeile" style="margin-top:6px"><div class="mono" id="b-oeff">${esc(p.oeffentlich)}</div><button class="zweit" id="b-kopieren">Kopieren</button></div>`
      : "Dieses Profil hat noch keinen Schlüssel." + (Z.alter_schluessel ? " Gefunden: ein früher mit tools\\signieren.py erzeugter Schlüssel – unten übernehmen." : "");
    if (!p.hat_schluessel && Z.alter_schluessel && !$("b-pfad").value) $("b-pfad").value = Z.alter_schluessel;
    if ($("b-kopieren")) $("b-kopieren").onclick = () => navigator.clipboard.writeText(p.oeffentlich).then(() => status("b-status", "ok", "✅ Kopiert."));
  }
  $("bearbeiten").scrollIntoView({behavior: "smooth"});
}
$("b-regel").onchange = () => $("b-aus-box").classList.toggle("versteckt", $("b-regel").value === "speedrace");
$("neu-speedrace").onclick = () => bearbeiten(null, "speedrace");
$("neu-allgemein").onclick = () => bearbeiten(null, "alle");
$("b-abbrechen").onclick = () => $("bearbeiten").classList.add("versteckt");
$("b-speichern").onclick = e => mit("b-status", e.target, "Speichern …", async () => {
  const neu = !$("b-id").value;
  Z = await api("profil_speichern", {id: $("b-id").value, name: $("b-name").value, regel: $("b-regel").value,
    repo: $("b-repo").value, zweig: $("b-zweig").value, ausschluss: $("b-ausschluss").value});
  zeichnen();
  const p = neu ? Z.profile[Z.profile.length - 1] : Z.profile.find(x => x.id === $("b-id").value);
  bearbeiten(p); status("b-status", "ok", "✅ Gespeichert." + (p.hat_schluessel ? "" : " Jetzt einen Schlüssel erzeugen oder übernehmen."));
});
$("b-neu").onclick = e => mit("b-status", e.target, "Schlüssel wird erzeugt …", async () => {
  if ($("b-kw1").value !== $("b-kw2").value) throw new Error("Die Kennwörter sind nicht gleich.");
  Z = await api("schluessel_neu", {id: $("b-id").value, kennwort: $("b-kw1").value});
  $("b-kw1").value = $("b-kw2").value = ""; zeichnen(); bearbeiten(Z.profile.find(x => x.id === $("b-id").value));
  status("b-status", "ok", "✅ " + esc(Z.meldung));
});
$("b-pfad-waehlen").onclick = async () => { try { const d = await api("datei_waehlen"); if (d.pfad) $("b-pfad").value = d.pfad; } catch (e) { alert(e.message); } };
$("b-import").onclick = e => mit("b-status", e.target, "Schlüssel wird geprüft …", async () => {
  Z = await api("schluessel_import", {id: $("b-id").value, pfad: $("b-pfad").value, kennwort: $("b-pfad-kw").value});
  $("b-pfad-kw").value = ""; zeichnen(); bearbeiten(Z.profile.find(x => x.id === $("b-id").value));
  status("b-status", "ok", "✅ " + esc(Z.meldung));
});
$("daten-oeffnen").onclick = () => api("ordner_oeffnen", {was: "daten"}).catch(e => alert(e.message));
document.querySelectorAll("[data-waehle]").forEach(b => b.onclick = async () => {
  try { const d = await api("ordner_waehlen"); if (d.pfad) $(b.dataset.waehle).value = d.pfad; } catch (e) { alert(e.message); } });
function kennwort(text) {
  return new Promise(ok => {
    $("kw-text").textContent = text; $("kw-feld").value = ""; $("kw-dialog").classList.remove("versteckt"); $("kw-feld").focus();
    const fertig = w => { $("kw-dialog").classList.add("versteckt"); $("kw-ok").onclick = $("kw-abbr").onclick = $("kw-feld").onkeydown = null; ok(w); };
    $("kw-ok").onclick = () => fertig($("kw-feld").value); $("kw-abbr").onclick = () => fertig(null);
    $("kw-feld").onkeydown = ev => { if (ev.key === "Enter") fertig($("kw-feld").value); if (ev.key === "Escape") fertig(null); };
  });
}
function profilPruefen(id) {
  const p = Z.profile.find(x => x.id === id);
  if (!p) throw new Error("Bitte zuerst ein Profil anlegen (Reiter „Profile & Schlüssel“).");
  if (!p.hat_schluessel) throw new Error("Das Profil hat noch keinen Schlüssel (Reiter „Profile & Schlüssel“).");
  return p;
}
$("s-github").onclick = async e => {
  let p; try { p = profilPruefen($("s-profil").value); } catch (err) { return status("s-status", "fehler", "❌ " + esc(err.message)); }
  const kw = await kennwort(`${p.name}: Stand von ${p.repo || "?"} (${p.zweig || "main"}) laden, signieren und SIGNATUR.json hochladen.`);
  if (kw === null) return;
  mit("s-status", e.target, "Lade von GitHub, signiere und lade hoch … (kann eine Minute dauern)", async () => {
    const d = await api("signieren_github", {id: p.id, kennwort: kw}); status("s-status", "ok", "✅ " + esc(d.meldung)); });
};
$("s-ordner-los").onclick = async e => {
  let p; try { p = profilPruefen($("s-profil").value); } catch (err) { return status("s-status", "fehler", "❌ " + esc(err.message)); }
  const kw = await kennwort(`${p.name}: Ordner ${$("s-ordner").value} signieren.`);
  if (kw === null) return;
  mit("s-status", e.target, "Signiere …", async () => {
    const d = await api("signieren_ordner", {id: p.id, kennwort: kw, ordner: $("s-ordner").value}); status("s-status", "ok", "✅ " + esc(d.meldung)); });
};
function pruefErgebnis(d) {
  const r = d.pruefung || {};
  if (r.ok) return status("p-status", "ok", `✅ Signatur gültig – Version ${esc(r.version || "(ohne)")}, alle ${r.anzahl} Dateien passen${d.stand ? " (GitHub-Stand " + esc(d.stand) + ")" : ""}.`);
  const art = r.arten || {};
  status("p-status", "fehler", "❌ " + esc(r.fehler || "Nicht gültig.") + (r.abweichend && r.abweichend.length ? "<ul>" + r.abweichend.map(n => `<li><span class="mono">${esc(n)}</span>${art[n] ? " (" + esc(art[n]) + ")" : ""}</li>`).join("") + "</ul>" : ""));
}
$("p-github").onclick = e => mit("p-status", e.target, "Lade von GitHub und prüfe …", async () => {
  const p = Z.profile.find(x => x.id === $("p-profil").value); if (!p || !p.oeffentlich) throw new Error("Profil ohne Schlüssel.");
  pruefErgebnis(await api("pruefen_github", {id: p.id})); });
$("p-ordner-los").onclick = e => mit("p-status", e.target, "Prüfe …", async () => {
  const p = Z.profile.find(x => x.id === $("p-profil").value); if (!p || !p.oeffentlich) throw new Error("Profil ohne Schlüssel.");
  pruefErgebnis(await api("pruefen_ordner", {id: p.id, ordner: $("p-ordner").value})); });
$("g-speichern").onclick = e => mit("g-status", e.target, "Speichere …", async () => {
  Z = await api("token_speichern", {token: $("g-token").value}); $("g-token").value = ""; zeichnen(); status("g-status", "ok", "✅ " + esc(Z.meldung)); });
$("g-entfernen").onclick = e => mit("g-status", e.target, "Entferne …", async () => {
  Z = await api("token_speichern", {token: ""}); zeichnen(); status("g-status", "ok", "✅ " + esc(Z.meldung)); });
$("g-migrieren").onclick = e => mit("g-status", e.target, "Übernehme …", async () => {
  Z = await api("token_migrieren"); zeichnen(); status("g-status", "ok", "✅ " + esc(Z.meldung)); });
$("g-alt-weg").onclick = e => mit("g-status", e.target, "Entferne …", async () => {
  Z = await api("token_speichern", {token: ""}); zeichnen(); status("g-status", "ok", "✅ " + esc(Z.meldung)); });
$("beenden").onclick = async () => { try { await api("beenden"); } catch (e) {} document.body.innerHTML = '<main><div class="karte"><h2>Beendet</h2>Das Fenster kann geschlossen werden.</div></main>'; };
setInterval(() => api("ping").catch(() => {}), 20000);
function updateZeigen(d) {
  if (!d.neuer) return;
  $("update-knopf").classList.remove("versteckt"); $("update-knopf").textContent = "Update auf " + d.version;
  $("update-knopf").onclick = async () => {
    if (!d.exe) return alert("Updates werden nur in der Signier-Werkzeug.exe eingespielt.");
    if (!confirm(`Version ${d.version} laden, Signatur prüfen und einspielen? Das Werkzeug startet danach neu.`)) return;
    const l = $("update-leiste"); l.classList.remove("versteckt"); l.textContent = "⏳ Lade und prüfe Version " + d.version + " …";
    $("update-knopf").disabled = true;
    try { const r = await api("update_einspielen"); l.textContent = "✅ " + r.meldung + " Dieses Fenster kann geschlossen werden."; }
    catch (e) { l.textContent = "❌ " + e.message; $("update-knopf").disabled = false; }
  };
}
$("w-suchen").onclick = e => mit("w-status", e.target, "Frage GitHub …", async () => {
  const d = await api("update_suchen"); updateZeigen(d);
  status("w-status", "ok", d.neuer ? `✅ Version ${esc(d.version)} ist verfügbar – oben auf „Update auf ${esc(d.version)}“ klicken.`
    : `✅ Aktuell (Version ${esc(d.aktuell)}${d.version ? ", neueste veröffentlichte " + esc(d.version) : ", noch nichts veröffentlicht"}).`); });
let bauTimer = null, bauBis = 0;
function bauZeigen(d) {
  const link = d.url ? ` <a href="${esc(d.url)}" target="_blank" rel="noopener noreferrer">Lauf öffnen</a>` : "";
  $("w-veroeff").classList.toggle("hervor", d.zustand === "fertig" && d.entwurf);
  if (d.zustand === "keiner") return status("w-status", "laeuft", "Noch kein Bau gefunden.");
  if (d.zustand === "wartet") return status("w-status", "laeuft", `⏳ Bau ${esc(d.tag)} wartet auf einen Rechner bei GitHub …` + link);
  if (d.zustand === "laeuft") return status("w-status", "laeuft", `⏳ Bau ${esc(d.tag)} läuft${d.schritt ? " - " + esc(d.schritt) : ""} …` + link);
  if (d.zustand === "fehlgeschlagen") return status("w-status", "fehler", `❌ Bau ${esc(d.tag)} fehlgeschlagen.` + link);
  status("w-status", "ok", `✅ Bau ${esc(d.tag)} fertig` + (d.entwurf ? " - der Entwurf ist bereit: jetzt „Neuen Entwurf signieren und veröffentlichen“."
    : " (Entwurf nicht gefunden - ist er schon veröffentlicht oder fehlt ein Token?).") + link);
}
async function bauAbfragen() {
  try { const d = await api("werkzeug_bau_status"); bauZeigen(d);
    if (["fertig", "fehlgeschlagen"].includes(d.zustand) || Date.now() > bauBis) { clearInterval(bauTimer); bauTimer = null; }
  } catch (e) { status("w-status", "fehler", "❌ " + esc(e.message)); clearInterval(bauTimer); bauTimer = null; }
}
function bauBeobachten() { clearInterval(bauTimer); bauBis = Date.now() + 40 * 60 * 1000; bauTimer = setInterval(bauAbfragen, 20000); }
$("w-bauen").onclick = e => {
  if (!confirm("Tag v<VERSION> auf den neuesten Stand von main setzen? Die Version kommt aus signier_werkzeug.py auf main. GitHub baut daraufhin den Entwurf.")) return;
  mit("w-status", e.target, "Setze Tag …", async () => {
    const d = await api("werkzeug_bau_starten"); status("w-status", "ok", "✅ " + esc(d.meldung) + " Der Fortschritt wird hier angezeigt.");
    bauBeobachten(); setTimeout(bauAbfragen, 8000); });
};
$("w-baustatus").onclick = e => mit("w-status", e.target, "Frage GitHub …", async () => {
  const d = await api("werkzeug_bau_status"); bauZeigen(d); if (["wartet", "laeuft"].includes(d.zustand)) bauBeobachten(); });
$("w-veroeff").onclick = async e => {
  const kw = await kennwort("Neuesten Entwurf des Signier-Werkzeugs von GitHub laden, signieren und veröffentlichen (Schlüssel des Herausgebers).");
  if (kw === null) return;
  mit("w-status", e.target, "Lade Entwurf, signiere und veröffentliche …", async () => {
    const d = await api("werkzeug_veroeffentlichen", {kennwort: kw}); $("w-veroeff").classList.remove("hervor"); status("w-status", "ok", "✅ " + esc(d.meldung)); });
};
// ---- QNAP-Begleiter ----------------------------------------------------
let QZ = null;
const Q_STATUS = {offen: "offen", laeuft: "läuft – Ergebnis melden", erledigt: "erledigt", fehler: "Fehler", uebersprungen: "übersprungen"};
function qSetzen(d) { QZ = d; qZeichnen(); }
function qProfilZeigen() {
  const p = QZ.profil || {};
  $("q-host").value = p.host || ""; $("q-port").value = p.port || 22; $("q-benutzer").value = p.benutzer || "";
  $("q-ordner").value = p.programmordner || ""; $("q-adresse").value = p.adresse || ""; $("q-bin").value = p.bin_ordner || "";
  $("q-compose").value = p.compose || "plugin";
  $("q-quelle").innerHTML = '<option value="">– bitte wählen –</option>' + (QZ.quellen || []).map(x =>
    `<option value="${esc(x.id)}">${esc(x.name)} (${esc(x.repo)})</option>`).join("");
  $("q-quelle").value = p.quelle || "";
}
function qZeichnen() {
  if (!QZ) return;
  const laeuft = !!QZ.lauf, nur = $("q-nur").checked;
  if (!$("q-ablauf").options.length) $("q-ablauf").innerHTML = Object.entries(QZ.ablaeufe).map(([k, t]) => `<option value="${esc(k)}">${esc(t)}</option>`).join("");
  $("q-ablauf").value = QZ.ablauf; $("q-ablauf").disabled = laeuft;
  ["q-host", "q-port", "q-benutzer", "q-ordner", "q-adresse", "q-bin", "q-compose", "q-quelle", "q-speichern"].forEach(id => $(id).disabled = laeuft);
  $("q-beginnen").disabled = laeuft || !QZ.profil; $("q-abbrechen").disabled = !laeuft;
  $("q-vergessen").classList.toggle("versteckt", !QZ.alt || laeuft);
  $("q-info").innerHTML = (QZ.alt ? `Beiseitegelegter alter Ordner: <span class="mono">${esc(QZ.alt)}</span> (Rückweg möglich). ` : "")
    + `Protokoll: <span class="mono">${esc(QZ.protokoll)}</span>`;
  const idx = laeuft ? QZ.lauf.index : -1;
  $("q-schritte").innerHTML = QZ.schritte.map(s => {
    const aktiv = laeuft && s.nr === idx && !nur, st = s.status;
    const marke = st === "erledigt" ? "gut" : (st === "fehler" ? "schlecht" : "");
    let h = `<div class="karte" id="qs-${s.nr}" style="${laeuft && s.nr === idx ? "border-color:var(--akzent)" : ""}">
      <h2>${s.nr + 1}. ${esc(s.titel)}${s.optional ? " <span class=\"marke\">optional</span>" : ""} <span class="marke ${marke}">${esc(Q_STATUS[st] || st)}</span></h2>
      <ul>${s.erklaerung.map(t => `<li>${esc(t)}</li>`).join("")}</ul>
      <div class="hinweis" style="margin-top:6px"><b>Was du sehen solltest:</b> ${esc(s.erwartet)}</div>`;
    if (s.befehl) h += `<div class="zeile" style="margin-top:8px"><div class="mono karte" style="margin:0;padding:8px">${esc(s.befehl)}</div>
      <button class="zweit" data-qkopie="${s.nr}">Kopieren</button></div>`;
    if (s.id === "version" && QZ.lauf && QZ.lauf.paket) {
      const k = QZ.lauf.paket;
      h += `<div class="status ok">✅ ${esc(k.tag)} – Signatur gültig (${k.signiert} signierte Dateien), Commit <span class="mono">${esc(k.commit.slice(0, 7))}</span>,
        ZIP-Prüfsumme <span class="mono">${esc(k.sha256)}</span>.<details style="margin-top:6px"><summary>${k.unsigniert_anzahl} Dateien nicht von der Signatur erfasst
        (aus demselben Tag-Commit)</summary><div class="mono hinweis">${k.unsigniert.map(esc).join("<br>")}</div></details></div>`;
    }
    if (s.fehler.length) h += `<details ${st === "fehler" ? "open" : ""} style="margin-top:8px"><summary class="hinweis">Typische Fehler und Abhilfe</summary><ul>`
      + s.fehler.map(f => `<li><span class="mono">${esc(f[0])}</span> – ${esc(f[1])}</li>`).join("") + "</ul></details>";
    if (aktiv) {
      h += `<div style="margin-top:10px;border-top:1px solid var(--rand);padding-top:10px">`;
      if (s.art === "lokal") h += `<div class="zeile"><div><label for="q-tag">Version (signierter Tag)</label><select id="q-tag"><option value="">– erst „Versionen laden“ –</option></select></div>
        <button class="zweit" id="q-tags">Versionen laden</button></div>`;
      if (s.bestaetigung === "veranstaltung") h += `<div class="status fehler" style="display:block">⚠️ Nicht am Tag vor oder am Veranstaltungstag!
        Ab diesem Schritt ist das Dashboard einige Minuten nicht erreichbar.<label style="display:flex;gap:8px;align-items:center">
        <input type="checkbox" id="q-veranst" style="width:auto"> Heute ist weder der Tag vor noch der Tag einer Veranstaltung.</label></div>`;
      if (s.bestaetigung === "name" || s.bestaetigung === "alt") h += `<label for="q-name">Zur Sicherheit den Namen abtippen: <span class="mono">${esc(s.bestaetigung === "name" ? QZ.name : QZ.alt)}</span></label>
        <input id="q-name" autocomplete="off">`;
      if (s.art !== "anleitung" && st !== "laeuft") h += `<div class="zeile" style="margin-top:10px"><button data-qlos="${s.nr}">${s.art === "lokal" ? "Laden und prüfen" : "Im SSH-Fenster ausführen"}</button>
        ${s.optional ? `<button class="zweit" data-qmeld="uebersprungen">Überspringen</button>` : ""}</div>`;
      if (s.art === "anleitung" || st === "laeuft") {
        if (s.rueckfrage === "root") h += `<label for="q-root">Ist der Benutzer root (Zahl nach „Verbindung-OK“ ist 0)?</label><select id="q-root">
          <option value="">– bitte wählen –</option><option value="ja">ja (0) – ohne sudo</option><option value="nein">nein – mit sudo</option></select>`;
        if (s.rueckfrage === "compose") h += `<label for="q-variante">Welche Variante hat eine Version gemeldet?</label><select id="q-variante">
          <option value="">– bitte wählen –</option><option value="plugin">docker compose</option><option value="standalone">docker-compose</option></select>`;
        h += `<div class="zeile" style="margin-top:10px"><button data-qmeld="geklappt">Hat geklappt</button>
          ${s.art !== "anleitung" ? `<button class="zweit" data-qmeld="fehler">Fehler – Hilfe anzeigen</button>` : ""}
          ${s.art !== "anleitung" ? `<button class="zweit" data-qlos="${s.nr}">Noch einmal ausführen</button>` : ""}
          ${s.optional ? `<button class="zweit" data-qmeld="uebersprungen">Überspringen</button>` : ""}</div>`;
      }
      h += `<div class="status" id="q-sstatus"></div></div>`;
    }
    return h + "</div>";
  }).join("");
  document.querySelectorAll("[data-qkopie]").forEach(b => b.onclick = () => {
    const s = QZ.schritte[+b.dataset.qkopie];
    navigator.clipboard.writeText(s.befehl).then(() => { b.textContent = "Kopiert ✓"; setTimeout(() => b.textContent = "Kopieren", 1500); });
  });
  if ($("q-tags")) $("q-tags").onclick = e => mit("q-sstatus", e.target, "Frage GitHub …", async () => {
    const d = await api("qnap_versionen");
    $("q-tag").innerHTML = d.versionen.length ? d.versionen.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join("") : '<option value="">– keine Tags gefunden –</option>';
    status("q-sstatus", "ok", "✅ " + d.versionen.length + " Versionen. Die neueste ist vorausgewählt."); });
  document.querySelectorAll("[data-qlos]").forEach(b => b.onclick = () => qAusfuehren(QZ.schritte[+b.dataset.qlos], b));
  document.querySelectorAll("[data-qmeld]").forEach(b => b.onclick = () => qMelden(QZ.schritte[idx], b.dataset.qmeld, b));
}
async function qAusfuehren(s, knopf) {
  const extra = {schritt: s.id, bestaetigt: true};
  if ($("q-veranst")) extra.veranstaltung = $("q-veranst").checked;
  if ($("q-name")) extra.name = $("q-name").value;
  if ($("q-tag")) extra.tag = $("q-tag").value;
  mit("q-sstatus", knopf, s.art === "lokal" ? "Lade und prüfe … (kann eine Minute dauern)" : "Bereite vor …", async () => {
    if (s.art === "lokal" && !extra.tag) throw new Error("Bitte erst „Versionen laden“ und eine Version wählen.");
    const v = await api("qnap_vorbereiten", {schritt: s.id});
    const text = s.art === "lokal" ? `${extra.tag} von GitHub laden, Signatur prüfen und ZIP bauen?`
      : `Dieser Befehl wird jetzt in einem neuen Konsolenfenster gestartet:\n\n${v.zeile}\n\nPasswort bzw. Host-Schlüssel bestätigst du dort selbst. Starten?`;
    if (!confirm(text)) return status("q-sstatus", "laeuft", "Nicht gestartet.");
    const d = await api("qnap_ausfuehren", {...extra, marke: v.marke});
    qSetzen(d);
    status("q-sstatus", "ok", s.art === "lokal" ? "✅ Geprüft. Bitte das Ergebnis oben ansehen und melden."
      : "✅ Fenster geöffnet. Wenn es fertig ist: Ergebnis hier melden (das Fenster kannst du danach schließen).");
  });
}
function qMelden(s, ergebnis, knopf) {
  const extra = {schritt: s.id, ergebnis};
  if ($("q-root")) extra.root = $("q-root").value;
  if ($("q-variante")) extra.compose = $("q-variante").value;
  mit("q-sstatus", knopf, "Speichere …", async () => {
    const d = await api("qnap_rueckmelden", extra); qSetzen(d);
    if (d.fertig) return status("q-status", "ok", "✅ Ablauf abgeschlossen. Alles steht im Protokoll.");
    if (ergebnis === "fehler") return status("q-sstatus", "fehler", "Fehler gemeldet – unter „Typische Fehler und Abhilfe“ nachsehen. Danach den Schritt erneut ausführen oder den Ablauf abbrechen.");
    const n = $("qs-" + d.lauf.index); if (n) n.scrollIntoView({behavior: "smooth", block: "center"});
  });
}
async function qLaden() { try { const a = $("q-ablauf").value; qSetzen(await api("qnap_zustand", a ? {ablauf: a} : {})); qProfilZeigen(); } catch (e) { status("q-status", "fehler", "❌ " + esc(e.message)); } }
$("q-ablauf").onchange = qLaden;
$("q-nur").onchange = qZeichnen;
$("q-speichern").onclick = e => mit("q-pstatus", e.target, "Speichere …", async () => {
  qSetzen(await api("qnap_profil_speichern", {host: $("q-host").value, port: $("q-port").value, benutzer: $("q-benutzer").value,
    programmordner: $("q-ordner").value, adresse: $("q-adresse").value, quelle: $("q-quelle").value, compose: $("q-compose").value,
    bin_ordner: $("q-bin").value}));
  qProfilZeigen(); status("q-pstatus", "ok", "✅ Gespeichert."); });
$("q-beginnen").onclick = e => mit("q-status", e.target, "Beginne …", async () => {
  qSetzen(await api("qnap_beginnen", {ablauf: $("q-ablauf").value}));
  status("q-status", "ok", "✅ Ablauf begonnen – Schritt 1 ist freigegeben."); });
$("q-abbrechen").onclick = e => {
  if (!confirm("Ablauf abbrechen? Bereits ausgeführte Schritte werden nicht rückgängig gemacht (ein beiseitegelegter Ordner bleibt gemerkt).")) return;
  mit("q-status", e.target, "Breche ab …", async () => { qSetzen(await api("qnap_abbrechen")); status("q-status", "ok", "Abgebrochen."); });
};
$("q-vergessen").onclick = e => {
  if (!confirm(`Den gemerkten Ordner „${QZ.alt}“ vergessen? Nur, wenn es ihn auf der QNAP sicher nicht (mehr) gibt – sonst geht der Rückweg verloren.`)) return;
  mit("q-status", e.target, "…", async () => { qSetzen(await api("qnap_alt_vergessen")); status("q-status", "ok", "Vergessen."); });
};
$("q-http").onclick = e => mit("q-status", e.target, "Rufe die Dashboard-Adresse auf …", async () => {
  const d = await api("qnap_http"); status("q-status", d.ok ? "ok" : "fehler", (d.ok ? "✅ " : "❌ ") + esc(d.text)); });
$("q-protokoll").onclick = () => api("ordner_oeffnen", {was: "qnap"}).catch(e => alert(e.message));
document.querySelector('[data-reiter="qnap"]').addEventListener("click", qLaden);
api("update_suchen").then(updateZeigen).catch(() => {});
api("zustand").then(d => { Z = d; zeichnen(); if (!Z.profile.length) document.querySelector('[data-reiter="profile"]').click(); })
  .catch(e => alert(e.message));
</script></body></html>"""


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--selbsttest":
        selbsttest(sys.argv[2])
        return
    threading.Thread(target=_alte_exe_entfernen, daemon=True).start()
    Server().starten(browser="--ohne-browser" not in sys.argv)


if __name__ == "__main__":
    main()
