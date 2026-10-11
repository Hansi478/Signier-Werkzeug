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
%APPDATA%\\Signier-Werkzeug\\schluessel, das GitHub-Token mit Windows-DPAPI
verschlüsselt (nur für diesen Windows-Benutzer lesbar).
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
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROGRAMM = "Signier-Werkzeug"
VERSION = "1.2.0"
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


def daten_ordner():
    basis = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    pfad = os.path.join(basis, PROGRAMM)
    os.makedirs(os.path.join(pfad, "schluessel"), exist_ok=True)
    return pfad


# ---------------------------------------------------------------------------
# Dateiliste, Signieren, Prüfen
# ---------------------------------------------------------------------------
def pruefsumme(pfad):
    with open(pfad, "rb") as f:
        daten = f.read()
    if not pfad.lower().endswith(BINAER) and b"\0" not in daten:
        daten = daten.replace(b"\r\n", b"\n")
    return hashlib.sha256(daten).hexdigest()


def _speedrace_erlaubt(wurzel):
    """Erlaubte Update-Einträge aus der app.py des Ordners (Speedrace-Dashboard)."""
    try:
        quelle = open(os.path.join(wurzel, "app.py"), encoding="utf-8").read()
        dateien = re.findall(r'"([^"]+)"', re.search(r"UPDATE_ALLOWED_FILES = \(([^)]*)\)", quelle).group(1))
        ordner = re.findall(r'"([^"]+)"', re.search(r"UPDATE_ALLOWED_DIRS = \(([^)]*)\)", quelle).group(1))
    except (OSError, AttributeError):
        raise ValueError("Keine app.py des Speedrace-Dashboards in diesem Ordner gefunden.")
    return dateien, ordner


def dateiliste(wurzel, regel="alle", ausschluss=None):
    """{relativer Pfad (mit /): Prüfsumme} der zu signierenden Dateien."""
    out = {}
    if regel == "speedrace":
        dateien, ordner = _speedrace_erlaubt(wurzel)
        for name in sorted(os.listdir(wurzel)):
            pfad = os.path.join(wurzel, name)
            if name == SIGNATUR_DATEI or os.path.islink(pfad):
                continue
            if name in dateien and os.path.isfile(pfad):
                out[name] = pruefsumme(pfad)
            elif name in ordner and os.path.isdir(pfad):
                for root, dirs, files in os.walk(pfad):
                    dirs[:] = sorted(d for d in dirs if d != "__pycache__" and not os.path.islink(os.path.join(root, d)))
                    for f in sorted(files):
                        voll = os.path.join(root, f)
                        if f.endswith(".pyc") or os.path.islink(voll):
                            continue
                        out[os.path.relpath(voll, wurzel).replace(os.sep, "/")] = pruefsumme(voll)
        return out
    muster = STANDARD_AUSSCHLUSS + [m.strip() for m in (ausschluss or []) if m.strip()]
    for root, dirs, files in os.walk(wurzel):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
        for f in sorted(files):
            voll = os.path.join(root, f)
            rel = os.path.relpath(voll, wurzel).replace(os.sep, "/")
            if os.path.islink(voll) or any(fnmatch.fnmatch(rel, m) or fnmatch.fnmatch(f, m) for m in muster):
                continue
            out[rel] = pruefsumme(voll)
    return out


def nachricht(version, dateien):
    return json.dumps({"format": FORMAT, "version": version, "dateien": dateien},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ordner_version(wurzel):
    try:
        return open(os.path.join(wurzel, "VERSION"), encoding="utf-8").read().strip()[:40]
    except OSError:
        return ""


def privat_laden(pfad, kennwort):
    from cryptography.hazmat.primitives import serialization
    try:
        with open(pfad, "rb") as f:
            return serialization.load_pem_private_key(f.read(), kennwort.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError("Kennwort falsch oder Schlüsseldatei beschädigt.")


def oeffentlich_text(privat):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(privat.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)).decode("ascii")


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
    with open(os.path.join(wurzel, SIGNATUR_DATEI), "w", encoding="utf-8", newline="\n") as f:
        f.write(inhalt)
    return version, len(dateien), inhalt


def pruefen(wurzel, oeffentlich, regel="alle", ausschluss=None):
    """-> {"ok", "version", "anzahl", "abweichend", "fehler"}"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = json.load(open(os.path.join(wurzel, SIGNATUR_DATEI), encoding="utf-8"))
        if sig.get("format") != FORMAT or not isinstance(sig.get("dateien"), dict):
            raise ValueError
    except (OSError, ValueError):
        return {"ok": False, "fehler": "Keine gültige SIGNATUR.json in diesem Ordner."}
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(oeffentlich, validate=True)).verify(
            base64.b64decode(sig.get("signatur") or "", validate=True), nachricht(str(sig.get("version") or ""), sig["dateien"]))
    except (InvalidSignature, ValueError, TypeError):
        return {"ok": False, "version": sig.get("version"), "fehler": "Signatur ungültig (anderer Schlüssel oder verändert)."}
    try:
        ist = dateiliste(wurzel, regel, ausschluss)
    except ValueError as e:
        return {"ok": False, "fehler": str(e)}
    abweichend = sorted(n for n in set(ist) | set(sig["dateien"]) if ist.get(n) != sig["dateien"].get(n))
    return {"ok": not abweichend, "version": sig.get("version"), "anzahl": len(ist), "abweichend": abweichend[:50],
            "fehler": "Diese Dateien passen nicht zur Signatur." if abweichend else ""}


# ---------------------------------------------------------------------------
# Profile und Geheimnisse
# ---------------------------------------------------------------------------
_lock = threading.RLock()


def _profile_datei():
    return os.path.join(daten_ordner(), "profile.json")


def profile_laden():
    try:
        d = json.load(open(_profile_datei(), encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def profile_speichern(d):
    tmp = _profile_datei() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, ensure_ascii=False)
    os.replace(tmp, _profile_datei())


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


def geheim_speichern(text):
    if os.name == "nt":
        return "dpapi:" + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")
    return "klar:" + base64.b64encode(text.encode("utf-8")).decode("ascii")   # nur zum Testen außerhalb von Windows


def geheim_lesen(wert):
    wert = str(wert or "")
    if wert.startswith("dpapi:") and os.name == "nt":
        return _dpapi(base64.b64decode(wert[6:]), False).decode("utf-8")
    if wert.startswith("klar:"):
        return base64.b64decode(wert[5:]).decode("utf-8")
    return ""


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
def _gh(pfad, token, methode="GET", daten=None, roh=False, timeout=60):
    req = urllib.request.Request(GITHUB_API + pfad, method=methode,
                                 data=json.dumps(daten).encode("utf-8") if daten is not None else None,
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": PROGRAMM,
                                          "X-GitHub-Api-Version": "2022-11-28",
                                          **({"Authorization": f"Bearer {token}"} if token else {}),
                                          **({"Content-Type": "application/json"} if daten is not None else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            inhalt = r.read(300 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        meldung = {401: "GitHub-Token ungültig oder abgelaufen.", 403: "Keine Berechtigung (Token braucht „Contents: Read and write“).",
                   404: "Repository oder Zweig nicht gefunden (bei privatem Repository: Token nötig).",
                   409: "GitHub meldet einen Konflikt - bitte erneut versuchen.",
                   422: "GitHub hat die Anfrage abgelehnt."}.get(e.code, f"GitHub-Fehler {e.code}.")
        raise ValueError(meldung)
    except OSError as e:
        raise ValueError(f"GitHub nicht erreichbar ({e.__class__.__name__}).")
    return inhalt if roh else json.loads(inhalt.decode("utf-8") or "{}")


def _zweig_stand(repo, zweig, token):
    d = _gh(f"/repos/{repo}/branches/{urllib.parse.quote(zweig, safe='')}", token)
    return d["commit"]["sha"]


def github_laden(repo, zweig, token, ziel):
    """Stand des Zweigs als Ordner -> (Ordner, Commit)."""
    if not _REPO_RE.match(repo or "") or not _ZWEIG_RE.match(zweig or ""):
        raise ValueError("Repository bitte als „Besitzer/Name“ angeben, Zweig z. B. „main“.")
    stand = _zweig_stand(repo, zweig, token)
    daten = _gh(f"/repos/{repo}/zipball/{stand}", token, roh=True, timeout=300)
    with zipfile.ZipFile(io.BytesIO(daten)) as z:
        for info in z.infolist():
            teile = info.filename.split("/", 1)
            if len(teile) < 2 or not teile[1] or info.is_dir():
                continue
            rel = os.path.normpath(teile[1])
            if rel.startswith("..") or os.path.isabs(rel) or (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue   # kein Ausbruch aus dem Ordner, keine Verknüpfungen
            pfad = os.path.join(ziel, rel)
            os.makedirs(os.path.dirname(pfad), exist_ok=True)
            with z.open(info) as src, open(pfad, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return ziel, stand


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


def github_tag_setzen(repo, token, version, commit):
    """Tag v<Version> auf den signierten Stand setzen (bzw. dorthin
    verschieben) -> Tag-Name oder "". Programme, die Versionen über Tags
    finden (z. B. das Update aus GitHub im Speedrace Dashboard), laden so den
    Stand mit der passenden SIGNATUR.json."""
    if not _TAG_VERSION_RE.match(version or "") or not re.match(r"^[0-9a-f]{40}$", commit or ""):
        return ""
    name = f"v{version}"
    ref = f"/repos/{repo}/git/refs/tags/{urllib.parse.quote(name, safe='')}"
    try:
        vorhanden = _gh(f"/repos/{repo}/git/ref/tags/{urllib.parse.quote(name, safe='')}", token)
    except ValueError:
        vorhanden = None
    if isinstance(vorhanden, dict) and (vorhanden.get("object") or {}).get("sha"):
        if vorhanden["object"]["sha"] != commit:
            _gh(ref, token, "PATCH", {"sha": commit, "force": True})
    else:
        _gh(f"/repos/{repo}/git/refs", token, "POST", {"ref": f"refs/tags/{name}", "sha": commit})
    return name


# ---------------------------------------------------------------------------
# Eigene Versionen: Release signieren und veröffentlichen, Update einspielen
# ---------------------------------------------------------------------------
def _version_tupel(v):
    m = _VERSION_RE.match(str(v or ""))
    return tuple(int(x) for x in m.groups()) if m else None


class _OhneAuthWeiter(urllib.request.HTTPRedirectHandler):
    """Weiterleitung zum Download-Server von GitHub ohne das Token."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        neu = super().redirect_request(req, fp, code, msg, headers, newurl)
        if neu is not None and urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            neu.remove_header("Authorization")
        return neu


def _herunterladen(url, token=None, limit=_EXE_MAX, accept="application/octet-stream"):
    if not url.startswith("https://"):
        raise ValueError("Ungültige Download-Adresse.")
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": PROGRAMM,
                                               **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.build_opener(_OhneAuthWeiter).open(req, timeout=300) as r:
            daten = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise ValueError(f"Download fehlgeschlagen (GitHub-Fehler {e.code}).")
    except OSError as e:
        raise ValueError(f"GitHub nicht erreichbar ({e.__class__.__name__}).")
    if len(daten) > limit:
        raise ValueError("Download zu groß.")
    return daten


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
        assert isinstance(sig, dict) and sig.get("format") == FORMAT
    except (ValueError, UnicodeDecodeError, AssertionError):
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


def _gh_hochladen(release_id, name, daten, token):
    url = (f"https://uploads.github.com/repos/{WERKZEUG_REPO}/releases/{int(release_id)}/assets"
           f"?name={urllib.parse.quote(name)}")
    req = urllib.request.Request(url, data=daten, method="POST", headers={
        "Accept": "application/vnd.github+json", "User-Agent": PROGRAMM, "Authorization": f"Bearer {token}",
        "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read(1024 * 1024)
    except urllib.error.HTTPError as e:
        raise ValueError(f"SIGNATUR.json konnte nicht hochgeladen werden (GitHub-Fehler {e.code}).")
    except OSError as e:
        raise ValueError(f"GitHub nicht erreichbar ({e.__class__.__name__}).")


def werkzeug_veroeffentlichen(profil, kennwort, token):
    """Entwurf laden, prüfen, signieren, SIGNATUR.json anhängen, veröffentlichen."""
    privat = privat_laden(schluessel_pfad(profil), kennwort)
    if oeffentlich_text(privat) != WERKZEUG_SCHLUESSEL:
        raise ValueError("Dieser Schlüssel passt nicht zum eingebauten Schlüssel des Werkzeugs.")
    rel = werkzeug_entwurf(token)
    version = rel["tag_name"].lstrip("v")
    exe = _herunterladen(_asset(rel, EXE_NAME)["url"], token)
    _exe_plausibel(exe)
    inhalt = werkzeug_signatur_inhalt(privat, version, exe)
    werkzeug_signatur_pruefen(inhalt.encode("utf-8"), exe, version)
    alt = _asset(rel, SIGNATUR_DATEI)
    if alt:
        _gh(f"/repos/{WERKZEUG_REPO}/releases/assets/{int(alt['id'])}", token, "DELETE", roh=True)
    _gh_hochladen(rel["id"], SIGNATUR_DATEI, inhalt.encode("utf-8"), token)
    _gh(f"/repos/{WERKZEUG_REPO}/releases/{int(rel['id'])}", token, "PATCH", {"draft": False, "make_latest": "true"})
    return version, hashlib.sha256(exe).hexdigest()


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
    neu, alt = exe_pfad + ".neu", exe_pfad + ".alt"
    with open(neu, "wb") as f:
        f.write(exe)
    try:
        if os.path.exists(alt):
            os.remove(alt)
        os.replace(exe_pfad, alt)   # laufende exe darf umbenannt, aber nicht überschrieben werden
        try:
            os.replace(neu, exe_pfad)
        except OSError:
            os.replace(alt, exe_pfad)
            raise
    except OSError as e:
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
        if not os.path.exists(alt):
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
    return {"profile": profile, "token": bool(d.get("github_token")), "version": VERSION,
            "daten": daten_ordner(), "alter_schluessel": alt if os.path.isfile(alt) else ""}


def aktion(name, p):
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
            if os.path.isfile(schluessel_pfad(pr)):
                raise ValueError("Das Profil hat schon einen Schlüssel - für einen neuen bitte ein neues Profil anlegen.")
            privat = Ed25519PrivateKey.generate()
            pem = privat.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(kw.encode("utf-8")))
            fd = os.open(schluessel_pfad(pr), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            pr["oeffentlich"] = oeffentlich_text(privat)
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Schlüssel erzeugt. Bitte die Schlüsseldatei zusätzlich sichern (USB-Stick)."}
        if name == "schluessel_import":
            pr = _profil(d, p.get("id"))
            quelle = str(p.get("pfad") or "").strip().strip('"')
            if not os.path.isfile(quelle):
                raise ValueError("Datei nicht gefunden.")
            privat = privat_laden(quelle, str(p.get("kennwort") or ""))
            if os.path.isfile(schluessel_pfad(pr)):
                raise ValueError("Das Profil hat schon einen Schlüssel.")
            shutil.copyfile(quelle, schluessel_pfad(pr))
            pr["oeffentlich"] = oeffentlich_text(privat)
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Schlüssel übernommen. Die ursprüngliche Datei bleibt, wo sie ist."}
        if name == "token_speichern":
            t = str(p.get("token") or "").strip()
            if t and not re.fullmatch(r"[A-Za-z0-9_]{20,255}", t):
                raise ValueError("Das sieht nicht wie ein GitHub-Token aus.")
            d["github_token"] = geheim_speichern(t) if t else ""
            profile_speichern(d)
            return {**_ansicht(d), "meldung": "Token gespeichert (verschlüsselt)." if t else "Token entfernt."}
        if name == "ordner_waehlen":
            return {"pfad": ordner_waehlen()}
        if name == "datei_waehlen":
            return {"pfad": datei_waehlen()}
        if name == "ordner_oeffnen":
            ordner_oeffnen(daten_ordner() if p.get("was") == "daten" else str(p.get("pfad") or ""))
            return {}
        if name == "werkzeug_veroeffentlichen":
            pr = next((x for x in d.get("profile") or [] if x.get("oeffentlich") == WERKZEUG_SCHLUESSEL), None)
            if not pr or not os.path.isfile(schluessel_pfad(pr)):
                raise ValueError("Kein Profil mit dem Schlüssel des Herausgebers (" + WERKZEUG_SCHLUESSEL[:8] + "…) gefunden.")
            pr = dict(pr)
        else:
            pr = _profil(d, p.get("id")) if name not in ("update_suchen", "update_einspielen") else None
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
    if name == "werkzeug_veroeffentlichen":
        if not token:
            raise ValueError("Zum Veröffentlichen wird ein GitHub-Token gebraucht (Reiter „GitHub“).")
        version, summe = werkzeug_veroeffentlichen(pr, str(p.get("kennwort") or ""), token)
        return {"ok": True, "meldung": f"Signier-Werkzeug {version} signiert und veröffentlicht (SHA-256 {summe[:16]}…). "
                                       "Andere Installationen bieten das Update jetzt an."}
        token = geheim_lesen(d.get("github_token"))
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
                    self._senden(400, json.dumps({"fehler": str(e)}, ensure_ascii=False))
                except Exception as e:
                    self._senden(500, json.dumps({"fehler": f"Unerwarteter Fehler: {e.__class__.__name__}: {e}"},
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


def selbsttest(ausgabe):
    """Für den Bau: signiert und prüft einen Testordner, Ergebnis in eine Datei."""
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
        open(ausgabe, "w").write(("OK" if r["ok"] else "FEHLER " + json.dumps(r)) + dp + "\n")


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
.versteckt{display:none !important}ul{margin:6px 0 0 18px;padding:0}
</style></head><body>
<header><h1>🔏 Signier-Werkzeug</h1><div class="rechts"><button id="update-knopf" class="versteckt">Update</button>
Version __VERSION__ <button class="zweit" id="beenden">Beenden</button></div></header>
<div id="update-leiste" class="versteckt" style="padding:10px 20px;background:#1e293b;border-bottom:1px solid var(--rand)"></div>
<main>
<nav><button data-reiter="signieren" class="aktiv">Signieren</button><button data-reiter="pruefen">Prüfen</button>
<button data-reiter="profile">Profile &amp; Schlüssel</button><button data-reiter="github">GitHub</button></nav>

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
  <b>Contents: Read and write</b>. Es wird nur auf diesem Rechner gespeichert, verschlüsselt für deinen Windows-Benutzer.</div>
  <div class="zeile" style="margin-top:10px"><div><label for="g-token">Token</label><input id="g-token" type="password" autocomplete="off" placeholder="github_pat_…"></div>
  <button id="g-speichern">Speichern</button><button class="zweit" id="g-entfernen">Entfernen</button></div>
  <div class="hinweis" id="g-stand" style="margin-top:8px"></div><div class="status" id="g-status"></div></div>
 <div class="karte"><h2>Signier-Werkzeug selbst</h2>
  <div class="hinweis">Updates kommen aus <span class="mono">__REPO__</span> und werden nur mit gültiger Signatur
  (Schlüssel des Herausgebers) eingespielt. Neue Version veröffentlichen: im Repository den Tag setzen (z. B. <span class="mono">v1.2.1</span>),
  warten, bis GitHub unter „Actions“ fertig gebaut hat, dann hier signieren. Erst danach sehen andere Installationen das Update.</div>
  <div class="zeile" style="margin-top:10px"><button class="zweit" id="w-suchen">Nach Update suchen</button>
  <button id="w-veroeff">Neuen Entwurf signieren und veröffentlichen</button></div>
  <div class="status" id="w-status"></div></div>
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
  $("g-stand").textContent = Z.token ? "✓ Ein Token ist gespeichert." : "Noch kein Token gespeichert.";
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
  status("p-status", "fehler", "❌ " + esc(r.fehler || "Nicht gültig.") + (r.abweichend && r.abweichend.length ? "<ul>" + r.abweichend.map(n => `<li class="mono">${esc(n)}</li>`).join("") + "</ul>" : ""));
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
$("w-veroeff").onclick = async e => {
  const kw = await kennwort("Neuesten Entwurf des Signier-Werkzeugs von GitHub laden, signieren und veröffentlichen (Schlüssel des Herausgebers).");
  if (kw === null) return;
  mit("w-status", e.target, "Lade Entwurf, signiere und veröffentliche …", async () => {
    const d = await api("werkzeug_veroeffentlichen", {kennwort: kw}); status("w-status", "ok", "✅ " + esc(d.meldung)); });
};
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
