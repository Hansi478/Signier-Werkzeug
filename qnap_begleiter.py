# -*- coding: utf-8 -*-
"""QNAP-Begleiter: leitet die SSH-Schritte für das Speedrace-Dashboard auf
einem QNAP-NAS an und begleitet sie - Schritt für Schritt, nie als Kette.

Grundsätze (siehe SICHERHEIT.md, Abschnitt „QNAP-Begleiter“):
- Jeder Schritt wird einzeln vorbereitet (Befehl wird angezeigt), erst nach
  ausdrücklicher Bestätigung gestartet und erst nach der Rückmeldung des
  Benutzers („hat geklappt“ / „Fehler“ / „übersprungen“) folgt der nächste.
  Die Reihenfolge prüft der Server, nicht nur die Oberfläche.
- SSH nur über das in Windows eingebaute ssh.exe/scp.exe, je Schritt ein
  eigenes Konsolenfenster. Passwort und Host-Schlüssel bestätigt der Benutzer
  dort selbst - das Werkzeug sieht, speichert und protokolliert kein Passwort
  und legt keine SSH-Schlüssel an.
- Befehle entstehen nur aus festen Vorlagen und geprüften Profilwerten (kein
  Freitext); Pfade stehen immer in einfachen Anführungszeichen.
- Im Elternordner des Programmordners fasst das Werkzeug nur an: den
  Programmordner (nur umbenennen), selbst angelegte „<Name>.alt-…“-,
  „.kaputt-…“- und „.entpacken-…“-Ordner und die selbst hochgeladenen
  „<Name>.signier-JJJJMMTT-hhmm.zip“. Alles andere (z. B. der
  Daten-Ordner) kommt in keinem Befehl vor.

Dieses Modul enthält keine echten Namen, Adressen oder Pfade - nur
Platzhalter. Speichern, Herunterladen und Prüfen übernimmt der Aufrufer
(signier_werkzeug.py) über die übergebenen Funktionen.
"""
import os
import posixpath
import re
import secrets
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOKOLL_DATEI = "qnap-protokoll.txt"
PROTOKOLL_MAX = 512 * 1024          # danach wird nach …txt.1 rotiert

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_BENUTZER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
# Pfade auf der QNAP: absolut, nur diese Zeichen. Leerzeichen sind (anders als
# in der ersten Planung) nicht erlaubt: scp übergibt den Zielpfad bei älteren
# Windows-Versionen ungeschützt an die Shell der QNAP.
_PFAD_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,239}$")
_TAG_RE = re.compile(r"^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ALT_RE = r"\.alt-\d{8}-\d{4}"
# Zeichen, die in keinem Argument der Windows-Befehlszeile vorkommen dürfen
# (cmd.exe: % und ! werden auch in Anführungszeichen ausgewertet)
_WIN_VERBOTEN = re.compile(r'["%!\x00-\x1f\x7f]')

GESPERRTE_NAMEN = ("daten", "container-station-data")
_LOCK = threading.RLock()   # ein Ablauf zur Zeit, auch über mehrere Begleiter-Objekte


# ---------------------------------------------------------------------------
# Eingabeprüfung
# ---------------------------------------------------------------------------
def host_pruefen(wert):
    h = str(wert or "").strip()
    if not _HOST_RE.match(h) or ".." in h:
        raise ValueError("Host bzw. IP: nur Buchstaben, Ziffern, Punkt, Bindestrich und Doppelpunkt "
                         "(nicht mit einem Zeichen wie „-“ beginnend).")
    return h


def port_pruefen(wert):
    try:
        p = int(str(wert if wert not in (None, "") else 22).strip())
    except ValueError:
        raise ValueError("Port: bitte eine Zahl (Vorgabe 22).") from None
    if not 1 <= p <= 65535:
        raise ValueError("Port: 1 bis 65535.")
    return p


def benutzer_pruefen(wert):
    b = str(wert or "").strip()
    if not _BENUTZER_RE.match(b):
        raise ValueError("Benutzer: nur Buchstaben, Ziffern, „.“, „_“ und „-“ (nicht mit „-“ oder „.“ beginnend).")
    return b


def pfad_pruefen(wert, was="Pfad", mindestens=1):
    """Absoluter Pfad auf der QNAP; nichts, was eine Shell anders auslegen
    könnte. `mindestens`: so viele Ordnerebenen muss er haben."""
    p = str(wert or "").strip()
    if not _PFAD_RE.match(p):
        raise ValueError(f"{was}: absolut (beginnt mit /), nur Buchstaben, Ziffern, „.“, „_“, „-“ und „/“ "
                         "- keine Leerzeichen, Anführungszeichen oder Sonderzeichen.")
    teile = p.split("/")[1:]
    if p.endswith("/") or "//" in p or any(t in ("", ".", "..") or t.startswith("-") for t in teile) \
            or posixpath.normpath(p) != p:
        raise ValueError(f"{was}: ohne „..“, „.“, doppelte „/“ oder „/“ am Ende, kein Teil darf mit „-“ beginnen.")
    if len(teile) < mindestens:
        raise ValueError(f"{was}: bitte den vollständigen Pfad angeben (mindestens {mindestens} Ordnerebenen).")
    return p


def programmordner_pruefen(wert):
    p = pfad_pruefen(wert, "Programmordner", 2)
    name = posixpath.basename(p)
    if name.casefold() in GESPERRTE_NAMEN or name.startswith(".") or re.search(_ALT_RE + "$", name) \
            or re.search(r"\.(kaputt|entpacken)-\d{8}-\d{4,6}$", name):
        raise ValueError(f"„{name}“ kann nicht der Programmordner sein.")
    return p


def adresse_pruefen(wert):
    """Dashboard-Adresse (optional) - nur http/https, ohne Benutzer/Kennwort."""
    a = str(wert or "").strip()
    if not a:
        return ""
    t = urllib.parse.urlsplit(a)
    try:
        t.port
    except ValueError:
        raise ValueError("Dashboard-Adresse: ungültiger Port.") from None
    if t.scheme not in ("http", "https") or not t.hostname or t.username or t.password \
            or any(ord(c) < 33 for c in a) or len(a) > 300:
        raise ValueError("Dashboard-Adresse: z. B. http://192.0.2.10:8090 (nur http/https, ohne Zugangsdaten).")
    return a


def profil_pruefen(p, quellen=()):
    """Eingaben des Formulars -> geprüftes QNAP-Profil (ValueError sonst)."""
    quelle = str(p.get("quelle") or "")
    if quelle and quelle not in quellen:
        raise ValueError("Das gewählte Signier-Profil gibt es nicht (oder es hat kein GitHub-Repository).")
    root = p.get("root")
    return {
        "host": host_pruefen(p.get("host")),
        "port": port_pruefen(p.get("port")),
        "benutzer": benutzer_pruefen(p.get("benutzer")),
        "programmordner": programmordner_pruefen(p.get("programmordner")),
        "adresse": adresse_pruefen(p.get("adresse")),
        "quelle": quelle,
        "bin_ordner": pfad_pruefen(p.get("bin_ordner"), "Ordner der Docker-Programme") if p.get("bin_ordner") else "",
        "compose": "standalone" if p.get("compose") == "standalone" else "plugin",
        "root": True if root in (True, "ja") else False if root in (False, "nein") else None,
    }


# ---------------------------------------------------------------------------
# Befehlsbau
# ---------------------------------------------------------------------------
def q(s):
    """In einfache Anführungszeichen (die Werte sind vorher geprüft)."""
    s = str(s)
    if "'" in s or "\n" in s or "\x00" in s:
        raise ValueError("Unzulässiges Zeichen im Befehl.")
    return "'" + s + "'"


def orte(profil):
    """Programmordner, Elternordner, Name, Ziel der ZIP auf der QNAP."""
    p = programmordner_pruefen(profil.get("programmordner"))
    e, name = posixpath.split(p)
    return {"p": p, "e": e, "name": name}


def zip_name(name, jetzt=None):
    """Eigener, eindeutiger Name der hochgeladenen ZIP - nie der einer
    Datei, die der Benutzer selbst angelegt haben könnte (z. B. <Name>.zip)."""
    return name + ".signier-" + time.strftime("%Y%m%d-%H%M", time.localtime(jetzt)) + ".zip"


def _zip_pruefen(o, zipname):
    if not re.fullmatch(re.escape(o["name"]) + r"\.signier-\d{8}-\d{4}\.zip", str(zipname or "")):
        raise ValueError("Unbekannter ZIP-Name.")
    return zipname


def _sudo(profil, roh=False):
    if profil.get("root") is True:
        return ""
    if profil.get("root") is False:
        return "sudo "
    if roh:
        return "[sudo] "
    raise ValueError("Erst Schritt „Verbindung testen“ abschließen (root ja/nein).")


def _docker(profil):
    b = profil.get("bin_ordner") or ""
    return q(b + "/docker") if b else "docker"


def compose(profil, roh=False):
    """z. B. "sudo docker compose" bzw. "'/…/bin/docker-compose'"."""
    b = profil.get("bin_ordner") or ""
    if profil.get("compose") == "standalone":
        dc = q(b + "/docker-compose") if b else "docker-compose"
    else:
        dc = _docker(profil) + " compose"
    return _sudo(profil, roh) + dc


def alt_name(name, jetzt=None):
    return name + ".alt-" + time.strftime("%Y%m%d-%H%M", time.localtime(jetzt))


def _alt_pruefen(o, alt):
    if not alt or not re.fullmatch(re.escape(o["name"]) + _ALT_RE, alt):
        raise ValueError("Kein beiseitegelegter alter Programmordner bekannt.")
    return alt


def _abbruch(text):
    return "echo " + q("ABBRUCH: " + text)


# Befehle je Schritt: f(profil, lauf, zustand, roh) -> Befehl auf der QNAP
def _b_verbindung(pr, lauf, z, roh):
    return "echo Verbindung-OK; id -u; uname -a"


def _b_werkzeuge(pr, lauf, z, roh):
    b = pr.get("bin_ordner") or ""
    extra = f"; ls -la {q(b)}" if b else ""
    return "command -v docker; command -v docker-compose; command -v unzip; " \
           "docker compose version || docker-compose version" + extra


def _b_ordner(pr, lauf, z, roh):
    return f"ls -la {q(orte(pr)['p'])}"


def _b_zustand(pr, lauf, z, roh):
    return f"cd {q(orte(pr)['p'])} && {compose(pr, roh)} ps"


def _b_anhalten(pr, lauf, z, roh):
    return f"cd {q(orte(pr)['p'])} && {compose(pr, roh)} down"


def _b_beiseite(pr, lauf, z, roh):
    o = orte(pr)
    alt = lauf.get("geplant_alt") or alt_name(o["name"])
    return (f"cd {q(o['e'])} && if [ -e {q(alt)} ]; then {_abbruch(alt + ' gibt es schon - schon beiseitegelegt')}; "
            f"elif [ -d {q(o['name'])} ]; then {_sudo(pr, roh)}mv -- {q(o['name'])} {q(alt)} && ls -la; "
            f"else {_abbruch(o['name'] + ' fehlt - nichts veraendert')}; fi")


def _b_entpacken(pr, lauf, z, roh):
    o = orte(pr)
    paket = lauf.get("paket") or {}
    summe = paket.get("sha256") or ("<Prüfsumme aus Schritt „Version laden“>" if roh else "")
    zipname = paket.get("zipname") or (o["name"] + ".signier-JJJJMMTT-hhmm.zip" if roh else "")
    if not roh:
        if not _SHA_RE.match(summe):
            raise ValueError("Erst Schritt „Version laden“ abschließen.")
        _zip_pruefen(o, zipname)
    # erst in einen eigenen Zwischenordner, dann umbenennen: bricht unzip ab (z. B. Platte
    # voll), entsteht kein halber Programmordner, aus dem weitergebaut würde
    tmp = lauf.get("geplant_entpacken") or (o["name"] + ".entpacken-JJJJMMTT-hhmmss" if roh else "")
    if not roh and not re.fullmatch(re.escape(o["name"]) + r"\.entpacken-\d{8}-\d{6}", tmp):
        raise ValueError("Schritt neu vorbereiten.")
    return (f"cd {q(o['e'])} && echo {q(summe + '  ' + zipname)} | sha256sum -c - && "
            f"if [ -e {q(o['name'])} ]; then {_abbruch(o['name'] + ' gibt es noch - nichts entpackt')}; "
            f"elif [ -e {q(tmp)} ]; then {_abbruch(tmp + ' gibt es schon - Schritt neu vorbereiten')}; "
            f"else mkdir -- {q(tmp)} && unzip -q -d {q(tmp)} {q(zipname)} && mv -- {q(tmp + '/' + o['name'])} "
            f"{q(o['name'])} && rmdir -- {q(tmp)} && ls -la {q(o['name'])}; fi")


def _alt_oder_platzhalter(o, z, roh):
    alt = z.get("alt") if not roh else (z.get("alt") or o["name"] + ".alt-JJJJMMTT-hhmm")
    return alt if roh else _alt_pruefen(o, alt)


def _b_compose_vergleich(pr, lauf, z, roh):
    # nur lesen: die signierte Fassung (neu) gegen die bisherige auf der QNAP (im …alt-Ordner)
    o = orte(pr)
    alt = _alt_oder_platzhalter(o, z, roh)
    return (f"cd {q(o['e'])} && if diff -u {q(o['name'] + '/docker-compose.yml')} {q(alt + '/docker-compose.yml')}; "
            "then echo GLEICH - naechsten Schritt ueberspringen; else echo UNTERSCHIEDE - siehe oben; fi")


def _b_compose_uebernehmen(pr, lauf, z, roh):
    o = orte(pr)
    alt = _alt_oder_platzhalter(o, z, roh)
    return (f"cd {q(o['e'])} && if [ -d {q(o['name'])} ] && [ -f {q(alt + '/docker-compose.yml')} ]; then "
            f"cp -p -- {q(alt + '/docker-compose.yml')} {q(o['name'] + '/docker-compose.yml')} && "
            f"ls -la {q(o['name'] + '/docker-compose.yml')}; "
            f"else {_abbruch('Programmordner oder bisherige docker-compose.yml fehlt - nichts kopiert')}; fi")


def _b_uebersicht(pr, lauf, z, roh):
    return f"ls -la {q(orte(pr)['e'])}"


def _b_bau_vorpruefung(pr, lauf, z, roh):
    return f"grep -c -- '--bau-pruefen' {q(orte(pr)['p'] + '/app.py')}"


def _pruef_ergebnis(befehl):
    """Bau-Prüfung ausführen; „Ergebnis=…“ nur, wenn sie wirklich lief (eine
    Zeile OK:/HINWEIS:/FEHLER:). Sonst wäre z. B. sudo mit falschem Kennwort
    oder „service is not running“ (Rückgabe 1) nicht von „Hinweise“ zu
    unterscheiden."""
    return ("t=$(mktemp) && { { " + befehl + " 2>&1; echo rc=$?; } | tee $t; "
            "if grep -q -E '^(OK|HINWEIS|FEHLER): ' $t; then echo Ergebnis=$(sed -n 's/^rc=//p' $t); "
            "else echo Ergebnis fehlt - keine Pruefung gelaufen, Fehler melden; fi; rm -f $t; }")


def _b_bau_pruefen(pr, lauf, z, roh):
    # Container läuft („Nur neu bauen“): im laufenden Container prüfen
    return f"cd {q(orte(pr)['p'])} && " + _pruef_ergebnis(f"{compose(pr, roh)} exec dashboard python app.py --bau-pruefen")


def _b_bau_pruefen_run(pr, lauf, z, roh):
    # Container angehalten („Neue Version installieren“): einmalig starten, nur die Prüfung
    return f"cd {q(orte(pr)['p'])} && " + _pruef_ergebnis(
        f"{compose(pr, roh)} run --rm --no-deps --entrypoint python dashboard app.py --bau-pruefen")


def _b_bauen(pr, lauf, z, roh):
    return f"cd {q(orte(pr)['p'])} && {compose(pr, roh)} build --no-cache"


def _b_starten(pr, lauf, z, roh):
    return f"cd {q(orte(pr)['p'])} && {compose(pr, roh)} up -d"


def _b_kontrolle(pr, lauf, z, roh):
    dc = compose(pr, roh)
    return f"cd {q(orte(pr)['p'])} && {dc} ps && {dc} logs --tail 60"


def _b_alt_loeschen(pr, lauf, z, roh):
    o = orte(pr)
    alt = z.get("alt") if not roh else (z.get("alt") or o["name"] + ".alt-JJJJMMTT-hhmm")
    if not roh:
        _alt_pruefen(o, alt)
    # nie die einzige Kopie löschen: der Programmordner muss da sein
    return (f"cd {q(o['e'])} && if [ -d {q(o['name'])} ] && [ -d {q(alt)} ]; then "
            f"{_sudo(pr, roh)}rm -r -- {q(alt)} && ls -la; "
            f"elif [ -d {q(o['name'])} ]; then {_abbruch(alt + ' gibt es nicht - nichts geloescht')}; "
            f"else {_abbruch(o['name'] + ' fehlt - der alte Ordner ist die einzige Kopie, nichts geloescht')}; fi")


def _b_zip_loeschen(pr, lauf, z, roh):
    o = orte(pr)
    zips = list(z.get("zips") or [])
    if roh and not zips:
        zips = [o["name"] + ".signier-JJJJMMTT-hhmm.zip"]
    if not zips:
        raise ValueError("Es ist keine vom Werkzeug hochgeladene ZIP bekannt - Schritt überspringen.")
    for n in zips if not roh else []:
        _zip_pruefen(o, n)
    # je Datei nur, wenn es sie gibt (scp kann gescheitert sein, bevor sie entstand)
    return f"cd {q(o['e'])} && " + "".join(f"if [ -e {q(n)} ]; then rm -- {q(n)}; fi; " for n in zips) + "ls -la"


def _b_images(pr, lauf, z, roh):
    return f"{_sudo(pr, roh)}{_docker(pr)} image prune -f"


def _b_wegstellen(pr, lauf, z, roh):
    o = orte(pr)
    kaputt = lauf.get("geplant_kaputt") or o["name"] + ".kaputt-" + time.strftime("%Y%m%d-%H%M")
    alt = z.get("alt") if not roh else (z.get("alt") or o["name"] + ".alt-JJJJMMTT-hhmm")
    if not roh:
        _alt_pruefen(o, alt)
    # nur wegstellen, wenn der Rückweg wirklich da ist
    return (f"cd {q(o['e'])} && if [ -e {q(kaputt)} ]; then {_abbruch(kaputt + ' gibt es schon')}; "
            f"elif [ -d {q(alt)} ]; then {_sudo(pr, roh)}mv -- {q(o['name'])} {q(kaputt)} && ls -la; "
            f"else {_abbruch(alt + ' gibt es nicht - nichts veraendert')}; fi")


def _b_zurueckholen(pr, lauf, z, roh):
    o = orte(pr)
    alt = z.get("alt") if not roh else (z.get("alt") or o["name"] + ".alt-JJJJMMTT-hhmm")
    if not roh:
        _alt_pruefen(o, alt)
    return (f"cd {q(o['e'])} && if [ -e {q(o['name'])} ]; then {_abbruch(o['name'] + ' gibt es noch')}; "
            f"elif [ -d {q(alt)} ]; then {_sudo(pr, roh)}mv -- {q(alt)} {q(o['name'])} && ls -la; "
            f"else {_abbruch(alt + ' gibt es nicht - nichts veraendert')}; fi")


# ---------------------------------------------------------------------------
# Die Schritte (feste Liste; Texte in einfachen Worten)
# ---------------------------------------------------------------------------
_SSH_FEHLER = [
    ("Connection refused / timed out", "SSH ist in QTS nicht eingeschaltet, Host oder Port falsch, oder der Rechner ist nicht im selben Netz."),
    ("Permission denied", "Benutzer oder Passwort falsch. Nur Benutzer der Gruppe „administrators“ dürfen per SSH."),
    ("REMOTE HOST IDENTIFICATION HAS CHANGED", "Der Host-Schlüssel der QNAP hat sich geändert. Nicht weitermachen, "
     "bis geklärt ist, warum (z. B. QNAP neu eingerichtet). Erst dann den alten Eintrag aus "
     "%USERPROFILE%\\.ssh\\known_hosts entfernen."),
    ("ssh: Could not resolve hostname", "Den Namen kennt das Netz nicht - die IP-Adresse der QNAP eintragen."),
]
_SUDO_FEHLER = [
    ("sudo: command not found / not in the sudoers file", "Der Benutzer ist kein Admin, oder er ist root und braucht kein sudo "
     "(in Schritt „Verbindung testen“ dann „root: ja“ wählen und den Ablauf neu beginnen)."),
    ("docker: command not found (nur mit sudo)", "sudo kennt den Pfad der Container Station nicht: im Profil "
     "„Ordner der Docker-Programme“ eintragen (siehe Schritt „Docker finden“)."),
]
_COMPOSE_FEHLER = [
    ("no configuration file provided / Can't find a suitable configuration file", "Falscher Programmordner - "
     "docker-compose.yml fehlt. Nicht weitermachen, Profil prüfen."),
    ("unknown command \"compose\" / docker-compose: not found", "Andere Docker-Variante: im Profil „docker-compose“ "
     "bzw. „docker compose“ wählen."),
]

SCHRITTE = {
    "vorbereitung": {
        "titel": "Vorbereitung prüfen", "art": "anleitung",
        "erklaerung": [
            "In QTS SSH einschalten: Systemsteuerung → Netzwerk- & Dateidienste → Telnet/SSH → „SSH-Verbindung zulassen“ (Port merken).",
            "Unter Windows 11 kopiert scp über SFTP: in QTS zusätzlich „SFTP aktivieren“ einschalten (gleiche Seite bzw. "
            "Win/Mac/NFS/WebDAV → SFTP), sonst meldet das Hochladen „subsystem request failed“.",
            "Mit einem Admin-Benutzer anmelden (Gruppe „administrators“). Das Passwort tippst du später selbst im Konsolenfenster - das Werkzeug sieht es nicht.",
            "Beim ersten Verbinden fragt ssh: „The authenticity of host … can't be established … fingerprint is SHA256:…“. Das ist der "
            "Fingerabdruck des Host-Schlüssels der QNAP: Mit „yes“ merkt sich Windows ihn (in %USERPROFILE%\\.ssh\\known_hosts) und "
            "warnt künftig, falls sich am anderen Ende ein anderes Gerät meldet.",
            "Vergleichen kannst du ihn, wenn du schon einmal auf anderem Weg auf der QNAP angemeldet bist (z. B. an einem Rechner, der "
            "ihn schon kennt): dort „ssh-keygen -lf“ auf die Datei des Host-Schlüssels (bei QNAP meist unter /etc/config/ssh/, Endung .pub). "
            "Im eigenen Heimnetz ist das erste „yes“ vertretbar; meldet ssh später „REMOTE HOST IDENTIFICATION HAS CHANGED“, sofort aufhören.",
            "Nicht am Tag vor oder am Veranstaltungstag umbauen.",
        ],
        "erwartet": "Nichts wird ausgeführt - nur lesen und mit „Hat geklappt“ bestätigen.",
        "fehler": [],
    },
    "verbindung": {
        "titel": "Verbindung testen", "art": "ssh", "befehl": _b_verbindung, "rueckfrage": "root",
        "erklaerung": ["Zeigt, ob die Anmeldung klappt und ob der Benutzer root ist (Zahl nach „Verbindung-OK“: 0 = root).",
                       "Auf der QNAP ist der Admin oft root - dann ist kein sudo nötig. Sonst stellt das Werkzeug den "
                       "folgenden Befehlen „sudo“ voran (sudo fragt im Fenster nach deinem Passwort)."],
        "erwartet": "„Verbindung-OK“, darunter eine Zahl und eine Zeile mit „Linux …“. Danach unten angeben: root ja oder nein.",
        "fehler": _SSH_FEHLER,
    },
    "werkzeuge": {
        "titel": "Docker finden", "art": "ssh", "befehl": _b_werkzeuge, "rueckfrage": "compose",
        "erklaerung": ["Docker gehört auf der QNAP zur Container Station - je nach Version als „docker compose“ oder als „docker-compose“.",
                       "unzip wird zum Entpacken einer neuen Version gebraucht."],
        "erwartet": "Pfade zu docker (und ggf. docker-compose, unzip) und eine Versionszeile „Docker Compose version …“. "
                    "Danach unten die passende Variante wählen.",
        "fehler": [("command not found / keine Ausgabe für docker", "Container Station installiert? Die Programme liegen z. B. unter "
                    "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/ - diesen Ordner im Profil unter „Ordner der Docker-Programme“ eintragen."),
                   ("keine Ausgabe für unzip", "Ohne unzip kann keine neue Version entpackt werden - dann nur „Nur neu bauen“ verwenden.")]
        + _SSH_FEHLER,
    },
    "version": {
        "titel": "Version laden und prüfen", "art": "lokal",
        "erklaerung": ["Das Werkzeug lädt die gewählte Version (Tag v…) von GitHub, prüft die Signatur mit deinem öffentlichen Schlüssel "
                       "und baut daraus eine saubere ZIP mit genau einem Ordner (Name des Programmordners). Noch nichts geht zur QNAP.",
                       "Dockerfile, docker-compose.yml und tools/ deckt ab Dashboard 1.8.8 die Bau-Signatur (SIGNATUR-BAU.json) "
                       "ab - jede Abweichung im Tag heißt „nicht installieren“. In die ZIP kommen nur signierte Dateien; "
                       "alles andere listet das Werkzeug als „nicht übernommen“ auf (Ausnahme: Versionen vor 1.8.8 ohne "
                       "Bau-Signatur - deren Bau-Dateien kommen unsigniert mit, sonst ließe sich nicht bauen)."],
        "erwartet": "„Signatur gültig“, Version, Commit und die Prüfsumme der ZIP.",
        "fehler": [("Signatur ungültig / Dateien passen nicht", "Nicht installieren. Die Version auf GitHub ist nicht so, wie du sie signiert hast."),
                   ("Kein Token / 404", "Im Reiter „GitHub“ ein Token mit Lesezugriff auf das Repository speichern.")],
    },
    "hochladen": {
        "titel": "ZIP auf die QNAP hochladen", "art": "scp",
        "erklaerung": ["scp (in Windows eingebaut) kopiert die geprüfte ZIP in den Elternordner des Programmordners. "
                       "Das Passwort tippst du im Fenster."],
        "erwartet": "Eine Fortschrittszeile mit 100 %.",
        "fehler": [("Permission denied (beim Kopieren)", "Der Benutzer darf im Elternordner nicht schreiben."),
                   ("subsystem request failed / Connection closed", "scp nutzt unter Windows 11 SFTP: in QTS „SFTP "
                    "aktivieren“ einschalten und den Schritt wiederholen."),
                   ("No such file or directory", "Elternordner falsch - Programmordner im Profil prüfen.")] + _SSH_FEHLER,
    },
    "ordner": {
        "titel": "Programmordner prüfen", "art": "ssh", "befehl": _b_ordner,
        "erklaerung": ["Ist es der richtige Ordner? Erwartet werden u. a. docker-compose.yml, Dockerfile und app.py."],
        "erwartet": "Liste mit docker-compose.yml, Dockerfile, app.py. Fehlt docker-compose.yml: nicht weitermachen (Fehler melden).",
        "fehler": [("No such file or directory", "Pfad im Profil falsch. Bei „Neue Version installieren“: fehlt der Ordner, "
                    "weil er schon beiseitegelegt ist, „Zur vorigen Version zurück“ verwenden.")] + _SSH_FEHLER,
    },
    "zustand": {
        "titel": "Laufenden Zustand anzeigen", "art": "ssh", "befehl": _b_zustand,
        "erklaerung": ["Zeigt den Container vor der Änderung - zum Vergleich mit der Kontrolle am Ende."],
        "erwartet": "Eine Zeile mit dem Container, Status „Up …“ bzw. „running“.",
        "fehler": _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "anhalten": {
        "titel": "Container anhalten", "art": "ssh", "befehl": _b_anhalten, "bestaetigung": "veranstaltung",
        "erklaerung": ["Hält das Dashboard an und entfernt den Container. Ab hier ist das Dashboard nicht erreichbar, "
                       "bis Schritt „Starten“ durch ist. Die Daten liegen neben dem Programmordner und bleiben erhalten."],
        "erwartet": "„Container … Stopped / Removed“.",
        "fehler": _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "beiseite": {
        "titel": "Alten Programmordner beiseitelegen", "art": "ssh", "befehl": _b_beiseite, "bestaetigung": "name",
        "erklaerung": ["Benennt den Programmordner um (…alt-Datum-Uhrzeit), statt ihn zu löschen. So geht es mit "
                       "„Zur vorigen Version zurück“ jederzeit zurück. Gelöscht wird er erst am Ende, wenn alles läuft.",
                       "Zur Sicherheit den Namen des Programmordners abtippen."],
        "erwartet": "Ordnerliste, darin der Ordner mit „.alt-…“, der Programmordner fehlt.",
        "fehler": [("ABBRUCH: … gibt es schon - schon beiseitegelegt", "Der Ordner wurde schon umbenannt (z. B. beim ersten "
                    "Ausführen). In der Liste nachsehen: Steht dort der …alt-Ordner und fehlt der Programmordner, "
                    "„Hat geklappt“ melden. Der Name bleibt in diesem Ablauf derselbe."),
                   ("ABBRUCH: … fehlt - nichts veraendert", "Den Programmordner gibt es nicht (mehr). Nicht weitermachen - "
                    "ist er schon beiseitegelegt, „Zur vorigen Version zurück“ verwenden."),
                   ("Permission denied", "Ohne root: sudo nötig (Schritt „Verbindung testen“: root nein).")] + _SSH_FEHLER,
    },
    "entpacken": {
        "titel": "Neue Version entpacken", "art": "ssh", "befehl": _b_entpacken,
        "erklaerung": ["Prüft zuerst die Prüfsumme der hochgeladenen ZIP, dann entpackt unzip sie in einen eigenen "
                       "Zwischenordner (…entpacken-…) im Elternordner und benennt erst danach den fertigen Ordner um. "
                       "Dabei entsteht genau der Programmordner neu - sonst nichts."],
        "erwartet": "„… OK“ von sha256sum, danach die Liste des neuen Programmordners.",
        "fehler": [("FAILED / sha256sum: WARNING", "Die ZIP auf der QNAP ist nicht die geprüfte. Nicht weitermachen - "
                    "Schritt „Hochladen“ wiederholen."),
                   ("ABBRUCH: … gibt es noch", "Der alte Programmordner ist nicht beiseitegelegt."),
                   ("unzip: not found", "unzip fehlt - „Zur vorigen Version zurück“ verwenden."),
                   ("unzip: … write error / No space left", "Entpacken abgebrochen (z. B. Speicher voll): Der Programmordner "
                    "ist nicht entstanden, nur ein halber Zwischenordner …entpacken-… (wird nicht benutzt, kann von Hand "
                    "gelöscht werden). Platz schaffen und den Schritt wiederholen - oder „Zur vorigen Version zurück“.")],
    },
    "compose_vergleich": {
        "titel": "docker-compose.yml vergleichen", "art": "ssh", "befehl": _b_compose_vergleich,
        "erklaerung": ["Die neue Version bringt die signierte docker-compose.yml mit. Hast du deine auf der QNAP angepasst "
                       "(Port, SR_UPDATE_SCHLUESSEL, SR_UID/SR_GID, „.:/app:ro“), wären diese Änderungen sonst weg - deine "
                       "Fassung liegt nur noch im beiseitegelegten …alt-Ordner.",
                       "Dieser Schritt zeigt nur die Unterschiede (Zeilen mit „-“: signierte Fassung, mit „+“: deine "
                       "bisherige). Es wird nichts verändert."],
        "erwartet": "„GLEICH“: beide gleich - den nächsten Schritt überspringen. „UNTERSCHIEDE“ und darüber die Zeilen: "
                    "prüfen, ob nur deine eigenen Anpassungen abweichen.",
        "fehler": [("No such file or directory", "Eine der beiden Dateien fehlt (z. B. erste Installation ohne eigene "
                    "Fassung) - dann den nächsten Schritt überspringen."),
                   ("diff: not found", "Kein diff auf der QNAP: beide Dateien mit „cat“ ansehen oder den nächsten Schritt "
                    "nur übernehmen, wenn du sicher bist, dass die alte Fassung nur deine Anpassungen enthält.")] + _SSH_FEHLER,
    },
    "compose_uebernehmen": {
        "titel": "Eigene docker-compose.yml übernehmen", "art": "ssh", "befehl": _b_compose_uebernehmen, "optional": True,
        "erklaerung": ["Kopiert deine bisherige docker-compose.yml aus dem …alt-Ordner in den neuen Programmordner - nur, "
                       "wenn der Vergleich ausschließlich deine eigenen Anpassungen zeigt. Bringt die neue Version "
                       "selbst Änderungen an der Datei (Zeilen mit „-“, die du nicht kennst), stattdessen überspringen "
                       "und deine Anpassungen nach der Installation von Hand nachtragen.",
                       "Die Bau-Prüfung meldet danach Ergebnis 1 („docker-compose.yml weicht ab“) - das ist dann gewollt."],
        "erwartet": "Eine Zeile mit docker-compose.yml im neuen Programmordner.",
        "fehler": [("ABBRUCH: … fehlt - nichts kopiert", "Programmordner oder alte Datei gibt es nicht - überspringen.")]
        + _SSH_FEHLER,
    },
    "uebersicht": {
        "titel": "Elternordner ansehen", "art": "ssh", "befehl": _b_uebersicht, "optional": True,
        "erklaerung": ["Zeigt den Elternordner des Programmordners. Übrig gebliebene …kaputt-… (nach einem Rückweg) und "
                       "…entpacken-…-Ordner (nach abgebrochenem Entpacken) räumt das Werkzeug nicht selbst weg - "
                       "jeder ist eine vollständige Programmkopie. Brauchst du sie nicht mehr, von Hand löschen.",
                       "Es wird nichts verändert."],
        "erwartet": "Ordnerliste mit Programmordner und Daten-Ordner.", "fehler": _SSH_FEHLER,
    },
    "bau_vorpruefung": {
        "titel": "Kennt das Programm die Bau-Prüfung?", "art": "ssh", "befehl": _b_bau_vorpruefung,
        "rueckfrage": "treffer",
        "erklaerung": ["Sucht in app.py nach dem Schalter „--bau-pruefen“ (ab Dashboard 1.8.8). Ein älteres Programm "
                       "kennt ihn nicht und würde mit dem unbekannten Schalter das Dashboard starten - deshalb erst nachsehen.",
                       "Es wird nur gesucht, nichts gestartet."],
        "erwartet": "Eine Zahl. 0 = Programm älter als 1.8.8 (Bau-Dateien nicht prüfbar), 1 oder mehr = Prüfung möglich. "
                    "Danach unten angeben, was angezeigt wurde.",
        "fehler": [("No such file or directory", "Programmordner falsch oder app.py fehlt - nicht weitermachen.")] + _SSH_FEHLER,
    },
    "bau_pruefen": {
        "titel": "Bau-Dateien prüfen", "art": "ssh", "befehl": _b_bau_pruefen, "rueckfrage": "bauergebnis",
        "erklaerung": ["Prüft mit dem fest eingebauten Schlüssel des Herausgebers, ob Dockerfile, Startskript, Updatehelfer "
                       "usw. im Programmordner genau der signierten Version entsprechen - bevor daraus ein neues Image "
                       "mit root-Rechten entsteht.",
                       "Der Container läuft dabei weiter; die Prüfung läuft darin („docker compose exec“)."],
        "erwartet": "Eine Zeile „OK: …“, „HINWEIS: …“ oder „FEHLER: …“ und danach „Ergebnis=0“, „=1“ oder „=2“. "
                    "Steht dort „Ergebnis fehlt“ (z. B. „service is not running“, sudo-Kennwort falsch), lief keine "
                    "Prüfung: „Fehler“ melden.",
        "fehler": [("Ergebnis=2 / FEHLER:", "Bau-Dateien aus der signierten Version neu holen, nicht bauen "
                    "(„Neue Version installieren“)."),
                   ("Ergebnis=1 / HINWEIS:", "z. B. docker-compose.yml lokal angepasst oder eine zusätzliche Datei - "
                    "prüfen, ob das gewollt ist. Gebaut wird nur nach ausdrücklicher Bestätigung."),
                   ("service \"dashboard\" is not running", "Der Container läuft nicht - erst starten oder den Ablauf "
                    "„Neue Version installieren“ verwenden.")] + _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "bau_pruefen_run": {
        "titel": "Bau-Dateien prüfen", "art": "ssh", "befehl": _b_bau_pruefen_run, "rueckfrage": "bauergebnis",
        "erklaerung": ["Prüft mit dem fest eingebauten Schlüssel des Herausgebers, ob Dockerfile, Startskript, Updatehelfer "
                       "usw. im Programmordner genau der signierten Version entsprechen - bevor daraus ein neues Image "
                       "mit root-Rechten entsteht.",
                       "Der Container ist angehalten; für die Prüfung startet „docker compose run --rm“ ihn kurz nur mit "
                       "Python (ohne Dashboard) und entfernt ihn danach wieder.",
                       "Gibt es noch gar kein Image (erste Installation), würde compose es vorher aus den noch ungeprüften "
                       "Dateien bauen - dann diesen Schritt nicht ausführen, sondern abbrechen."],
        "erwartet": "Eine Zeile „OK: …“, „HINWEIS: …“ oder „FEHLER: …“ und danach „Ergebnis=0“, „=1“ oder „=2“. "
                    "Steht dort „Ergebnis fehlt“, lief keine Prüfung: „Fehler“ melden.",
        "fehler": [("Ergebnis=2 / FEHLER:", "Bau-Dateien aus der signierten Version neu holen, nicht bauen "
                    "(„Zur vorigen Version zurück“, dann neu installieren)."),
                   ("Ergebnis=1 / HINWEIS:", "z. B. docker-compose.yml lokal angepasst oder eine zusätzliche Datei - "
                    "prüfen, ob das gewollt ist. Gebaut wird nur nach ausdrücklicher Bestätigung."),
                   ("No such image / pull access denied", "Es gibt noch kein Image - dann ist keine Prüfung mit dem "
                    "Programm möglich; „Fehler“ melden und den Ablauf abbrechen.")] + _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "bauen": {
        "titel": "Image neu bauen", "art": "ssh", "befehl": _b_bauen,
        "erklaerung": ["Baut das Image ohne Zwischenspeicher neu: neues Startskript, neuer Updatehelfer, aktuelle Pakete. "
                       "Dauert einige Minuten. Ein laufender Container läuft dabei weiter."],
        "erwartet": "Am Ende „… Built“ bzw. „Successfully built“, keine roten Fehlerzeilen.",
        "fehler": [("Temporary failure in name resolution / Could not resolve", "Kein Internet bzw. DNS auf der QNAP - Netzwerk prüfen."),
                   ("no space left on device", "Speicher voll: „df -h“ ansehen, alte Images entfernen (letzter Schritt)."),
                   ("THESE PACKAGES DO NOT MATCH THE HASHES", "Prüfsummenfehler bei pip: NICHT wiederholen, sondern melden.")]
        + _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "starten": {
        "titel": "Container starten", "art": "ssh", "befehl": _b_starten,
        "erklaerung": ["Startet den Container mit dem neuen Image. Das Dashboard ist danach in etwa 1–3 Minuten wieder erreichbar. "
                       "Die Daten bleiben erhalten."],
        "erwartet": "„Container … Started“.",
        "fehler": [("port is already allocated / address already in use", "Der Port ist belegt (anderer Container oder QTS-Dienst) - "
                    "in docker-compose.yml einen freien Port wählen.")] + _COMPOSE_FEHLER + _SUDO_FEHLER,
    },
    "kontrolle": {
        "titel": "Kontrolle", "art": "ssh", "befehl": _b_kontrolle,
        "erklaerung": ["Zeigt den Container und die letzten 60 Log-Zeilen. Zusätzlich oben „Dashboard-Adresse prüfen“ (ohne SSH).",
                       "Im Dashboard unter Ressourcenmonitor → Systemcheck die Zeilen „Container-Image“ (Baudatum, Version) "
                       "und „Updatehelfer im Image“ ansehen."],
        "erwartet": "Status „Up …“ bzw. „running“, in den Logs Startmeldung und Version.",
        "fehler": [("Restarting / Exited", "Die Logs zeigen den Grund. Bei einer neuen Version: „Zur vorigen Version zurück“.")]
        + _COMPOSE_FEHLER,
    },
    "alt_loeschen": {
        "titel": "Alten Programmordner endgültig löschen", "art": "ssh", "befehl": _b_alt_loeschen, "bestaetigung": "alt",
        "optional": True,
        "erklaerung": ["Erst, wenn die neue Version läuft. Löscht nur den beiseitegelegten …alt-Ordner - danach gibt es kein Zurück.",
                       "Zur Sicherheit den Namen des …alt-Ordners abtippen."],
        "erwartet": "Ordnerliste ohne den …alt-Ordner.",
        "fehler": [("Permission denied", "Ohne root: sudo nötig.")],
    },
    "zip_loeschen": {
        "titel": "Hochgeladene ZIP löschen", "art": "ssh", "befehl": _b_zip_loeschen, "optional": True,
        "erklaerung": ["Entfernt die vom Werkzeug hochgeladene ZIP aus dem Elternordner (andere Dateien bleiben)."],
        "erwartet": "Ordnerliste ohne die ZIP.", "fehler": [],
    },
    "images": {
        "titel": "Alte Images aufräumen", "art": "ssh", "befehl": _b_images, "optional": True,
        "erklaerung": ["Entfernt nur Images, die kein Container mehr benutzt (z. B. das alte nach dem Neubau). Gibt Speicher frei."],
        "erwartet": "„Total reclaimed space: …“.", "fehler": _SUDO_FEHLER,
    },
    "wegstellen": {
        "titel": "Neuen Programmordner wegstellen", "art": "ssh", "befehl": _b_wegstellen, "bestaetigung": "name",
        "optional": True,
        "erklaerung": ["Benennt den (nicht funktionierenden) neuen Programmordner in …kaputt-Datum um. Überspringen, wenn es ihn nicht gibt.",
                       "Zur Sicherheit den Namen des Programmordners abtippen."],
        "erwartet": "Ordnerliste mit „….kaputt-…“, der Programmordner fehlt.", "fehler": _SSH_FEHLER,
    },
    "zurueckholen": {
        "titel": "Alten Programmordner zurückholen", "art": "ssh", "befehl": _b_zurueckholen, "bestaetigung": "alt",
        "erklaerung": ["Benennt den beiseitegelegten …alt-Ordner wieder in den Programmordner um.",
                       "Zur Sicherheit den Namen des …alt-Ordners abtippen."],
        "erwartet": "Ordnerliste mit dem Programmordner, ohne …alt-Ordner.",
        "fehler": [("ABBRUCH: … gibt es noch", "Zuerst „Neuen Programmordner wegstellen“.")] + _SSH_FEHLER,
    },
}

for _sid, _s in SCHRITTE.items():
    _s["id"] = _sid
    _s.setdefault("optional", False)
    _s.setdefault("bestaetigung", None)
    _s.setdefault("rueckfrage", None)

# Abläufe: feste Reihenfolgen. Später kommt hier „Weg A einrichten“ dazu
# (einmalige Einrichtung des Neubau-Skripts auf der QNAP), sobald das
# Gegenstück im Dashboard fertig ist - als weitere Liste, ohne neue Mechanik.
ABLAEUFE = {
    "installieren": {"titel": "Neue Version installieren",
                     "schritte": ["vorbereitung", "verbindung", "werkzeuge", "version", "hochladen", "ordner", "zustand",
                                  "anhalten", "beiseite", "entpacken", "compose_vergleich", "compose_uebernehmen",
                                  "bau_vorpruefung", "bau_pruefen_run", "bauen",
                                  "starten", "kontrolle",
                                  "alt_loeschen", "zip_loeschen", "images"]},
    "neubau": {"titel": "Nur neu bauen (gleiche Version)",
               "schritte": ["vorbereitung", "verbindung", "werkzeuge", "ordner", "zustand", "bau_vorpruefung", "bau_pruefen",
                            "bauen", "starten:warnung",
                            "kontrolle", "images"]},
    "zurueck": {"titel": "Zur vorigen Version zurück",
                "schritte": ["verbindung", "anhalten:optional", "wegstellen", "zurueckholen", "bau_vorpruefung",
                             "bau_pruefen_run", "bauen", "starten", "kontrolle"]},
    "aufraeumen": {"titel": "Aufräumen (alter Ordner, ZIP, Images)",
                   "schritte": ["verbindung", "alt_loeschen", "zip_loeschen", "images", "uebersicht"]},
}


def _optional(s, ablauf, z):
    """Im Rückweg darf „Image neu bauen“ entfallen, wenn die Installation kein
    neues Image gebaut hat (z. B. Bauen ohne Internet gescheitert) - dann passt
    das vorhandene Image noch zur alten Version."""
    return bool(s.get("optional")) or (s["id"] == "bauen" and ablauf == "zurueck" and not z.get("neu_gebaut"))


def _schritte(ablauf):
    """Schritte eines Ablaufs (mit Abwandlungen „:warnung“, „:optional“)."""
    if ablauf not in ABLAEUFE:
        raise ValueError("Unbekannter Ablauf.")
    liste = []
    for eintrag in ABLAEUFE[ablauf]["schritte"]:
        sid, _, abw = eintrag.partition(":")
        s = dict(SCHRITTE[sid])
        if abw == "warnung":
            s["bestaetigung"] = "veranstaltung"
        elif abw == "optional":
            s["optional"] = True
            s["bestaetigung"] = None
        liste.append(s)
    return liste


# ---------------------------------------------------------------------------
# Windows-Befehlszeile (ein Konsolenfenster je Schritt)
# ---------------------------------------------------------------------------
def windows_programme():
    sysroot = os.environ.get("SystemRoot") or r"C:\Windows"
    return {"cmd": os.path.join(sysroot, "System32", "cmd.exe"),
            "ssh": os.path.join(sysroot, "System32", "OpenSSH", "ssh.exe"),
            "scp": os.path.join(sysroot, "System32", "OpenSSH", "scp.exe")}


def _arg(a):
    a = str(a)
    if not a or _WIN_VERBOTEN.search(a) or a.endswith("\\"):
        raise ValueError("Unzulässiges Zeichen in der Befehlszeile (z. B. % ! \" oder ein Zeilenumbruch) - "
                         "Pfad bzw. Profil prüfen.")
    return '"' + a + '"'


def befehlszeile(argv, prog=None):
    """-> (Programm, Befehlszeile) für CreateProcess: cmd.exe /k hält das
    Fenster nach dem Ende offen. Jedes Argument in "…"; cmd entfernt das
    äußere Paar um den ganzen Rest. Zeichen, die cmd auch in Anführungs-
    zeichen auswertet (%, !) oder die das Quoting brechen ("), sind gesperrt."""
    prog = prog or windows_programme()
    innen = " ".join(_arg(a) for a in argv)
    return prog["cmd"], f'{_arg(prog["cmd"])} /d /v:off /k "{innen}"'


def ziel_host(profil):
    h = host_pruefen(profil.get("host"))
    return "[" + h + "]" if ":" in h else h


def ssh_argv(profil, befehl, prog=None):
    prog = prog or windows_programme()
    return [prog["ssh"], "-t", "-p", str(port_pruefen(profil.get("port"))), "--",
            benutzer_pruefen(profil.get("benutzer")) + "@" + host_pruefen(profil.get("host")), befehl]


def scp_argv(profil, lokal, ziel, prog=None):
    prog = prog or windows_programme()
    return [prog["scp"], "-P", str(port_pruefen(profil.get("port"))), "--", lokal,
            benutzer_pruefen(profil.get("benutzer")) + "@" + ziel_host(profil) + ":" + pfad_pruefen(ziel, "Ziel")]


def konsole_starten(programm, zeile, ordner):
    """Startet die Befehlszeile in einem neuen Konsolenfenster (ohne Shell
    dieses Prozesses; das Fenster gehört danach dem Benutzer)."""
    if os.name != "nt":
        raise ValueError("Das SSH-Fenster gibt es nur unter Windows - Befehl bitte kopieren.")
    for pfad in (programm,):
        if not os.path.isfile(pfad):
            raise ValueError(f"{pfad} nicht gefunden.")
    subprocess.Popen(zeile, executable=programm, cwd=ordner, close_fds=True,
                     creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10))


# ---------------------------------------------------------------------------
# Dashboard-Adresse prüfen (ohne SSH)
# ---------------------------------------------------------------------------
class _KeineWeiterleitung(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_pruefen(url, timeout=10):
    """-> Text für die Anzeige. Nur GET, kein Token, keine Weiterleitung,
    kein Proxy; gelesen wird nur der Statuscode."""
    url = adresse_pruefen(url)
    if not url:
        raise ValueError("Im QNAP-Profil ist keine Dashboard-Adresse eingetragen.")
    oeffner = urllib.request.build_opener(urllib.request.ProxyHandler({}), _KeineWeiterleitung())
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Signier-Werkzeug"})
    try:
        with oeffner.open(req, timeout=timeout) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
        e.close()
    except (ssl.SSLError, ssl.CertificateError):
        return {"ok": False, "text": "Antwortet, aber das https-Zertifikat ist nicht gültig (nicht weiter geprüft)."}
    except urllib.error.URLError as e:
        if isinstance(e.reason, (ssl.SSLError, ssl.CertificateError)):
            return {"ok": False, "text": "Antwortet, aber das https-Zertifikat ist nicht gültig (nicht weiter geprüft)."}
        return {"ok": False, "text": f"Keine Antwort ({e.__class__.__name__}) - läuft der Container schon? Etwas warten."}
    except OSError as e:
        return {"ok": False, "text": f"Keine Antwort ({e.__class__.__name__}) - läuft der Container schon? Etwas warten."}
    if code == 200:
        return {"ok": True, "text": "Dashboard antwortet (HTTP 200)."}
    if code in (301, 302, 303, 307, 308):
        return {"ok": True, "text": f"Dashboard antwortet mit einer Weiterleitung (HTTP {code}) - nicht gefolgt."}
    return {"ok": False, "text": f"Dashboard antwortet mit HTTP {code}."}


# ---------------------------------------------------------------------------
# Ablauf (Zustand in qnap.json, Reihenfolge erzwingt der Server)
# ---------------------------------------------------------------------------
class Begleiter:
    """laden() -> dict, speichern(dict): Zustand (qnap.json).
    ordner: Datenordner (Protokoll, ZIP). starter(programm, zeile, ordner).
    paket(profil, tag, name) -> dict: Version laden, prüfen, ZIP bauen."""

    def __init__(self, laden, speichern, ordner, starter=konsole_starten, prog=None, jetzt=time.time):
        self._laden, self._speichern, self.ordner = laden, speichern, ordner
        self.starter, self.prog, self.jetzt = starter, prog, jetzt
        self.lock = _LOCK

    # -- Protokoll: Zeit, Ablauf, Schritt, Ereignis, Befehl (keine Geheimnisse)
    def protokollieren(self, ablauf, schritt, ereignis, befehl=""):
        zeile = "\t".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(x)) for x in (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.jetzt())), ablauf, schritt, ereignis, befehl))
        pfad = os.path.join(self.ordner, PROTOKOLL_DATEI)
        try:
            if os.path.isfile(pfad) and os.path.getsize(pfad) > PROTOKOLL_MAX:
                os.replace(pfad, pfad + ".1")
        except OSError:
            pass
        fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "ab") as f:
            f.write((zeile + "\n").encode("utf-8"))

    def _zustand(self):
        z = self._laden() or {}
        return z if isinstance(z, dict) else {}

    def _profil(self, z):
        pr = z.get("profil")
        if not pr:
            raise ValueError("Bitte zuerst das QNAP-Profil ausfüllen und speichern.")
        return pr

    # -- Anzeige ------------------------------------------------------------
    def ansicht(self, ablauf=None):
        with self.lock:
            z = self._zustand()
            pr, lauf = z.get("profil"), z.get("lauf")
            ablauf = (lauf or {}).get("ablauf") or (ablauf if ablauf in ABLAEUFE else "installieren")
            schritte = []
            for i, s in enumerate(_schritte(ablauf)):
                befehl = ""
                if pr and s.get("befehl"):
                    try:
                        befehl = s["befehl"](pr, lauf or {}, z, True)
                    except ValueError as e:
                        befehl = f"(noch nicht möglich: {e})"
                elif pr and s["art"] == "scp":
                    zn = ((lauf or {}).get("paket") or {}).get("zipname") or orte(pr)["name"] + ".signier-JJJJMMTT-hhmm.zip"
                    befehl = (f"scp -P {pr.get('port')} -- <geprüfte ZIP> "
                              f"{pr.get('benutzer')}@{ziel_host(pr)}:{orte(pr)['e']}/{zn}")
                status = ((lauf or {}).get("status") or {}).get(str(i), "offen") if lauf else "offen"
                schritte.append({k: s.get(k) for k in ("id", "titel", "art", "erklaerung", "erwartet",
                                                       "bestaetigung", "rueckfrage")}
                                | {"optional": _optional(s, ablauf, z)}
                                | ({"erklaerung": s["erklaerung"] + [
                                    "Die Installation hat kein neues Image gebaut: Das vorhandene passt noch zur alten "
                                    "Version - Überspringen ist möglich (z. B. ohne Internet)."]}
                                   if s["id"] == "bauen" and ablauf == "zurueck" and not z.get("neu_gebaut") else {})
                                | {"fehler": [list(f) for f in s["fehler"]], "befehl": befehl, "status": status,
                                   "nr": i})
            o = orte(pr) if pr else {}
            return {"profil": pr, "ablaeufe": {k: v["titel"] for k, v in ABLAEUFE.items()}, "ablauf": ablauf,
                    "lauf": {k: lauf.get(k) for k in ("ablauf", "index", "paket")} if lauf else None,
                    "schritte": schritte, "alt": z.get("alt") or "", "zips": list(z.get("zips") or []),
                    "bau_gesperrt": bool(z.get("bau_gesperrt")),
                    "name": o.get("name", ""), "protokoll": os.path.join(self.ordner, PROTOKOLL_DATEI)}

    # -- Profil -------------------------------------------------------------
    def profil_speichern(self, p, quellen=()):
        with self.lock:
            z = self._zustand()
            if z.get("lauf"):
                raise ValueError("Während ein Ablauf läuft, bleibt das Profil fest - erst abschließen oder abbrechen.")
            neu = profil_pruefen(p, quellen)
            alt = z.get("profil") or {}
            if (z.get("alt") or z.get("zips")) and alt and alt.get("programmordner") != neu["programmordner"]:
                raise ValueError("Der Programmordner bleibt fest, solange ein beiseitegelegter Ordner oder eine "
                                 "hochgeladene ZIP gemerkt ist (sie gehören zu diesem Ordner). Erst „Zur vorigen Version "
                                 "zurück“ bzw. „Aufräumen“ - oder das Gemerkte vergessen.")
            if (z.get("alt") or z.get("zips")) and alt and alt.get("host") != neu["host"]:
                if p.get("gleiches_geraet") is not True:
                    raise ValueError("Die Adresse der QNAP ändern, obwohl noch ein beiseitegelegter Ordner bzw. eine "
                                     "hochgeladene ZIP gemerkt ist? Das geht nur, wenn es dasselbe Gerät unter neuer "
                                     "Adresse ist (bitte bestätigen).")
                self.protokollieren("-", "-", "Adresse geändert (gleiches Gerät bestätigt)",
                                    f"{alt.get('host')} -> {neu['host']}")
            z["profil"] = neu
            self._speichern(z)
            return self.ansicht()

    # -- Ablauf -------------------------------------------------------------
    def beginnen(self, ablauf):
        with self.lock:
            z = self._zustand()
            pr = self._profil(z)
            schritte = _schritte(ablauf)
            if z.get("lauf"):
                raise ValueError("Es läuft schon ein Ablauf - erst abschließen oder abbrechen.")
            if ablauf == "zurueck":
                _alt_pruefen(orte(pr), z.get("alt"))
            if ablauf == "installieren" and z.get("alt"):
                raise ValueError(f"Es liegt noch ein beiseitegelegter Ordner ({z['alt']}). Läuft die neue Version nicht "
                                 "oder fehlt der Programmordner: „Zur vorigen Version zurück“. Nur wenn die neue Version "
                                 "läuft: „Aufräumen“ (alten Ordner endgültig löschen). Sonst ginge der Rückweg verloren.")
            if ablauf == "installieren" and not pr.get("quelle"):
                raise ValueError("Im QNAP-Profil ist kein Signier-Profil (GitHub-Repository) gewählt.")
            pr["root"] = None   # fragt Schritt „Verbindung testen“ jedes Mal neu ab
            z["lauf"] = {"ablauf": ablauf, "index": 0, "status": {}, "marke": None, "geplant": None,
                         "id": secrets.token_hex(8), "schritte": [x["id"] for x in schritte]}
            self._speichern(z)
            self.protokollieren(ablauf, "-", "Ablauf begonnen")
            return self.ansicht()

    def alt_vergessen(self):
        """Nur wenn der gemerkte …alt-Ordner sicher nicht (mehr) existiert -
        z. B. nach einem fehlgeschlagenen Umbenennen."""
        with self.lock:
            z = self._zustand()
            if z.get("lauf"):
                raise ValueError("Erst den laufenden Ablauf abschließen oder abbrechen.")
            alt = z.pop("alt", "")
            self._speichern(z)
            if alt:
                self.protokollieren("-", "-", "gemerkten alten Ordner vergessen", alt)
            return self.ansicht()

    def zips_vergessen(self):
        """Gemerkte hochgeladene ZIPs vergessen (z. B. schon von Hand gelöscht)."""
        with self.lock:
            z = self._zustand()
            if z.get("lauf"):
                raise ValueError("Erst den laufenden Ablauf abschließen oder abbrechen.")
            zips = z.pop("zips", None)
            self._speichern(z)
            if zips:
                self.protokollieren("-", "-", "gemerkte ZIPs vergessen", ", ".join(zips))
            return self.ansicht()

    def sperre_aufheben(self):
        """Bau-Sperre (Ergebnis 2) bewusst aufheben - nur durch den Benutzer,
        z. B. nach dem Neuholen der Bau-Dateien von Hand; wird protokolliert."""
        with self.lock:
            z = self._zustand()
            if z.get("lauf"):
                raise ValueError("Erst den laufenden Ablauf abschließen oder abbrechen.")
            if z.pop("bau_gesperrt", None):
                self._speichern(z)
                self.protokollieren("-", "-", "Bau-Sperre vom Benutzer aufgehoben")
            return self.ansicht()

    def abbrechen(self):
        with self.lock:
            z = self._zustand()
            lauf = z.pop("lauf", None)
            gemerkt = (lauf or {}).get("beiseite_gestartet")
            if gemerkt and not z.get("alt"):
                z["alt"] = gemerkt   # „beiseitelegen“ lief schon: Rückweg nicht vergessen
            self._speichern(z)
            if lauf:
                self.protokollieren(lauf.get("ablauf"), "-", "Ablauf abgebrochen",
                                    f"alter Ordner gemerkt: {gemerkt}" if gemerkt else "")
            return self.ansicht()

    def _aktuell(self, z, schritt_id):
        lauf = z.get("lauf")
        if not lauf:
            raise ValueError("Es läuft kein Ablauf.")
        schritte = _schritte(lauf["ablauf"])
        if lauf.get("schritte") and lauf["schritte"] != [x["id"] for x in schritte]:
            raise ValueError("Der Ablauf hat sich seit dem Beginn geändert (Update des Werkzeugs) - bitte abbrechen und "
                             "neu beginnen.")
        i = lauf["index"]
        if i >= len(schritte):
            raise ValueError("Der Ablauf ist abgeschlossen.")
        s = schritte[i]
        if schritt_id != s["id"]:
            raise ValueError(f"Jetzt ist Schritt „{s['titel']}“ dran - nur einer nach dem anderen.")
        return lauf, s, i

    def _planen(self, z, lauf, s, pr):
        """Befehl genau so festlegen, wie er angezeigt und ausgeführt wird."""
        o = orte(pr)
        if s["id"] == "beiseite":
            # einmal festgelegt, bleibt der Name im Lauf gleich - sonst überschriebe
            # eine Wiederholung den Namen des wirklich umbenannten Ordners
            lauf["geplant_alt"] = lauf.get("beiseite_gestartet") or alt_name(o["name"], self.jetzt())
        if s["id"] == "entpacken":
            lauf["geplant_entpacken"] = o["name"] + ".entpacken-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(self.jetzt()))
        if s["id"] == "wegstellen":
            lauf["geplant_kaputt"] = o["name"] + ".kaputt-" + time.strftime("%Y%m%d-%H%M", time.localtime(self.jetzt()))
        if s["art"] in ("ssh", "scp") and os.name == "nt" and self.prog is None:
            exe = windows_programme()[s["art"]]
            if not os.path.isfile(exe):
                raise ValueError(f"{exe} fehlt - in Windows den „OpenSSH-Client“ einschalten (Einstellungen → System → "
                                 "Optionale Features).")
        if s["art"] == "ssh":
            befehl = s["befehl"](pr, lauf, z, False)
            programm, zeile = befehlszeile(ssh_argv(pr, befehl, self.prog), self.prog)
            return befehl, programm, zeile
        if s["art"] == "scp":
            paket = lauf.get("paket") or {}
            if not paket.get("zip"):
                raise ValueError("Erst Schritt „Version laden und prüfen“ abschließen.")
            # relativ zum Datenordner (dort startet das Fenster): der Pfad mit dem Windows-Benutzernamen
            # (evtl. mit „!“ oder „%“, die cmd.exe auswertet) steht so nicht in der Befehlszeile
            lokal = paket["zip"]
            if os.path.dirname(os.path.dirname(os.path.abspath(lokal))) == os.path.abspath(self.ordner):
                lokal = os.path.relpath(os.path.abspath(lokal), os.path.abspath(self.ordner))
            argv = scp_argv(pr, lokal, o["e"] + "/" + _zip_pruefen(o, paket.get("zipname")), self.prog)
            programm, zeile = befehlszeile(argv, self.prog)
            return f"scp -P {pr['port']} -- {lokal} {argv[-1]}", programm, zeile
        return "", "", ""

    def _erwartet_name(self, s, pr, z):
        if s["bestaetigung"] == "name":
            return orte(pr)["name"]
        if s["bestaetigung"] == "alt":
            return _alt_pruefen(orte(pr), z.get("alt"))
        return None

    def vorbereiten(self, schritt_id):
        """Zeigt den exakten Befehl und gibt eine Einmal-Marke aus, ohne die
        `ausfuehren` nichts startet."""
        with self.lock:
            z = self._zustand()
            pr = self._profil(z)
            lauf, s, i = self._aktuell(z, schritt_id)
            if s["art"] == "anleitung":
                raise ValueError("Dieser Schritt ist nur zum Lesen.")
            if lauf["status"].get(str(i)) == "laedt":
                raise ValueError("Die Version wird gerade geladen und geprüft - bitte warten. (Hängt es nach einem "
                                 "Neustart des Werkzeugs: Ablauf abbrechen und neu beginnen.)")
            if s["id"] == "bauen" and (lauf.get("bau_gesperrt") or z.get("bau_gesperrt")):
                raise ValueError("Neubau gesperrt: Die Bau-Dateien passen nicht zur Signatur (Ergebnis 2). "
                                 "Bau-Dateien aus der signierten Version neu holen, nicht bauen.")
            befehl, programm, zeile = self._planen(z, lauf, s, pr)
            lauf["marke"] = secrets.token_urlsafe(16)
            lauf["geplant"] = {"schritt": s["id"], "befehl": befehl, "programm": programm, "zeile": zeile}
            self._speichern(z)
            return {"schritt": s["id"], "befehl": befehl, "zeile": zeile, "marke": lauf["marke"],
                    "bestaetigung": s["bestaetigung"], "name": self._erwartet_name(s, pr, z)}

    def ausfuehren(self, schritt_id, marke, p, paket=None):
        with self.lock:
            z = self._zustand()
            pr = self._profil(z)
            lauf, s, i = self._aktuell(z, schritt_id)
            geplant = lauf.get("geplant") or {}
            if not marke or not lauf.get("marke") or not secrets.compare_digest(str(marke), lauf["marke"]) \
                    or geplant.get("schritt") != s["id"]:
                raise ValueError("Bitte den Schritt neu vorbereiten und den angezeigten Befehl bestätigen.")
            lauf["marke"] = None   # nur einmal gültig
            self._speichern(z)
            if p.get("bestaetigt") is not True:
                raise ValueError("Ohne ausdrückliche Bestätigung startet nichts.")
            if s["bestaetigung"] == "veranstaltung" and p.get("veranstaltung") is not True:
                raise ValueError("Bitte bestätigen, dass heute weder der Tag vor noch der Tag der Veranstaltung ist.")
            erwartet = self._erwartet_name(s, pr, z)
            if erwartet is not None and str(p.get("name") or "") != erwartet:
                raise ValueError(f"Zur Sicherheit bitte genau „{erwartet}“ abtippen.")
            if s["art"] != "lokal":
                self.starter(geplant["programm"], geplant["zeile"], self.ordner)
                if s["art"] == "scp":   # diese ZIP gehört dem Werkzeug - „ZIP löschen“ darf sie entfernen
                    zn = (lauf.get("paket") or {}).get("zipname")
                    if zn and zn not in (z.get("zips") or []):
                        z["zips"] = list(z.get("zips") or []) + [zn]
                return self._ausgefuehrt(z, lauf, s, i, geplant["befehl"])
            if paket is None:
                raise ValueError("Version kann nicht geladen werden.")
            tag = str(p.get("tag") or "")
            if not _TAG_RE.match(tag):
                raise ValueError("Bitte eine Version (Tag v…) wählen.")
            lauf["status"][str(i)] = "laedt"
            self._speichern(z)
            self.protokollieren(lauf["ablauf"], s["id"], "gestartet", tag)
            pr_l, lauf_id = dict(pr), lauf.get("id")
        # Laden und Prüfen dauert - ohne Sperre, damit Abbrechen, Anzeige usw. weiter gehen
        try:
            ergebnis, fehler = paket(pr_l, tag, orte(pr_l)["name"]), None
        except ValueError as e:
            ergebnis, fehler = None, e
        except Exception as e:   # nie auf „lädt“ hängen bleiben
            ergebnis, fehler = None, ValueError(f"Unerwarteter Fehler beim Laden ({e.__class__.__name__}: {e}).")
        with self.lock:
            z = self._zustand()
            lauf = z.get("lauf")
            if not lauf or lauf.get("id") != lauf_id or lauf.get("index") != i:
                raise ValueError("Der Ablauf wurde inzwischen abgebrochen oder geändert - Version nicht übernommen.")
            if fehler is not None:
                lauf["status"][str(i)] = "fehler"
                self._speichern(z)
                self.protokollieren(lauf["ablauf"], s["id"], "Fehler beim Laden", str(fehler)[:300])
                raise fehler
            ergebnis["zipname"] = zip_name(orte(pr_l)["name"], self.jetzt())
            lauf["paket"] = ergebnis
            return self._ausgefuehrt(z, lauf, s, i, f"{tag} geprüft, ZIP sha256 {ergebnis.get('sha256')}")

    def _ausgefuehrt(self, z, lauf, s, i, befehl):
        lauf["status"][str(i)] = "laeuft"
        lauf["ausgefuehrt"] = s["id"]
        if s["id"] == "beiseite":
            lauf["beiseite_gestartet"] = lauf.get("geplant_alt")
        self._speichern(z)
        self.protokollieren(lauf["ablauf"], s["id"], "ausgeführt", befehl)
        return {**self.ansicht(), "ergebnis": lauf.get("paket") if s["art"] == "lokal" else None}

    def rueckmelden(self, schritt_id, ergebnis, p):
        with self.lock:
            z = self._zustand()
            pr = self._profil(z)
            lauf, s, i = self._aktuell(z, schritt_id)
            status = lauf["status"].get(str(i), "offen")
            if ergebnis == "uebersprungen":
                if not _optional(s, lauf["ablauf"], z):
                    raise ValueError("Dieser Schritt ist nicht optional.")
                if status in ("laeuft", "laedt"):
                    raise ValueError("Der Schritt wurde schon ausgeführt - bitte das Ergebnis melden (geklappt/Fehler).")
            elif ergebnis in ("geklappt", "fehler"):
                if s["art"] != "anleitung" and (status != "laeuft" or lauf.get("ausgefuehrt") != s["id"]):
                    raise ValueError("Der Schritt wurde noch nicht ausgeführt.")
            else:
                raise ValueError("Unbekannte Rückmeldung.")
            sprung, notiz = 1, ""
            if ergebnis == "geklappt":
                if s["rueckfrage"] == "treffer":
                    if p.get("treffer") not in ("0", "mehr"):
                        raise ValueError("Bitte angeben, welche Zahl angezeigt wurde (0 oder mehr).")
                    if p["treffer"] == "0":
                        if z.get("bau_gesperrt"):
                            raise ValueError("Die letzte Bau-Prüfung ergab Ergebnis 2 (Neubau gesperrt). Ohne Prüfung "
                                             "geht es nicht weiter: erst eine signierte Version installieren - oder die "
                                             "Sperre bewusst aufheben.")
                        if p.get("ohne_pruefung") is not True:
                            raise ValueError("Programm älter als 1.8.8 – Bau-Dateien nicht prüfbar. Weiter nur nach "
                                             "ausdrücklicher Bestätigung.")
                        sprung, notiz = 2, "Programm älter als 1.8.8 – Bau-Dateien nicht prüfbar, Prüfung übersprungen"
                        lauf["status"][str(i + 1)] = "uebersprungen"
                if s["rueckfrage"] == "bauergebnis":
                    e = str(p.get("bauergebnis") or "")
                    if e == "2":
                        raise ValueError("Ergebnis 2: Neubau gesperrt - bitte „Fehler“ melden.")
                    if e not in ("0", "1"):
                        raise ValueError("Bitte das angezeigte Ergebnis (0, 1 oder 2) angeben.")
                    if e == "1" and p.get("hinweis_bestaetigt") is not True:
                        raise ValueError("Ergebnis 1 (Hinweis): Neubau nur nach ausdrücklicher Bestätigung.")
                    lauf["bau_gesperrt"] = False
                    z.pop("bau_gesperrt", None)
                    notiz = "Ergebnis=" + e + (" (Hinweis bestätigt)" if e == "1" else "")
                if s["rueckfrage"] == "root":
                    if p.get("root") not in ("ja", "nein"):
                        raise ValueError("Bitte angeben: Ist der Benutzer root (id -u = 0)?")
                    pr["root"] = p["root"] == "ja"
                if s["rueckfrage"] == "compose":
                    if p.get("compose") not in ("plugin", "standalone"):
                        raise ValueError("Bitte die Docker-Variante wählen.")
                    pr["compose"] = p["compose"]
                if s["id"] == "beiseite":
                    z["alt"] = lauf.get("beiseite_gestartet") or ""
                if s["id"] in ("alt_loeschen", "zurueckholen"):
                    z["alt"] = ""
                    lauf.pop("beiseite_gestartet", None)   # sonst böte „Abbrechen“ den gelöschten Ordner als Rückweg an
                if s["id"] in ("entpacken", "wegstellen", "zurueckholen") and (z.get("bau_gesperrt") or lauf.get("bau_gesperrt")):
                    # andere Dateien im Programmordner: die Sperre galt den vorigen
                    z.pop("bau_gesperrt", None)
                    lauf["bau_gesperrt"] = False
                    notiz = "Bau-Sperre aufgehoben (anderer Stand im Programmordner)"
                if s["id"] == "beiseite":
                    z.pop("neu_gebaut", None)   # das vorhandene Image gehört zum beiseitegelegten Ordner
                if s["id"] == "bauen":
                    if lauf["ablauf"] == "zurueck":
                        z.pop("neu_gebaut", None)
                    else:
                        z["neu_gebaut"] = True   # der Rückweg muss das Image dann neu bauen
                if s["id"] == "zip_loeschen":
                    z.pop("zips", None)
            elif s["id"] == "beiseite" and lauf.get("beiseite_gestartet"):
                # unklar, ob umbenannt wurde: den Namen für den Rückweg merken
                z["alt"] = lauf["beiseite_gestartet"]
            if ergebnis == "fehler" and s["rueckfrage"] == "bauergebnis":
                lauf["bau_gesperrt"] = True   # dieser Lauf: gilt, bis eine Wiederholung 0 bzw. bestätigt 1 ergibt
                if str(p.get("bauergebnis") or "") == "2":
                    # nur ein echtes Ergebnis 2 sperrt über den Lauf hinaus - für genau diese Dateien
                    # (aufgehoben, sobald ein anderer Stand in den Programmordner kommt)
                    z["bau_gesperrt"] = True
                    notiz = "Ergebnis=2 - Neubau gesperrt"
                else:
                    notiz = "keine Prüfung gelaufen"
            lauf["status"][str(i)] = {"geklappt": "erledigt", "fehler": "fehler", "uebersprungen": "uebersprungen"}[ergebnis]
            lauf["ausgefuehrt"] = None
            if ergebnis != "fehler":
                lauf["index"] = i + sprung
            self.protokollieren(lauf["ablauf"], s["id"], {"geklappt": "hat geklappt", "fehler": "Fehler",
                                                         "uebersprungen": "übersprungen"}[ergebnis], notiz)
            fertig = lauf["index"] >= len(_schritte(lauf["ablauf"]))
            if fertig:
                self.protokollieren(lauf["ablauf"], "-", "Ablauf abgeschlossen")
                z.pop("lauf", None)
            self._speichern(z)
            return {**self.ansicht(), "fertig": fertig,
                    "hilfe": [list(f) for f in s["fehler"]] if ergebnis == "fehler" else None}
