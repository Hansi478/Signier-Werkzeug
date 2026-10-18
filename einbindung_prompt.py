# -*- coding: utf-8 -*-
"""Prompt zur Einbindung: Text für eine Sitzung, die eine andere Software
(Profil „andere Software“) für das Signier-Werkzeug vorbereitet und dort die
Signaturprüfung einbaut. Erzeugt je Profil im Reiter „Profile & Schlüssel“.

PFLEGE: Ändert sich etwas, das für die Einbindung wichtig ist (Format,
Dateiauswahl, Prüfsummen-Regel, Ablauf von Signieren/Hochladen/Tag, Prüfmodul,
Empfehlungen zu Schlüssel und Tags), muss diese Vorlage im selben Commit
angepasst werden. Regeln, die als Konstanten im Werkzeug stehen (Format,
feste Ausnahmen, Binär-Endungen, Prüfsumme des Prüfmoduls), werden beim
Erzeugen eingesetzt; tests/test_einbindung.py prüft das.

Enthält nur den ÖFFENTLICHEN Schlüssel - kein Token, keinen privaten Schlüssel.
"""
import base64
import hashlib
import json
import re

VORLAGE = r"""# Prompt: Signaturprüfung mit dem Signier-Werkzeug einbinden

> Erzeugt vom Signier-Werkzeug {{WERKZEUG_VERSION}} für das Profil „{{PROFILNAME}}“.
> Vollständig in die Sitzung kopieren, die an **{{REPOSITORY}}** arbeitet. Antworten bitte
> auf Deutsch, Anrede „du“. **Vor dem Programmieren:** Quelltext lesen und eine Tabelle mit
> Plan, Risiken und Aufwand vorlegen. Die Versionsnummer vergebe ich.

---

## Ziel

Die Software in `{{REPOSITORY}}` (Zweig `{{ZWEIG}}`) soll künftig nur Versionen annehmen,
die ich mit dem Signier-Werkzeug signiert habe. Signiert wird **nicht** in diesem Repository
und **nicht** in dieser Sitzung, sondern von mir am eigenen Rechner im Signier-Werkzeug
(Reiter „Signieren“ → „Von GitHub laden, signieren und hochladen“). Der private Schlüssel
verlässt meinen Rechner nie. Deine Aufgabe ist, das Repository dafür vorzubereiten und die
**Prüfung** in die Software einzubauen.

## Feste Daten (nicht ändern, nicht raten)

- Format: `{{FORMAT}}`, Signaturdatei `{{SIGNATUR_DATEI}}` im Wurzelordner
- Öffentlicher Schlüssel des Herausgebers dieses Profils (Ed25519, Base64, 44 Zeichen) –
  Voreinstellung, siehe Aufgabe 2:
  `{{OEFFENTLICHER_SCHLUESSEL}}`
- Fingerabdruck (SHA-256 über die 32 Bytes des dekodierten Schlüssels, hexadezimal in
  Großbuchstaben, in Vierergruppen – zum Vergleich mit mir über einen zweiten Weg):
  `{{FINGERABDRUCK}}`
- Profilregel: „alle Dateien außer Ausnahmen“
- Ausnahmen des Profils (zusätzlich zu den festen): {{AUSNAHMEN}}
- Prüfmodul: `Pruefmodul/signatur_pruefen.py` aus `{{WERKZEUG_REPO}}`, Stand Tag
  `v{{WERKZEUG_VERSION}}`, SHA-256 `{{PRUEFMODUL_SHA256}}` (über den Inhalt mit LF-Zeilenenden:
  vor dem Vergleich `\r\n` durch `\n` ersetzen – ein Windows-Checkout hat sonst CRLF)

## So signiert das Werkzeug (damit die Prüfung passt)

1. Es lädt den Stand des Zweigs `{{ZWEIG}}` über die GitHub-API als Archiv (zipball).
2. Die Version kommt aus der Datei `VERSION` im Wurzelordner (Inhalt genau `x.y.z` aus Ziffern,
   gestrippt, UTF-8 **ohne BOM**, Dateiname genau in dieser Schreibweise). Fehlt sie oder ist
   sie ungültig, bricht das Signieren ab.
3. Signiert werden **alle Dateien** außer:
   - immer: {{STANDARD_AUSSCHLUSS}} – jedes Muster trifft den relativen Pfad **oder** den
     Dateinamen: `.git/*` und `.github/*` gelten also nur im Wurzelordner (ein `.git` in einem
     Unterordner wird mitsigniert), `{{SIGNATUR_DATEI}}` dagegen in jeder Tiefe
   - die Ausnahmen des Profils (siehe oben): Muster wie `fnmatch.fnmatchcase` auf den
     relativen Pfad oder den Dateinamen, Trenner `/` (ein `\` im Muster gilt als `/`),
     **Groß-/Kleinschreibung zählt** (auf jedem Betriebssystem); „ordner/*“ nimmt einen ganzen
     Ordner aus
4. Prüfsumme je Datei: SHA-256 über den Inhalt, hexadezimal in Kleinbuchstaben. Bei
   Textdateien vorher `\r\n` → `\n`. Nicht umgewandelt werden Dateien mit Nullbyte und
   Dateien mit den Endungen `{{BINAER}}` (Groß-/Kleinschreibung der Endung egal, z. B. auch
   `.PDF`).
5. Signiert wird `json.dumps({"format": "{{FORMAT}}", "version": VERSION, "dateien": {Pfad: Prüfsumme}},
   sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` mit Ed25519.
   `{{SIGNATUR_DATEI}}` enthält dieselben drei Felder und dazu `"signatur"`: die 64 Bytes der
   Signatur in Base64 (höchstens {{MAX_SIGNATUR_MB}} MB, sonst lehnen Werkzeug und Prüfmodul ab).
6. `SIGNATUR.json` kommt in einem eigenen Commit **genau auf den geladenen Stand** (der Zweig
   wird nur vorgespult; hat er sich zwischendurch geändert, bricht das Werkzeug ab). Danach
   setzt das Werkzeug den Tag `v<VERSION>` **genau auf diesen signierten Commit**. Ein
   vorhandener Tag wird nie verschoben: Gibt es `v<VERSION>` schon – auch auf dem noch
   unsignierten Stand –, bricht das Signieren ab, **bevor** etwas hochgeladen wird.

Pfade sind relativ und mit `/`. Verknüpfungen (Symlinks, Junctions), Sonderdateien und Pfade,
die unter Windows/macOS gleich sein könnten (Groß/Klein, Unicode-Normalform), sind Fehler.
Andere Windows-Reparse-Points (z. B. OneDrive-Platzhalter) gelten als normale Dateien. Beim
Prüfen werden Dateinamen in Unicode-Normalform NFC verglichen (macOS liefert sonst NFD).

Beim Laden von GitHub lehnt das Werkzeug den **ganzen Stand** ab (es wird nichts signiert),
wenn das Archiv irgendwo – auch in `.github/` oder in ausgenommenen Ordnern – enthält:
Symlinks oder Submodule; unter Windows reservierte Namen (z. B. `aux.py`, `con.txt`); die
Zeichen `<>:"|?*\` oder Steuerzeichen; Punkt oder Leerzeichen am Namensende; Pfade über
{{ZIP_PFAD_ZEICHEN}} Zeichen oder mit mehr als {{ZIP_TIEFE}} Teilen (einschließlich Dateiname);
Dateien über {{ZIP_DATEI_MB}} MB; mehr als {{ZIP_EINTRAEGE}} Einträge bzw. {{ZIP_JE_ORDNER}} in einem
Ordner; zusammen über {{ZIP_GESAMT_MB}} MB entpackt oder ein Archiv über {{ZIP_ARCHIV_MB}} MB;
eine Datei ab 1 MB, die mehr als {{ZIP_VERHAELTNIS}}-fach komprimiert ist.

## Aufgaben

1. **Repository vorbereiten**
   - Datei `VERSION` im Wurzelordner anlegen bzw. beibehalten (nur `x.y.z`).
   - **Keine Tags `v<Version>` automatisch setzen** (keinen Workflow, kein Skript dafür).
     Tags setzt ausschließlich das Signier-Werkzeug nach dem Signieren. Einen vorhandenen
     Workflow dieser Art entfernen und das berichten.
   - Keine symbolischen Links und keine Submodule im **ganzen** Repository (auch nicht in
     `.github/` oder in ausgenommenen Ordnern – siehe oben).
   - In `.gitattributes` kein `export-ignore` und kein `export-subst` für Dateien, die zum
     Bestand gehören (das GitHub-Archiv würde sonst vom Repository abweichen).
   - Kein Git-LFS für Dateien im Bestand (das GitHub-Archiv enthält dann nur die Zeiger, die
     Prüfsummen weichen ab).
   - Der Zweig `{{ZWEIG}}` darf keine Regel haben, die direkte Commits verbietet, signierte
     Commits oder bestandene Status-Checks verlangt – das Werkzeug lädt die Signatur per Git-API
     direkt hoch (nur vorspulen, nie überschreiben; der Commit ist nicht Git-signiert).
   - Dateien, die erst zur Laufzeit entstehen (Logs, Einstellungen, Daten), dürfen im
     installierten Programmordner nicht zwischen den signierten Dateien liegen – oder sie
     müssen als Ausnahme im Profil stehen. Liste mir alle Kandidaten auf, damit ich die
     Ausnahmen im Werkzeug eintrage. Keine Ausnahmen selbst erfinden.
   - Kein privater Schlüssel, keine `.pem`-Datei ins Repository.

2. **Prüfung einbauen**
   - `signatur_pruefen.py` unverändert übernehmen und die SHA-256 (mit LF-Zeilenenden, siehe
     oben) gegen den Wert oben prüfen. Weicht sie ab: anhalten und mir melden.
   - **Kompilierte Python-Dateien:** `__pycache__/` und `*.pyc` sind nicht signiert, Python
     lädt sie aber. Das Prüfmodul lehnt sie deshalb ab (außer in ausgenommenen Ordnern). Vor
     der Prüfung im zu prüfenden Ordner löschen; nie ungeprüfte `.pyc` ausliefern.
   - **Schlüssel einstellbar, aber geschützt.** Die Software soll auch von anderen Herausgebern
     mit eigenem Schlüssel genutzt werden können. Deshalb:
     - Der Schlüssel oben ist nur die **Voreinstellung**.
     - Ersetzen lässt er sich **nur durch den Betreiber der Installation**: über eine
       Umgebungsvariable (z. B. `<PROGRAMM>_SIGNATUR_SCHLUESSEL`) oder eine Einstellung, die
       nur ein Admin ändern kann.
     - **Nie** aus einer Datei, die mit einem Update kommt oder im Programmordner liegt. Sonst
       könnte ein manipuliertes Update seinen eigenen Schlüssel mitbringen.
     - Format prüfen: Base64, genau 32 Bytes. Bei ungültigem Wert nichts installieren,
       nicht stillschweigend auf „ohne Prüfung“ fallen.
     - Den aktiven Schlüssel samt Fingerabdruck sichtbar anzeigen (z. B. Einstellungen/Systemcheck),
       damit ein Austausch auffällt.
     - Abschalten der Prüfung ist nicht vorgesehen.
   - **Laden und Entpacken sicher:** das Tag-Archiv in einen frischen, nur für diese Prüfung
     angelegten Ordner entpacken. Dabei absolute Pfade, `..`, Laufwerksangaben und Links
     ablehnen (bei `tarfile` mit `filter="data"`, bei `zipfile` jeden Namen selbst prüfen) –
     ein präpariertes Archiv dürfte sonst schon **vor** der Prüfung außerhalb schreiben.
   - Prüfen **bevor** eine neue Version installiert oder gestartet wird:
     `pruefen(ordner, aktiver_schluessel, ausschluss=[…])`. Bei `SignaturFehler` (und jeder anderen
     Ausnahme daraus): nichts installieren,
     verständliche Meldung, alte Version bleibt.
   - **Genau den geprüften Ordner** installieren – nicht danach neu laden oder aus einer anderen
     Quelle kopieren. Einen `.git`-Ordner aus dem Update nie mitkopieren (er wird nicht geprüft;
     Git-Hooks und `core.fsmonitor` könnten sonst Code ausführen).
   - Die Ausnahmen gehören zum Vertrag: an **einer** Stelle als Konstante, genau wie im Profil.
     Ändere ich sie im Werkzeug, muss die Software sie im selben Update ändern – sonst lehnt
     die Prüfung bestehender Installationen ab.
   - Eine **ältere** Version als die installierte nur nach ausdrücklicher Bestätigung
     annehmen (Rückstufung): auch alte Versionen sind gültig signiert, können aber bekannte
     Fehler haben.
   - Zusätzlich vergleichen: Version laut Signatur == Inhalt von `VERSION` == gewählter Tag
     (ohne „v“). Sonst ablehnen.
   - Versionen über Tags `v<x.y.z>` laden (nicht über den Zweig), damit genau der signierte
     Stand kommt.

3. **Tests**
   - Gültig signierter Testordner wird angenommen. Dafür im Test (Temp-Ordner) mit einem eigenen
     Test-Schlüssel signieren, genau nach „So signiert das Werkzeug“ – nie mit dem echten
     Schlüssel, nie im Repository.
   - Ein per Umgebungsvariable/Admin-Einstellung gesetzter anderer Schlüssel wird verwendet;
     ein ungültiger Wert führt zur Ablehnung, nicht zu „ohne Prüfung“.
   - Abgelehnt werden: `__pycache__/` bzw. `*.pyc` im zu prüfenden Ordner, eine Ausnahme mit
     anderer Groß-/Kleinschreibung trifft nicht (z. B. `*.log` vs. `X.LOG`),
     veränderte, zusätzliche und fehlende Datei, fremder Schlüssel,
     beschädigte `SIGNATUR.json`, Symlink im Bestand, Versionsabweichung Tag/`VERSION`,
     Archiv mit `../`-Pfad oder Link (Entpacken), Rückstufung ohne Bestätigung.
   - Die Ausnahmen im Test genau wie im Profil.

4. **Doku:** Ablauf je Version in die README:
   `VERSION erhöhen → committen und nach {{ZWEIG}} pushen → im Signier-Werkzeug signieren
   (lädt SIGNATUR.json hoch, setzt v<Version>) → erst dann verteilen.`

## Grenzen

- Im Repository nicht signieren, keine `SIGNATUR.json` anlegen oder ändern (nur Tests im
  Temp-Ordner mit Test-Schlüssel), keine Tags anlegen, verschieben oder löschen.
- `.github/` gehört nicht zum signierten Bestand. Wenn Workflows etwas ausliefern
  (Releases, Images), mir das melden – dafür bräuchte es eine eigene Lösung.
- Keine echten Namen, Adressen, Hosts oder Pfade in Quelltext, Vorlagen oder Tests. Ausnahme:
  die Update-Quelle (Repository bzw. Host, von dem die Software ihre Versionen lädt) und der
  öffentliche Schlüssel oben.
- Keine neuen Abhängigkeiten außer `cryptography`.

## Am Ende melden

- Commit auf `{{ZWEIG}}` und die Version in `VERSION`
- dass für diese Version noch **kein** Tag existiert
- die Liste möglicher Ausnahmen (Laufzeitdateien)
- Ergebnis der Tests
"""


def fingerabdruck(oeffentlich):
    fp = hashlib.sha256(base64.b64decode(oeffentlich, validate=True)).hexdigest().upper()
    return " ".join(fp[i:i + 4] for i in range(0, 64, 4))


def _code(text):
    return "`" + str(text).replace("`", "'").replace("\n", " ").replace("\r", " ") + "`"


def _liste(muster):
    """Ausnahmen genau wie im Werkzeug, als JSON-Liste im Code-Block (kein
    Zeichen geht verloren, auch kein Backtick)."""
    text = json.dumps(list(muster), ensure_ascii=False)
    zaun = "`" * max(3, max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    return f"genau diese Liste im Code verwenden:\n\n  {zaun}json\n  {text}\n  {zaun}\n"


def erzeugen(profil, werte):
    """profil: Profil des Werkzeugs (Name, Repository, Zweig, Ausnahmen,
    öffentlicher Schlüssel). werte: Konstanten des Werkzeugs (VERSION, FORMAT,
    SIGNATUR_DATEI, STANDARD_AUSSCHLUSS, BINAER, WERKZEUG_REPO, PRUEFMODUL_SHA256)."""
    oeffentlich = str(profil.get("oeffentlich") or "")
    if len(base64.b64decode(oeffentlich or "", validate=True)) != 32:
        raise ValueError("Das Profil hat noch keinen gültigen öffentlichen Schlüssel.")
    # wie ausschluss_muster() im Werkzeug: gestrippt, „\“ als „/“
    ausnahmen = [str(a).strip().replace("\\", "/") for a in profil.get("ausschluss") or [] if str(a).strip()]
    g = werte["ZIP_GRENZEN"]
    felder = {
        "WERKZEUG_VERSION": werte["VERSION"],
        "WERKZEUG_REPO": werte["WERKZEUG_REPO"],
        "PROFILNAME": " ".join(str(profil.get("name") or "").split())[:60].replace("“", "\"").replace("„", "\""),
        "REPOSITORY": str(profil.get("repo") or "") or "<Besitzer/Name>",
        "ZWEIG": str(profil.get("zweig") or "main"),
        "OEFFENTLICHER_SCHLUESSEL": oeffentlich,
        "FINGERABDRUCK": fingerabdruck(oeffentlich),
        "AUSNAHMEN": _liste(ausnahmen) if ausnahmen else "keine (im Code `[]`)",
        "FORMAT": werte["FORMAT"],
        "SIGNATUR_DATEI": werte["SIGNATUR_DATEI"],
        "STANDARD_AUSSCHLUSS": ", ".join(_code(a) for a in werte["STANDARD_AUSSCHLUSS"]),
        "BINAER": " ".join(werte["BINAER"]),
        "PRUEFMODUL_SHA256": werte["PRUEFMODUL_SHA256"],
        "MAX_SIGNATUR_MB": werte["MAX_SIGNATUR_BYTES"] // (1024 * 1024),
        "ZIP_PFAD_ZEICHEN": g["pfad_zeichen"], "ZIP_TIEFE": g["tiefe"], "ZIP_EINTRAEGE": g["eintraege"],
        "ZIP_JE_ORDNER": g["je_ordner"], "ZIP_VERHAELTNIS": g["verhaeltnis"],
        "ZIP_DATEI_MB": g["datei_bytes"] // (1024 * 1024), "ZIP_GESAMT_MB": g["gesamt_bytes"] // (1024 * 1024),
        "ZIP_ARCHIV_MB": g["archiv_bytes"] // (1024 * 1024),
    }
    fehlt = set(re.findall(r"\{\{([A-Z0-9_]+)\}\}", VORLAGE)) - set(felder)
    if fehlt:
        raise ValueError("Vorlage unvollständig ausgefüllt: " + ", ".join(sorted(fehlt)))
    # in einem Durchgang: „{{…}}“ in einem Profilnamen oder einer Ausnahme bleibt, wie es ist
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", lambda m: str(felder[m.group(1)]), VORLAGE)
