# Sicherheit des Signier-Werkzeugs

Dieses Dokument beschreibt, wie das Werkzeug signierte Stände erzeugt, prüft
und veröffentlicht, welche Regeln dabei gelten und was der Herausgeber
zusätzlich in den Einstellungen des Repositorys festlegen sollte.

## 1. Vertrauenskette

```
Quelltext (Commit auf main) ──Tag vX.Y.Z──► GitHub Actions „Bauen“
   │                                         │  Tests, Bau unter Windows, Selbsttest
   │                                         │  SHA-256 + Build-Attestation (Herkunftsnachweis)
   │                                         ▼
   │                                  Release-ENTWURF (exe, Commit, SHA-256 im Text)
   │                                         │
   └──────────────► Signier-Werkzeug (lokal, Schlüssel des Herausgebers)
                      prüft: Prüfsumme = Bau, Tag = gebauter Commit, Commit liegt auf main
                      signiert exe + Version (sr-signatur-1) und veröffentlicht
                                             ▼
                     Release vX.Y.Z: Signier-Werkzeug.exe + SIGNATUR.json
```

- Der **private Schlüssel** verlässt nie den Rechner des Herausgebers. Er liegt
  mit Kennwort verschlüsselt (PKCS#8, Ed25519) in
  `%APPDATA%\Signier-Werkzeug\schluessel` (Dateirechte 0600 bzw. nur der
  eigene Windows-Benutzer). Er ist nie Teil des Repositorys (`*.pem` in
  `.gitignore`), des Baus, eines Build-Artefakts oder eines Logs.
- Der **öffentliche Schlüssel** ist fest eingebaut: im Werkzeug
  (`WERKZEUG_SCHLUESSEL`) und im Speedrace-Dashboard (`UPDATE_SIGNATUR_STANDARD`
  in `app.py`, `STANDARD_SCHLUESSEL` in `tools/update_einspielen.py`).

### Öffentlicher Schlüssel - über einen unabhängigen Kanal prüfen

```
Schlüssel:   7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc=
Fingerabdruck (SHA-256 der 32 Schlüssel-Bytes):
             04B4 5F7A 55E8 BEB9 AEB2 34D5 8A95 812A 5710 2226 AA9E 777F 4C2D 30C1 CAE7 8086
```

Ein Schlüssel, der nur zusammen mit dem zu prüfenden Paket geliefert wird,
beweist nicht, von wem das Paket stammt. Der Empfänger sollte den
Fingerabdruck deshalb über einen **zweiten, unabhängigen Weg** vergleichen,
z. B. telefonisch beim Herausgeber, im gedruckten Handbuch oder im
eingebauten Schlüssel einer bereits vertrauten Dashboard-Installation.
Fingerabdruck selbst berechnen:

```
python -c "import base64,hashlib;print(hashlib.sha256(base64.b64decode('7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc=')).hexdigest().upper())"
```

## 2. Signierter Bestand - eine Regel für Signieren und Prüfen

Die Funktion `dateiliste()` in `signier_werkzeug.py` bestimmt den Bestand,
beim Signieren wie beim Prüfen. `Pruefmodul/signatur_pruefen.py` setzt
dieselbe Regel eigenständig um, und ein Test vergleicht beide.

| Frage | Regel |
|---|---|
| Was gehört dazu? | **Regel „speedrace“:** genau die Einträge aus `UPDATE_ALLOWED_FILES`/`UPDATE_ALLOWED_DIRS` der `app.py`, so wie ein Update des Dashboards sie übernimmt. **Regel „alle“:** alle Dateien des Ordners, rekursiv. |
| Was ist ausdrücklich ausgenommen? | `SIGNATUR.json`. Bei „speedrace“ in den Ordnern `__pycache__/` und `*.pyc`, alle anderen Einträge der obersten Ebene gehören nicht zum Update. Bei „alle“: `.git/*`, `.github/*`, `__pycache__`, `*.pyc` und die Ausnahmen des Profils. Jedes Muster trifft den relativen Pfad oder den Dateinamen: `.git/*` und `.github/*` gelten deshalb nur im Wurzelordner (ein `.git` in einem Unterordner wird mitsigniert), `SIGNATUR.json` in jeder Tiefe. Ausnahmen sind `fnmatchcase`-Muster mit `/` als Trenner (`\` wird als `/` gelesen): **Groß-/Kleinschreibung zählt auf jedem Betriebssystem**, damit die Windows-exe genau den Umfang signiert, den das Prüfmodul auf einem Linux-Server erwartet. Ordner, die über `…/*` ausgenommen sind, werden gar nicht betreten. |
| Kompilierte Python-Dateien | `__pycache__/` und `*.pyc` werden nicht signiert, Python lädt sie aber (eine „unchecked-hash“-pyc ohne Abgleich mit der Quelle). Bei „alle“ lehnen Signieren, Prüfmodul und „Prüfen“ sie deshalb ab, außer in ausgenommenen Ordnern. Der QNAP-Ablauf installiert keinen Stand, der welche enthält. |
| Verbotene Typen | Symlinks, Windows-Junctions und andere Name-Surrogate-Reparse-Points (z. B. Mount-Points), FIFOs, Sockets, Geräte. Andere Reparse-Points (z. B. OneDrive-Platzhalter) gelten als normale Dateien. Das ist ein **Fehler**, auch wenn der Eintrag unter eine Ausnahme fiele. Nichts wird stillschweigend übersprungen. |
| Pfade | `/` als Trenner. `\` und Steuerzeichen sind verboten. Zwei Pfade, die unter Windows dieselbe Datei wären (Groß-/Kleinschreibung, Unicode-Normalform NFC), sind ein Fehler, ebenso Datei und Ordner gleichen Namens. |
| Prüfen | Zusätzliche, fehlende und veränderte Dateien werden einzeln gemeldet. Eine Verknüpfung oder ein Sondertyp macht das Ergebnis immer ungültig. |

Gelesen wird jede Datei ohne einer Verknüpfung zu folgen (`O_NOFOLLOW`,
`O_NONBLOCK`). Geprüft wird vor dem Öffnen per `lstat` und am geöffneten
Deskriptor per `fstat`: Es muss dieselbe Datei sein. So fällt ein Austausch
zwischen Prüfung und Lesen auf.

**Prüfsumme und Format sind unverändert** (`sr-signatur-1`: SHA-256,
Textdateien mit LF, Ed25519 über `{"format","version","dateien"}`).
Vorhandene Signaturen bleiben gültig, und das Dashboard prüft neue
Signaturen ohne Änderung. Getestet wurde das mit `_update_signatur_pruefen`
(`app.py`) und `signatur_pruefen` (`tools/update_einspielen.py`) an einem
echten Dashboard-Stand.

### Bau-Signatur (SIGNATUR-BAU.json)

Für Profile „Speedrace-Dashboard“ gilt eine zweite, eigene Regel - genau wie im Dashboard
(`app.py`: `_bau_dateiliste`/`_bau_pruefung`, `tools/signieren.py`: `bau_dateiliste`):

- Dateien: `Dockerfile`, `.dockerignore`, `docker-compose.yml` (soweit vorhanden) und alles
  unter `tools/` und `.github/workflows/`, ohne `__pycache__/` und `*.pyc`. Verknüpfungen und
  Sondertypen sind Fehler. Bei GitHub wird die Auswahl zusätzlich gegen den Git-Baum des
  Commits geprüft: symbolische Links (120000) oder Submodule im Bau-Bereich brechen ab, und
  die Dateien im Archiv müssen genau denen im Git-Baum entsprechen.
- Prüfsumme: SHA-256, ohne Nullbyte vorher CRLF → LF, **keine** Ausnahmen nach Endung.
- Signiert wird `{"format": "sr-bau-signatur-1", "version", "dateien"}` (JSON, sortiert,
  ohne Leerzeichen) - ein eigenes Format, damit sich eine Update-Signatur nicht als
  Bau-Signatur ausgeben lässt und umgekehrt. Derselbe Schlüssel wie für `SIGNATUR.json`.
- Beide Dateien werden vor dem Schreiben gebildet (ein Fehler schreibt nichts) und gehen
  über die Git-Data-API in **einem** Commit nach GitHub; der Zweig wird nur vorgespult
  (`force: false`). Hat er sich zwischendurch geändert, wird abgebrochen.
- Prüfen: Fehler bei ungültiger Signatur, Verknüpfungen oder einer veränderten signierten
  Datei; nur Hinweis bei abweichender `docker-compose.yml` (wird vor Ort angepasst),
  fehlenden oder zusätzlichen Dateien oder einer Signatur anderer Version.
- Gegenprobe: `tests/test_bau_signatur.py` gegen eine Nachbildung von `_bau_pruefung`; mit
  `SR_DASHBOARD_ORDNER=<entpackter Stand ab 1.8.8>` zusätzlich gegen das echte
  `tools/signieren.py pruefen` und `app.py --bau-pruefen` (beide müssen 0 liefern).

### Paketliste (SIGNATUR-PAKETE.json)

Format `sr-pakete-signatur-1`, genau wie im Dashboard (`tools/signieren.py`: `pakete_pruefsumme`,
`pakete_nachricht`; `app.py`: `_pakete_liste_pruefen`):

- `lock_sha256`: SHA-256 (hex, klein) über `PAKETE.lock`, ohne Nullbyte vorher CRLF → LF.
- Signiert wird `json.dumps({"format", "programmversion", "lock_sha256", "erstellt"},
  sort_keys=True, separators=(",", ":"), ensure_ascii=False)` als UTF-8; `erstellt` ist das
  lokale Datum `JJJJ-MM-TT`. Gegenprobe mit strengem Base64.
- Die Programmversion kommt aus der Kopfzeile `# Programmversion: x.y.z`. Zusätzlich verlangt
  das Werkzeug, dass der Tag `v<Version>` existiert und dort eine gültige `SIGNATUR.json` dieses
  Profils für genau diese Version liegt; `requirements.lock` des Tags (für die Anzeige der
  Unterschiede) muss zu dieser Signatur passen. Dateien kommen über ihren Git-Blob (Prüfsumme
  gegen den Git-Baum).
- cloudflared: Die Zeile `# cloudflared: <Version> amd64=… arm64=… armhf=… windows-amd64=…`
  ist Teil der signierten Datei. Geprüft wie im Dashboard: Regex
  `^# cloudflared: (\d{4}\.\d{1,2}\.\d{1,3})((?: [a-z0-9-]+=[0-9a-f]{64})+)$`, genau diese vier
  Architekturen je einmal (Reihenfolge egal), höchstens eine Zeile. Zum Vergleich dient die
  Liste, die auf dem Zweig zuletzt gültig signiert war. Weicht sie vom Format ab, signiert das
  Werkzeug nicht - eine unbrauchbare Angabe würde sonst mitsigniert.
- Signiert wird genau die angezeigte Liste: Hat sie sich seit „Prüfen“ geändert, bricht das
  Werkzeug ab. Hochgeladen wird in einem Commit auf den Zweig `pakete` (nur vorspulen).

## 3. SIGNATUR.json und andere Dateien schreiben

`atomar_schreiben()` schreibt jede Datei so:

1. Am Ziel darf nichts liegen oder nur eine normale Datei. Geprüft wird per
   `lstat`, nicht per `os.path.exists()`. Ein Symlink (auch auf ein nicht
   vorhandenes Ziel), eine Junction oder ein Ordner bricht ab.
2. Der Inhalt wird vollständig in eine **neu und exklusiv angelegte Datei mit
   Zufallsnamen** im selben Ordner geschrieben (`O_CREAT|O_EXCL|O_NOFOLLOW`,
   Rechte 0644 für SIGNATUR.json bzw. 0600 für `profile.json`) und mit `fsync`
   gesichert.
3. Die Datei wird gegengelesen und validiert (SIGNATUR.json: gültiges JSON im
   richtigen Format).
4. Danach wird `os.replace` aufgerufen. Das ersetzt nur den
   Verzeichniseintrag, nie das Ziel einer Verknüpfung und nie den Inhalt
   eines Hardlinks. Unter Linux/macOS läuft das relativ zum geöffneten Ordner
   (`dir_fd`), ein Austausch des Ordnerpfads lenkt also nichts um.
5. Bei jedem Fehler wird die temporäre Datei entfernt, und der alte Stand
   bleibt erhalten.

`SIGNATUR.json` und `SIGNATUR-BAU.json` gehören zusammen: Erst wird die
Bau-Signatur geschrieben (alter Inhalt gemerkt), dann `SIGNATUR.json`;
scheitert diese, wird die Bau-Signatur zurückgesetzt. Gibt es keine
Bau-Dateien mehr, aber noch eine alte `SIGNATUR-BAU.json`, bricht das
Signieren ab.

`profile.json` und `qnap.json` werden nie still als leer gelesen: Ist eine
davon beschädigt (kein gültiges JSON), meldet das Werkzeug das und schreibt
nichts, bis sie repariert oder umbenannt ist. Sonst überschriebe das nächste
Speichern alle Profile bzw. den gemerkten QNAP-Rückweg. Ein BOM am Anfang
(z. B. im Editor gespeichert) ist erlaubt.

Genauso exklusiv und ohne Symlinks zu folgen werden angelegt: neue private
Schlüssel, übernommene Schlüssel (statt `shutil.copyfile`), `profile.json`
und die neue exe beim Update (Zufallsname statt fester `.neu`-Datei).

**Windows:** Windows kennt kein `dir_fd`. Dort sorgen `O_CREAT|O_EXCL`
(entspricht `CREATE_NEW`, folgt keiner Verknüpfung) und `MoveFileEx` (ersetzt
nur den Eintrag) für dasselbe Verhalten. Verknüpfungen werden über
`st_file_attributes` und `st_reparse_tag` (Name-Surrogate) erkannt. Beide Wege werden getestet: Linux in
`pruefen.yml`, Windows in `pruefen.yml`, `bauen.yml` und im Selbsttest der exe.

## 4. Import eines GitHub-Stands (zipball)

Das Archiv wird gestreamt in eine namenlose temporäre Datei geladen, mit
Größengrenze. Vor dem Entpacken prüft das Werkzeug das gesamte
Inhaltsverzeichnis, dann entpackt es in einen neu angelegten Ordner. Jede
Abweichung lehnt **das ganze Archiv** ab, der Ordner wird vollständig
gelöscht, und es wird nichts signiert.

- **Abgelehnte Pfade:** absolute Pfade (POSIX und Windows), Laufwerksangaben
  (`C:\…`, `C:datei`, `C:..\…`), UNC-Pfade (`\\server\share`), jeder
  Backslash, `..` und `.`, leere Bestandteile, für Windows verbotene Zeichen
  (`<>:"|?*`), reservierte Namen (`CON`, `NUL`, `COM1` …) und Namen mit Punkt
  oder Leerzeichen am Ende.
- **Endgültiger Schreibpfad:** `Path.resolve()` muss innerhalb des
  Zielordners liegen. Jeder angelegte Ordner wird per `lstat` geprüft, jede
  Datei exklusiv angelegt (`O_EXCL`).
- **Abgelehnte Einträge:** Symlinks und andere Nicht-Dateien (Unix-Modus im
  Archiv), verschlüsselte Einträge, andere Kompression als „stored“ oder
  „deflate“, doppelte oder unter Windows kollidierende Namen, Datei und
  Ordner gleichen Namens, Einträge außerhalb des gemeinsamen Hauptordners.
- **Grenzen** (`ZIP_GRENZEN`, je Aufruf über `grenzen` anpassbar). Sie gelten
  vor dem Entpacken laut Verzeichnis und währenddessen über die tatsächlich
  gezählten Bytes:

| Grenze | Wert |
|---|---|
| Archiv (komprimiert) | 300 MB |
| Einträge | 20 000 |
| eine entpackte Datei | 200 MB |
| alle entpackten Dateien | 1 GB |
| Kompressionsverhältnis je Eintrag (ab 1 MB) | 200 : 1 |
| Pfadlänge | 240 Zeichen |
| Ordnertiefe | 32 |
| Einträge je Ordner | 5 000 |

Zum Vergleich: Das Speedrace-Dashboard hat rund 160 Dateien, 50 MB, die
größte Datei 20 MB, Tiefe 3.

## 5. GitHub-Token

### Übertragung

- Das Token wird nur an die API-Hosts `api.github.com` und
  `uploads.github.com` gesendet, und nur per https.
- Weiterleitungen folgt das Werkzeug nicht automatisch, es prüft jede
  einzelne. Erlaubt sind höchstens fünf, nur https (kein Downgrade auf http),
  nur bekannte GitHub-Hosts (`github.com`, `codeload.github.com`,
  `objects.githubusercontent.com`, `release-assets.githubusercontent.com` …),
  keine Schleifen und keine Zugangsdaten in der Adresse.
- **Beim ersten Wechsel des Hosts fällt das Token für die ganze Kette weg.**
  Downloads, etwa der zipball über codeload oder Release-Dateien über
  objects.githubusercontent.com, laufen ohne Token weiter.
- Schreibende Anfragen (POST/PUT/PATCH/DELETE) folgen keiner Weiterleitung.
- Fehlermeldungen enthalten nur den HTTP-Code, nie Header oder Token. Alles,
  was der lokale Server als Fehler ausgibt, wird zusätzlich geschwärzt
  (`schwaerzen()`).

### Speicherung

| System | Speicher | Dauerhaft? |
|---|---|---|
| Windows (exe) | DPAPI (`CryptProtectData`), nur für diesen Windows-Benutzer lesbar, in `profile.json` als `dpapi:…`. Ist es nicht lesbar (anderer PC/Benutzer, Kennwort zurückgesetzt), zeigt das Werkzeug „nicht lesbar – neu eingeben“; alles ohne Token funktioniert weiter. | ja |
| macOS/Linux mit Paket `keyring` und sicherem Backend (Schlüsselbund, Secret Service, KWallet) | Schlüsselbund des Betriebssystems, in `profile.json` nur der Vermerk `keyring:` | ja |
| macOS/Linux ohne sicheren Speicher | nur im Arbeitsspeicher der laufenden Sitzung | **nein**, nach dem Neustart erneut eingeben |

Base64 ist keine Verschlüsselung. Das Werkzeug schreibt deshalb nie mehr
Klartext. Ein Altbestand `klar:…` aus früheren Versionen wird erkannt und
angezeigt, ohne das Token offenzulegen. Mit „Sicher speichern“ wandert er
in DPAPI, den Schlüsselbund bzw. die Sitzung, mit „Entfernen“ wird er
gelöscht. Entfernt wird ein Token nur über „Entfernen“ (mit Rückfrage) –
„Speichern“ mit leerem Feld wird abgelehnt. Unsichere keyring-Backends (Klartext, „fail“, „null“) werden nicht
benutzt.

## 6. Bau und Veröffentlichung (GitHub Actions)

`.github/workflows/bauen.yml`:
- Wird nur durch einen Tag-Push `v*` ausgelöst, nie durch Pull Requests. Es
  gibt kein `pull_request_target` und keine Secrets.
- Das `GITHUB_TOKEN` ist standardmäßig nur lesend. Der Job `bauen` (Windows:
  Tests, PyInstaller, Selbsttest) hat nur `contents: read`.
  `persist-credentials: false`.
- Nur der Job `entwurf` hat `contents: write` (Release-Entwurf) sowie
  `id-token`/`attestations: write` (Herkunftsnachweis). Er führt keinen Code
  aus dem Repository aus.
- Alle Actions sind auf vollständige Commit-SHAs festgelegt, die Version
  steht im Kommentar.
  Neue Versionen schlägt Dependabot monatlich als Pull Request vor
  (`.github/dependabot.yml`); die SHA-Festlegung bleibt dabei erhalten, die
  Tests laufen auf jedem Vorschlag, übernommen wird nur nach Prüfung.
- Die Bau-Pakete stehen mit festen Versionen und SHA-256-Prüfsummen in
  `requirements-bau.txt` (`pip --require-hashes`). Auch dafür schlägt
  Dependabot neue Versionen vor.
- Die Python-Laufzeit ist genau festgelegt (z. B. `3.14.8`) - sie steckt in der
  exe. Python 3.12 gibt es seit 3.12.10 nur noch als Quelltext, ohne
  Windows-Ausgaben; deshalb wird mit 3.14 gebaut, solange diese Reihe
  Windows-Ausgaben mit Korrekturen bekommt.

### Sicherheitsupdates: wer macht was

- **Erkennen (GitHub, automatisch):**
  - `sicherheit.yml` läuft jeden Montag (und auf Knopfdruck unter „Actions“):
    `pip-audit` prüft alle Bau-Pakete gegen die Schwachstellen-Datenbank,
    `tools/python_aktuell.py` prüft, ob es eine neuere Python-Version der Reihe
    für Windows gibt. Bei einem Fund schlägt der Lauf fehl; GitHub schickt eine E-Mail.
  - Dependabot meldet Lücken sofort, wenn in den Repository-Einstellungen
    (Settings → Code security) „Dependabot alerts“ und „Dependabot security
    updates“ eingeschaltet sind.
- **Beheben (Herausgeber):** Pull Request bzw. Versionsnummer anheben, Tests
  abwarten, zusammenführen, `VERSION` erhöhen, im Werkzeug „Bau starten“.
- **Signieren (Herausgeber, nur lokal):** im Werkzeug „Neuen Entwurf signieren
  und veröffentlichen“. Der Schlüssel liegt nie bei GitHub.
- **Verteilen (automatisch):** Jede Installation bietet beim Start das Update an.
  Eine Korrektur erreicht die Nutzer nur über ein neues, signiertes Release -
  die exe tauscht keine eingebauten Pakete selbst aus.
- Vor dem Bau wird geprüft:
  - Der Tag liegt auf einem Commit von `main`.
  - Tag und `VERSION` stimmen überein.
- Die exe wird zwischen den Jobs per SHA-256 abgeglichen. Danach bekommt sie
  eine **Build-Attestation** (`actions/attest-build-provenance`), und der
  Entwurf wird mit `--verify-tag` angelegt. Ein vorhandenes Release wird
  dabei nie überschrieben.
- Ausdrücke wie `${{ github.ref_name }}` werden über Umgebungsvariablen
  übergeben, nie direkt in Skripte eingesetzt.

`.github/workflows/pruefen.yml` lässt die Sicherheitstests bei jedem Push
unter Linux und Windows laufen, nur mit Leserechten.

### Versionen bleiben unveränderlich

- Das Werkzeug verschiebt **keinen** vorhandenen Tag mehr, auch nicht beim
  Signieren anderer Software. Zeigt `v<Version>` schon auf einen anderen
  Stand, bricht es ab, bevor etwas hochgeladen wird. Dann muss die Version
  erhöht werden.
- „Bau starten“ setzt nur neue Tags.
- **Im Repository eingestellt** (geprüft am 11.10.2026 über die öffentliche API):
  - Tag-Ruleset „Protect version tags“ (Settings → Rules → Rulesets), aktiv für
    `refs/tags/v*`: Ändern, Löschen und Force-Push verboten, keine Ausnahmen.
    Neue Tags lassen sich weiter anlegen.
  - „Release immutability“ (Settings → General → Releases) ist eingeschaltet.
    Sie gilt für Releases, die nach dem Einschalten veröffentlicht werden;
    v1.2.0 und v1.2.1 wurden davor veröffentlicht und bleiben änderbar.
    Der Ablauf des Werkzeugs passt dazu: Der Bau legt einen (änderbaren)
    Entwurf an; `SIGNATUR.json`, Text und „veröffentlicht“ kommen dazu, bevor
    die Sperre greift.
- Nachprüfen kann das jeder ohne Anmeldung:
  ```
  curl -s https://api.github.com/repos/Hansi478/Signier-Werkzeug/rulesets/24889762
  curl -s https://api.github.com/repos/Hansi478/Signier-Werkzeug/immutable-releases
  curl -s https://api.github.com/repos/Hansi478/Signier-Werkzeug/releases/latest | grep '"immutable"'
  ```
  Erwartet: `"enforcement": "active"` mit den Regeln `deletion`, `update`,
  `non_fast_forward`; `"enabled": true`; ab dem nächsten Release `"immutable": true`.
- Tags ohne „v“ fallen nicht unter das Ruleset; Versions-Tags heißen deshalb
  immer `v<Version>`.

### Herkunft eines Releases prüfen (Empfänger)

1. Den Fingerabdruck des öffentlichen Schlüssels über einen unabhängigen Kanal
   vergleichen (Abschnitt 1).
2. Die SHA-256 der exe berechnen:
   - Windows: `Get-FileHash Signier-Werkzeug.exe`
   - Linux: `sha256sum Signier-Werkzeug.exe`

   Sie muss mit dem Wert im Release-Text und in `SIGNATUR.json` übereinstimmen.
3. Den Herkunftsnachweis prüfen. Er zeigt, dass die exe vom Workflow dieses
   Repositorys aus genau dem genannten Commit gebaut wurde:
   ```
   gh attestation verify Signier-Werkzeug.exe --repo Hansi478/signier-werkzeug
   ```
4. Die Signatur prüft das Werkzeug beim Update selbst, mit dem eingebauten
   Schlüssel.

Beim Veröffentlichen ersetzt das Werkzeug den Entwurfstext („Ungeprüfter Entwurf …“)
durch einen Text mit Zeitpunkt der Signatur, Commit, SHA-256 der exe, öffentlichem
Schlüssel mit Fingerabdruck und Link zum Bau-Lauf. „Commit <sha>“ und „SHA-256 der exe:“
bleiben darin erhalten und damit maschinell prüfbar.

Den Fortschritt des Baus fragt das Werkzeug nur lesend über die Actions-API ab.
Weil das Repository öffentlich ist, geschieht das zuerst ohne Token. Ein Link zum Lauf
wird nur angezeigt, wenn er genau auf einen Lauf dieses Repositorys zeigt.

Vor dem Signieren prüft das Werkzeug selbst:
- Die exe im Entwurf hat die Prüfsumme aus dem Bau (Release-Text und
  GitHub-Digest).
- Der Tag zeigt auf den gebauten Commit.
- Dieser Commit liegt auf `main`.

PyInstaller-Builds sind nicht garantiert bit-genau reproduzierbar
(`PYTHONHASHSEED` ist fest gesetzt). Die Nachvollziehbarkeit beruht deshalb
auf Attestation, Prüfsumme und Signatur.

## 7. QNAP-Begleiter (Reiter „QNAP“)

Der Bereich leitet SSH-Schritte auf einer QNAP an. Er ist bewusst eng gehalten:

- **Keine Kette, kein Freitext.** Es gibt nur feste Abläufe aus festen Schritten
  (`qnap_begleiter.py`, `ABLAEUFE`/`SCHRITTE`). Die Reihenfolge prüft der Server:
  `vorbereiten` legt den Befehl fest und gibt eine Einmal-Marke aus. `ausfuehren` startet
  nur mit dieser Marke, ausdrücklicher Bestätigung und nur für den aktuellen Schritt.
  Der nächste Schritt wird erst nach der Rückmeldung des Benutzers frei. Es gibt keinen
  Aufruf, der mehrere Schritte ausführt, und kein Feld für eigene Befehle.
- **SSH nur über Windows.** Gestartet wird `%SystemRoot%\System32\cmd.exe /d /v:off /k`
  mit `%SystemRoot%\System32\OpenSSH\ssh.exe` bzw. `scp.exe` (absolute Pfade, kein PATH),
  über `CreateProcess` ohne Shell dieses Prozesses, je Schritt ein neues Fenster. Kein
  SSH-Paket im Werkzeug, keine Schlüssel, kein Passwort im Werkzeug, kein `-o`.
- **Eingaben.** Host `[A-Za-z0-9.:-]`, Benutzer `[A-Za-z0-9._-]` (beide nicht mit `-`
  beginnend, gegen Optionen wie `-oProxyCommand`), Port 1–65535, Pfade absolut aus
  `[A-Za-z0-9._/-]` ohne `..`, `.`, `//`, Teile mit `-` am Anfang und ohne Leerzeichen
  (scp übergibt den Zielpfad bei älteren Windows-Versionen an die Shell der QNAP). In
  Befehlen stehen Pfade immer in einfachen Anführungszeichen. Die fertige Befehlszeile wird
  zusätzlich auf Zeichen geprüft, die cmd.exe auch in Anführungszeichen auswertet (`%`, `!`,
  `"`, Steuerzeichen).
- **Was angefasst wird.** Im Elternordner des Programmordners nur der Programmordner
  (umbenennen, nie löschen), selbst angelegte `<Name>.alt-JJJJMMTT-hhmm`/`.kaputt-…`, der
  Zwischenordner `<Name>.entpacken-…` (entpackt wird dorthin, erst danach wird umbenannt -
  ein Abbruch hinterlässt keinen halben Programmordner) und die eigenen ZIPs
  `<Name>.signier-JJJJMMTT-hhmm.zip` (gelöscht nur, wenn vorhanden). `rm -r` gibt es nur für
  einen `.alt-…`-Ordner, den das Werkzeug selbst angelegt und gemerkt hat. Kein `-f`, keine
  Platzhalterzeichen, keine Variablen außer der Hilfsdatei der Bau-Prüfung (`mktemp`).
  Umbenennen und Löschen eines Ordners verlangen den abgetippten Namen. Der Programmordner darf nicht
  `Daten` oder `container-station-data` heißen.
- **Herkunft der Version.** Nur signierte Tags `v<x.y.z>`. Das Werkzeug lädt den Tag-Commit
  über die GitHub-API (mit den ZIP-Prüfungen aus Abschnitt 4), prüft die Signatur mit dem
  öffentlichen Schlüssel des gewählten Profils (Bestandsregel aus Abschnitt 2) und verlangt,
  dass Signatur und `VERSION` zum Tag passen. Daraus baut es eine neue ZIP mit genau einem
  Ordner und **nur den signierten Dateien** (dazu die signierten Bau-Dateien und die
  Signaturdateien) - eine unsignierte Datei im Tag-Commit (etwa eine fremde `json.py`) käme
  sonst ungeprüft in den Programmordner. Auf der QNAP prüft `sha256sum -c` die Prüfsumme vor dem Entpacken.
- **Bau-Dateien:** Ab Dashboard 1.8.8 prüft „Version laden und prüfen“ auch
  `SIGNATUR-BAU.json` (Fehler oder andere Version: nicht installieren). Vor jedem Neubau prüft
  der Schritt „Bau-Dateien prüfen“ auf der QNAP mit `app.py --bau-pruefen` (fest eingebauter
  Schlüssel des Herausgebers). Vorher sucht `grep -c -- '--bau-pruefen' app.py`, ob das Programm
  den Schalter kennt; bei 0 wird die Prüfung nur nach ausdrücklicher Bestätigung übersprungen.
  `Ergebnis=…` erscheint nur, wenn die Prüfung wirklich lief (eine Zeile `OK:`/`HINWEIS:`/
  `FEHLER:`); sonst „Ergebnis fehlt“ (z. B. sudo-Kennwort falsch, Container läuft nicht).
  Ergebnis 2 sperrt den Neubau (auch serverseitig), Ergebnis 1 nur nach Bestätigung. Fehlt
  `SIGNATUR-BAU.json` bei einer Version, deren signierte `app.py` die Bau-Prüfung kennt, lehnt
  schon „Version laden und prüfen“ ab.
- **Grenze:** Ältere Versionen (vor 1.8.8) haben keine Bau-Signatur - dort bleiben
  `Dockerfile`, `docker-compose.yml` und `tools/` unsigniert; das Werkzeug übernimmt genau diese
  Bau-Dateien trotzdem in die ZIP (sonst ließe sich nicht bauen) und listet sie auf.
- **Prüfen der Dashboard-Adresse:** nur GET, ohne Token, ohne Proxy, Weiterleitungen werden
  nicht verfolgt. Angezeigt wird nur der Statuscode.
- **Daten:** Profil und Ablauf in `qnap.json`, Protokoll in `qnap-protokoll.txt` (Zeit,
  Ablauf, Schritt, Ereignis, Befehl; rotiert ab 512 KB). Beides liegt im Datenordner. Der
  Bereich liest aus `profile.json` nur Repository, Regel, Ausnahmen und öffentlichen
  Schlüssel sowie das Token für den Download. Auf private Schlüssel greift er nicht zu.
- **Gemerktes:** Rückweg (`.alt`-Ordner), die vom Werkzeug hochgeladenen ZIPs (eigener Name
  `<Name>.signier-JJJJMMTT-hhmm.zip`, nur diese löscht „Aufräumen“) und eine Bau-Sperre nach
  Ergebnis 2 gelten über einen Abbruch hinaus. Die Sperre gilt den geprüften Dateien: Kommt ein
  anderer Stand in den Programmordner (entpacken, wegstellen, zurückholen), fällt sie. Ein
  „Fehler“ ohne Ergebnis 2 sperrt nur den laufenden Ablauf. Der Programmordner lässt sich
  nicht ändern, solange etwas gemerkt ist; eine neue Adresse derselben QNAP nur nach
  Bestätigung (protokolliert). Gemerkte ZIPs lassen sich vergessen. Der Rückweg baut das Image
  nur neu, wenn die Installation schon gebaut hat. Ein Lauf merkt sich die Liste seiner Schritte -
  ändert ein Update die Abläufe, muss er neu begonnen werden.

### Lokale Oberfläche

Die Seite läuft nur auf `127.0.0.1` mit einem Zufallsschlüssel in der Adresse; jede Anfrage
muss ihn mitschicken, Host und Origin werden geprüft. Es läuft nur **eine** Instanz je
Windows-Benutzer (Sperre `instanz.lock` im Datenordner): Ein zweiter Start öffnet die
laufende Seite (Adresse in `adresse.txt`, nur für diesen Benutzer lesbar) statt einer zweiten
Instanz, die `profile.json` bzw. `qnap.json` überschreiben könnte. Beenden ist gesperrt,
solange ein Vorgang läuft (auch ein offenes Auswahlfenster); danach nimmt es keine neuen
Aktionen mehr an. Ohne Lebenszeichen der Seite beendet sich das Werkzeug nach 10 Minuten
(nie mitten in einem Vorgang). Jedes Profil trägt einen Stand: Speichern aus einem Tab, der
einen älteren Stand zeigt, wird abgelehnt (sonst setzte er Änderungen des anderen Tabs zurück).

## 8. Bekannte Grenzen

- Zwei Pfade, die sich nur in Groß-/Kleinschreibung oder Unicode-Normalform unterscheiden,
  lehnen Werkzeug und Prüfmodul ab - zur Sicherheit auch Fälle, die Windows unterscheidet
  (etwa „ß“/„ss“, `casefold`).
- „Ordner signieren“ nimmt alle Dateien des Ordners, auch nicht eingecheckte. Bei einem
  Git-Arbeitsordner weist das Werkzeug darauf hin; für genau den Repository-Stand „Von GitHub
  laden, signieren und hochladen“ verwenden.

- Die exe hat keine Authenticode-Signatur. Windows SmartScreen warnt deshalb
  beim ersten Start nach einem Browser-Download.
- Das Paket `keyring` ist nicht Teil der Windows-exe, unter Windows wird
  ohnehin DPAPI verwendet. Wer den Quelltext unter macOS/Linux startet,
  installiert es bei Bedarf selbst (`pip install keyring`).
- Python-Reihen bekommen nur eine begrenzte Zeit Windows-Ausgaben. Meldet die
  Sicherheitsprüfung „keine Windows-Ausgaben mehr“, muss auf die nächste Reihe
  gewechselt werden (Pakete mit passenden Wheels, Tests unter Windows).
- Tag-Ruleset und Unveränderlichkeit von Releases sind Einstellungen des
  Repositorys, nicht des Werkzeugs. Sie sind gesetzt (Abschnitt 6); wer sie
  ändert, hebt den Schutz auf - deshalb mit den Befehlen dort gelegentlich nachprüfen.
