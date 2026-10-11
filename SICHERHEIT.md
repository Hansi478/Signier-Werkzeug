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
| Was ist ausdrücklich ausgenommen? | `SIGNATUR.json`. Bei „speedrace“ in den Ordnern `__pycache__/` und `*.pyc`, alle anderen Einträge der obersten Ebene gehören nicht zum Update. Bei „alle“: `.git/*`, `.github/*`, `__pycache__`, `*.pyc` und die Ausnahmen des Profils. Ordner, die über `…/*` ausgenommen sind, werden gar nicht betreten. |
| Verbotene Typen | Symlinks, Windows-Junctions/Reparse-Points, FIFOs, Sockets, Geräte. Das ist ein **Fehler**, auch wenn der Eintrag unter eine Ausnahme fiele. Nichts wird stillschweigend übersprungen. |
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

Genauso exklusiv und ohne Symlinks zu folgen werden angelegt: neue private
Schlüssel, übernommene Schlüssel (statt `shutil.copyfile`), `profile.json`
und die neue exe beim Update (Zufallsname statt fester `.neu`-Datei).

**Windows:** Windows kennt kein `dir_fd`. Dort sorgen `O_CREAT|O_EXCL`
(entspricht `CREATE_NEW`, folgt keiner Verknüpfung) und `MoveFileEx` (ersetzt
nur den Eintrag) für dasselbe Verhalten. Reparse-Points werden über
`st_file_attributes` erkannt. Beide Wege werden getestet: Linux in
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
| Windows (exe) | DPAPI (`CryptProtectData`), nur für diesen Windows-Benutzer lesbar, in `profile.json` als `dpapi:…` | ja |
| macOS/Linux mit Paket `keyring` und sicherem Backend (Schlüsselbund, Secret Service, KWallet) | Schlüsselbund des Betriebssystems, in `profile.json` nur der Vermerk `keyring:` | ja |
| macOS/Linux ohne sicheren Speicher | nur im Arbeitsspeicher der laufenden Sitzung | **nein**, nach dem Neustart erneut eingeben |

Base64 ist keine Verschlüsselung. Das Werkzeug schreibt deshalb nie mehr
Klartext. Ein Altbestand `klar:…` aus früheren Versionen wird erkannt und
angezeigt, ohne das Token offenzulegen. Mit „Sicher speichern“ wandert er
in DPAPI, den Schlüsselbund bzw. die Sitzung, mit „Entfernen“ wird er
gelöscht. Unsichere keyring-Backends (Klartext, „fail“, „null“) werden nicht
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
- **Bitte zusätzlich im Repository einstellen** (Settings → Rules →
  Rulesets → New tag ruleset). Ziel `v*`, aktiviert:
  - „Restrict updates“
  - „Restrict deletions“
  - „Block force pushes“

  Optional unter Settings → General → Releases die Einstellung „Enable
  release immutability“ aktivieren. Danach lassen sich veröffentlichte
  Releases nicht mehr ändern.

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

Vor dem Signieren prüft das Werkzeug selbst:
- Die exe im Entwurf hat die Prüfsumme aus dem Bau (Release-Text und
  GitHub-Digest).
- Der Tag zeigt auf den gebauten Commit.
- Dieser Commit liegt auf `main`.

PyInstaller-Builds sind nicht garantiert bit-genau reproduzierbar
(`PYTHONHASHSEED` ist fest gesetzt). Die Nachvollziehbarkeit beruht deshalb
auf Attestation, Prüfsumme und Signatur.

## 7. Bekannte Grenzen

- Die exe hat keine Authenticode-Signatur. Windows SmartScreen warnt deshalb
  beim ersten Start nach einem Browser-Download.
- Das Paket `keyring` ist nicht Teil der Windows-exe, unter Windows wird
  ohnehin DPAPI verwendet. Wer den Quelltext unter macOS/Linux startet,
  installiert es bei Bedarf selbst (`pip install keyring`).
- Die Tag-Regeln und die Unveränderlichkeit von Releases kann das Werkzeug
  nicht selbst setzen. Das muss der Herausgeber in den Einstellungen des
  Repositorys erledigen (Abschnitt 6).
