# Signier-Werkzeug

Software-Versionen signieren und prüfen (Ed25519, Format `sr-signatur-1`, dasselbe wie
`tools\signieren.py` des Speedrace-Dashboards). Bedienung über eine Seite im eigenen Browser,
nur auf diesem Rechner erreichbar.

## Herunterladen

Unter **Releases** die neueste `Signier-Werkzeug.exe` laden. Jedes Release enthält eine
`SIGNATUR.json`, signiert mit dem Schlüssel des Herausgebers:

```
7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc=
Fingerabdruck: 04B4 5F7A 55E8 BEB9 AEB2 34D5 8A95 812A 5710 2226 AA9E 777F 4C2D 30C1 CAE7 8086
```

Den Fingerabdruck bitte über einen zweiten Weg vergleichen (z. B. beim Herausgeber
nachfragen) - ein Schlüssel, der nur neben dem Paket steht, beweist nicht dessen Herkunft.
Prüfsumme, Herkunftsnachweis (`gh attestation verify`) und alle Sicherheitsregeln:
[SICHERHEIT.md](SICHERHEIT.md).

Beim ersten Start meldet Windows evtl. „Der Computer wurde durch Windows geschützt“
(das Programm ist nicht bei Microsoft registriert): „Weitere Informationen“ → „Trotzdem ausführen“.

## Updates

Das Werkzeug fragt beim Start nach einer neueren Version. Oben erscheint dann
„Update auf x.y.z“. Ein Klick lädt sie, prüft die Signatur mit dem fest eingebauten
Schlüssel und ersetzt das Programm. Ohne gültige Signatur wird nichts verändert.

## Neue Version veröffentlichen (Herausgeber)

1. `VERSION` in `signier_werkzeug.py` erhöhen, nach `main` committen.
2. Im Signier-Werkzeug: Reiter „GitHub“ → „Bau starten (Tag setzen)“. Das Werkzeug liest
   `VERSION` aus `signier_werkzeug.py` auf `main` und setzt den Tag, z. B. `v1.2.1`, auf
   diesen Stand (ein vorhandener Tag wird nie verschoben). Alternativ den Tag von Hand
   setzen (er muss auf `main` liegen). GitHub baut die exe unter „Actions“ (feste
   Paketversionen mit Prüfsummen, Sicherheitstests, Selbsttest, Herkunftsnachweis) und legt
   sie als **Entwurf** ab. Das Werkzeug zeigt den Fortschritt an („Bau läuft – Schritt …“,
   „Bau fertig – Entwurf bereit“); später jederzeit über „Bau-Status prüfen“.
3. Im Signier-Werkzeug: Reiter „GitHub“ → „Neuen Entwurf signieren und veröffentlichen“
   → Kennwort. Das Werkzeug lädt die exe, prüft ihre Herkunft (Prüfsumme aus dem Bau, Tag
   auf dem gebauten Commit, Commit auf `main`), signiert sie, hängt `SIGNATUR.json` an,
   ersetzt den Text „Ungeprüfter Entwurf“ durch Zeitpunkt, Commit, Prüfsumme und Schlüssel und
   veröffentlicht das Release. Erst jetzt sehen andere Installationen das Update.

Im Repository sind eine Tag-Regel für `v*` (Ändern, Löschen und Force-Push verboten) und
„Release immutability“ eingeschaltet - veröffentlichte Versionen lassen sich nicht mehr
verändern. Prüfbefehle: [SICHERHEIT.md](SICHERHEIT.md), Abschnitt 6.

Das Token im Werkzeug braucht für dieses Repository „Contents: Read and write“.

## Einrichten (Speedrace-Dashboard)

1. Reiter „Profile & Schlüssel“ → „+ Profil Speedrace-Dashboard“ → Speichern.
2. Den vorhandenen Schlüssel übernehmen (`.pem` und Kennwort). Der öffentliche Schlüssel
   muss der oben genannte sein.
3. Reiter „GitHub“: Fine-grained Token mit „Contents: Read and write“ für die
   betroffenen Repositories speichern. Unter Windows mit DPAPI verschlüsselt (nur für deinen
   Windows-Benutzer lesbar); im Quelltext unter macOS/Linux im Schlüsselbund des
   Betriebssystems (Paket `keyring`) oder - ohne sicheren Speicher - nur für die Sitzung.

Je Version: Reiter „Signieren“ → „Von GitHub laden, signieren und hochladen“. Das Werkzeug
lädt `SIGNATUR.json` (beim Dashboard zusammen mit `SIGNATUR-BAU.json`) in einem Commit genau
auf den geladenen Stand hoch – hat sich der Zweig zwischendurch geändert, bricht es ab – und
setzt den Tag `v<Version>` auf genau diesen Commit. Gibt es den Tag schon, auch auf dem noch
unsignierten Stand, bricht es ab, **bevor** etwas hochgeladen wird (eine veröffentlichte
Version wird nie verändert): dann `VERSION` erhöhen. Tags deshalb nie automatisch setzen
lassen (kein Workflow dafür). `VERSION` muss `x.y.z` enthalten, ohne BOM. Lässt sich der Tag
nach dem Hochladen nicht setzen, meldet das Werkzeug einen Fehler (nicht ✅) – dann einfach
noch einmal signieren. Archive mit unzulässigen Pfaden,
Verknüpfungen oder auffälliger Größe werden ganz abgelehnt.

### Bau-Signatur (`SIGNATUR-BAU.json`, ab Dashboard 1.8.8)

Bei Profilen „Speedrace-Dashboard“ signiert das Werkzeug zusätzlich die Dateien, aus denen
das Docker-Image gebaut wird: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, alles unter
`tools/` und `.github/workflows/` (ohne `__pycache__`/`*.pyc`). Sie stehen bewusst nicht in
`SIGNATUR.json` – laufende Dashboards verlangen dort genau die Update-Dateien. Eigenes Format
`sr-bau-signatur-1`, derselbe Schlüssel; beide Dateien gehen in **einem** Commit nach GitHub.
Symbolische Links oder Submodule im Bau-Bereich brechen das Signieren ab. Ältere Versionen
ohne Bau-Dateien bekommen keine `SIGNATUR-BAU.json` (Hinweis). „Prüfen“ zeigt die Bau-Dateien
in einer eigenen Zeile (Abweichung bei `docker-compose.yml` nur Hinweis).

### Paketliste (`SIGNATUR-PAKETE.json`)

Neuere Python-Pakete ohne neue Programmversion: Eine GitHub-Action des Dashboards legt eine
getestete `PAKETE.lock` auf den Zweig `pakete`. Im Reiter „Signieren“ (Profil
Speedrace-Dashboard) zeigt **„Paketliste prüfen“** Programmversion, Prüfsumme und die geänderten
Paketversionen gegenüber `requirements.lock` im Tag `v<Version>`. **„Paketliste signieren und
hochladen“** signiert genau diese Liste (Format `sr-pakete-signatur-1`, gleicher Schlüssel) und
lädt `SIGNATUR-PAKETE.json` in einem Commit auf den Zweig `pakete`. Nichts an main, kein Tag.
Abgebrochen wird, wenn es den Tag `v<Version>` nicht gibt oder er keine gültige Signatur dieses
Profils trägt; eine schon gültig signierte Liste wird nicht noch einmal hochgeladen.
Enthält die Liste die Zeile
`# cloudflared: <Version> amd64=<sha256> arm64=<sha256> armhf=<sha256> windows-amd64=<sha256>`,
ist sie mitsigniert (die Signatur deckt die ganze Datei ab); das Werkzeug prüft ihr Format streng
(wie das Dashboard) und zeigt die Änderung gegenüber der Liste, die auf dem Zweig zuletzt gültig
signiert war (z. B. „cloudflared 2026.9.1 → 2026.10.0“, sonst „(bisher keine)“). Ebenso die Zeile
`# debian: <Codename> <JJJJMMTTThhmmssZ>` (getesteter Stand der Debian-Systempakete), angezeigt als
„Debian trixie: Stand 24.10.2026 (bisher 26.09.2026)“. Eine falsche Zeile wird nicht signiert.

## QNAP (Dashboard auf dem NAS installieren oder neu bauen)

Reiter „QNAP“: Das Werkzeug begleitet die SSH-Schritte für das Dashboard auf einer QNAP –
jeder Schritt einzeln, mit Erklärung, dem genauen Befehl, typischen Fehlern und Abhilfe.
Gestartet wird ein Schritt erst nach deiner Bestätigung, in einem eigenen Konsolenfenster
(das in Windows eingebaute `ssh.exe`/`scp.exe`). Danach meldest du „Hat geklappt“ oder
„Fehler“; erst dann ist der nächste Schritt frei. Passwort und Host-Schlüssel tippst bzw.
bestätigst du nur im Konsolenfenster – das Werkzeug sieht und speichert kein Passwort und
legt keine SSH-Schlüssel an. „Nur anleiten“ zeigt alle Befehle zum Lesen und Kopieren.

Einmalig das QNAP-Profil ausfüllen: Host bzw. IP, Port, Benutzer, Programmordner (absoluter
Pfad, ohne Leerzeichen), optional die Dashboard-Adresse, und das Signier-Profil, aus dessen
Repository die Versionen kommen.

Abläufe:

- **Neue Version installieren:** Version (signierter Tag `v…`) wählen → das Werkzeug lädt
  sie, prüft die Signatur und baut eine saubere ZIP → hochladen → Container anhalten →
  alten Programmordner beiseitelegen (`….alt-Datum-Uhrzeit`, nicht löschen) → entpacken
  (mit Prüfsummen-Kontrolle) → Bau-Dateien prüfen → `build --no-cache` → `up -d` → Kontrolle → optional
  aufräumen (alten Ordner, ZIP, alte Images).
- **Nur neu bauen:** gleiche Version, neues Image (`build --no-cache`, `up -d`).

Vor jedem Neubau: „Bau-Dateien prüfen“ (`app.py --bau-pruefen`, ab Dashboard 1.8.8). Vorher
sieht das Werkzeug per `grep` nach, ob `app.py` den Schalter kennt – ein älteres Programm würde
sonst das Dashboard starten. Ergebnis 0: Neubau frei; 1 (Hinweis): nur nach Bestätigung;
2 (Fehler): Neubau gesperrt – Bau-Dateien aus der signierten Version neu holen.
- **Zur vorigen Version zurück:** den kaputten Ordner wegstellen, den beiseitegelegten Ordner
  zurückholen, Bau-Dateien prüfen, neu bauen (nur nötig, wenn die Installation schon ein neues
  Image gebaut hat – sonst überspringbar, z. B. ohne Internet) und starten.
- **Aufräumen:** beiseitegelegten Ordner endgültig löschen, ZIP und alte Images entfernen.

Im Elternordner des Programmordners fasst das Werkzeug nur den Programmordner (umbenennen),
die selbst angelegten `….alt-…`/`….kaputt-…`-Ordner, den Zwischenordner `….entpacken-…` und die
selbst hochgeladenen ZIPs (`<Programmordner>.signier-JJJJMMTT-hhmm.zip`) an – den Daten-Ordner
daneben nie. In die ZIP kommen nur signierte Dateien (dazu die signierten Bau-Dateien und die
Signaturdateien); alles andere aus dem Tag-Commit zeigt das Werkzeug als „nicht übernommen“.
Ausnahme: Versionen vor 1.8.8 haben keine Bau-Signatur – deren Bau-Dateien (Dockerfile, tools/ …)
kommen unsigniert mit und werden so angezeigt, sonst ließe sich nicht bauen. Protokoll (Zeit, Schritt, Befehl, Rückmeldung; keine
Passwörter): `%APPDATA%\Signier-Werkzeug\qnap-protokoll.txt`. Details: SICHERHEIT.md,
Abschnitt 7.

## Andere Software

„+ Profil für andere Software“: eigener Name und Schlüssel, Regel „Alle Dateien außer
Ausnahmen“. **Prompt zur Einbindung** (im Profil, sobald es einen Schlüssel hat): erzeugt einen
Text für eine Sitzung, die das Repository dieser Software vorbereitet und dort die Prüfung
einbaut – mit öffentlichem Schlüssel, Fingerabdruck, Ausnahmen, Regeln und Ablauf (kein Token,
kein privater Schlüssel). Der Schlüssel ist in der Software nur Voreinstellung und lässt sich
vom Betreiber ersetzen, nie aus einer Datei, die mit einem Update kommt. Die Software prüft mit `Pruefmodul/signatur_pruefen.py` - mit genau derselben
Regel wie beim Signieren: zusätzliche, fehlende und veränderte Dateien sind Fehler,
Verknüpfungen (Symlinks) und Sondertypen ebenfalls. `__pycache__/` und `*.pyc` werden nicht
signiert, Python lädt sie aber: Signieren und Prüfen brechen deshalb ab, wenn welche im Ordner
liegen (vorher löschen).

Ist für ein Profil ein öffentlicher Schlüssel hinterlegt, aber die Schlüsseldatei fehlt (z. B.
auf den USB-Stick verschoben), lässt sich nur genau dieser Schlüssel wieder übernehmen – ein
neuer würde die Prüfung in der eingesetzten Software brechen. Eine fremde `SIGNATUR.json`
(anderer Schlüssel) sichert „Ordner signieren“ vor dem Überschreiben im Datenordner
(`sicherung\`).

## Tests

```
python -m unittest discover -s tests -v
```

Laufen automatisch bei jedem Push unter Linux und Windows (`.github/workflows/pruefen.yml`)
und vor jedem Bau.

Jeden Montag prüft `.github/workflows/sicherheit.yml` die Bau-Pakete (`requirements-bau.txt`)
auf bekannte Schwachstellen und die eingebaute Python-Version auf Aktualität; bei einem Fund
kommt eine E-Mail von GitHub. Ablauf für Sicherheitsupdates: [SICHERHEIT.md](SICHERHEIT.md).

## Sicherung

Die privaten Schlüssel liegen mit Kennwort verschlüsselt in
`%APPDATA%\Signier-Werkzeug\schluessel`. Diesen Ordner auf einen USB-Stick kopieren und das
Kennwort sicher aufbewahren. Private Schlüssel gehören nie in dieses Repository.

## Hilfe und Copyright

Das „i“ neben der Versionsnummer öffnet das Handbuch als PDF ([Handbuch.pdf](Handbuch.pdf), in der
exe enthalten) – ausführlich, mit Bildschirmfotos und Abbildungen. Quelle: `docs/handbuch_quelle.html`
mit den Bildern in `docs/bilder/`. Bildschirmfotos neu: `node docs/handbuch_bilder.js` (startet das
Werkzeug mit Beispieldaten); PDF neu – nach Änderungen und bei jeder neuen Version:
`node docs/handbuch_pdf.js` (ein Test prüft, dass die Version im PDF stimmt).

© 2026 Hans-Christoph Rose. Alle Rechte vorbehalten.
