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
lädt `SIGNATUR.json` hoch und setzt den Tag `v<Version>` auf genau diesen Stand. Gibt es den
Tag schon auf einem anderen Stand, bricht es ab, ohne etwas hochzuladen (eine veröffentlichte
Version wird nie verändert): dann `VERSION` erhöhen. Archive mit unzulässigen Pfaden,
Verknüpfungen oder auffälliger Größe werden ganz abgelehnt.

## Andere Software

„+ Profil für andere Software“: eigener Name und Schlüssel, Regel „Alle Dateien außer
Ausnahmen“. Die Software prüft mit `Pruefmodul/signatur_pruefen.py` - mit genau derselben
Regel wie beim Signieren: zusätzliche, fehlende und veränderte Dateien sind Fehler,
Verknüpfungen (Symlinks) und Sondertypen ebenfalls.

## Tests

```
python -m unittest discover -s tests -v
```

Laufen automatisch bei jedem Push unter Linux und Windows (`.github/workflows/pruefen.yml`)
und vor jedem Bau.

## Sicherung

Die privaten Schlüssel liegen mit Kennwort verschlüsselt in
`%APPDATA%\Signier-Werkzeug\schluessel`. Diesen Ordner auf einen USB-Stick kopieren und das
Kennwort sicher aufbewahren. Private Schlüssel gehören nie in dieses Repository.
