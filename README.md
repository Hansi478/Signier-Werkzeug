# Signier-Werkzeug

Software-Versionen signieren und prüfen (Ed25519, Format `sr-signatur-1`, dasselbe wie
`tools\signieren.py` des Speedrace-Dashboards). Bedienung über eine Seite im eigenen Browser,
nur auf diesem Rechner erreichbar.

## Herunterladen

Unter **Releases** die neueste `Signier-Werkzeug.exe` laden. Jedes Release enthält eine
`SIGNATUR.json`, signiert mit dem Schlüssel des Herausgebers:

```
7OhcbQl3LZIM488s+WIDQMr4YhQmGd4dgyxRgun5XAc=
```

Beim ersten Start meldet Windows evtl. „Der Computer wurde durch Windows geschützt“
(das Programm ist nicht bei Microsoft registriert): „Weitere Informationen“ → „Trotzdem ausführen“.

## Updates

Das Werkzeug fragt beim Start nach einer neueren Version. Oben erscheint dann
„Update auf x.y.z“. Ein Klick lädt sie, prüft die Signatur mit dem fest eingebauten
Schlüssel und ersetzt das Programm. Ohne gültige Signatur wird nichts verändert.

## Neue Version veröffentlichen (Herausgeber)

1. `VERSION` in `signier_werkzeug.py` erhöhen, committen.
2. Tag setzen, z. B. `v1.2.1`. GitHub baut die exe unter „Actions“ (feste Paketversionen
   mit Prüfsummen, Selbsttest) und legt sie als **Entwurf** ab.
3. Im Signier-Werkzeug: Reiter „GitHub“ → „Neuen Entwurf signieren und veröffentlichen“
   → Kennwort. Das Werkzeug lädt die exe, signiert sie, hängt `SIGNATUR.json` an und
   veröffentlicht das Release. Erst jetzt sehen andere Installationen das Update.

Das Token im Werkzeug braucht für dieses Repository „Contents: Read and write“.

## Einrichten (Speedrace-Dashboard)

1. Reiter „Profile & Schlüssel“ → „+ Profil Speedrace-Dashboard“ → Speichern.
2. Den vorhandenen Schlüssel übernehmen (`.pem` und Kennwort). Der öffentliche Schlüssel
   muss der oben genannte sein.
3. Reiter „GitHub“: Fine-grained Token mit „Contents: Read and write“ für die
   betroffenen Repositories speichern (verschlüsselt für deinen Windows-Benutzer).

Je Version: Reiter „Signieren“ → „Von GitHub laden, signieren und hochladen“. Das Werkzeug
lädt `SIGNATUR.json` hoch und setzt den Tag `v<Version>` auf genau diesen Stand.

## Andere Software

„+ Profil für andere Software“: eigener Name und Schlüssel, Regel „Alle Dateien außer
Ausnahmen“. Die Software prüft mit `Pruefmodul/signatur_pruefen.py`.

## Sicherung

Die privaten Schlüssel liegen mit Kennwort verschlüsselt in
`%APPDATA%\Signier-Werkzeug\schluessel`. Diesen Ordner auf einen USB-Stick kopieren und das
Kennwort sicher aufbewahren. Private Schlüssel gehören nie in dieses Repository.
