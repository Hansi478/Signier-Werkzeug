# Hinweise für Sitzungen an diesem Repository

- Antworten auf Deutsch, Anrede „du“. Versionsnummern vergibt der Benutzer.
- Vor größeren Änderungen: Plan mit Risiken und Aufwand als Tabelle vorlegen.
- **Prompt zur Einbindung pflegen:** `einbindung_prompt.py` ist der Text, den das Werkzeug je
  Profil („andere Software“) erzeugt, damit eine andere Sitzung dort die Signaturprüfung
  einbaut. Ändert sich etwas, das dafür wichtig ist – Format, Dateiauswahl, Prüfsummen-Regel,
  Ablauf von Signieren/Hochladen/Tag, `Pruefmodul/signatur_pruefen.py`, Empfehlungen zu
  Schlüssel, Tags oder Updates, oder eine neue Erkenntnis aus einem eingebundenen Projekt –,
  die Vorlage **im selben Commit** anpassen. `PRUEFMODUL_SHA256` in `signier_werkzeug.py`
  muss zur Datei passen; `tests/test_einbindung.py` prüft das.
- Keine echten Namen, Adressen, Hosts oder Pfade in Quelltext, Vorlagen oder Tests – nur
  Platzhalter. Ausnahmen: `WERKZEUG_REPO` (Quelle der eigenen Updates, funktional nötig)
  samt öffentlichem Herausgeber-Schlüssel, und der Copyright-Vermerk des Urhebers im Handbuch
  (`docs/handbuch_quelle.html`, `Handbuch.pdf`) und in der README (vom Benutzer so gewünscht).
- **Handbuch nur als PDF:** Ändert sich etwas, das Benutzer betrifft, `docs/handbuch_quelle.html`
  anpassen und mit `node docs/handbuch_pdf.js` `Handbuch.pdf` neu erzeugen – auch bei jeder
  neuen Version (der Test prüft die Version im PDF). Private Schlüssel nie ins Repository.
- Actions in Workflows nur mit vollständigen Commit-SHAs.
- Tests: `python -m unittest discover -s tests -v`; Selbsttest:
  `python signier_werkzeug.py --selbsttest selbst.txt`.
