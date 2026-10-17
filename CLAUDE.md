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
  Platzhalter. Einzige Ausnahme: `WERKZEUG_REPO` (Quelle der eigenen Updates, funktional nötig)
  samt öffentlichem Herausgeber-Schlüssel. Private Schlüssel nie ins Repository.
- Actions in Workflows nur mit vollständigen Commit-SHAs.
- Tests: `python -m unittest discover -s tests -v`; Selbsttest:
  `python signier_werkzeug.py --selbsttest selbst.txt`.
