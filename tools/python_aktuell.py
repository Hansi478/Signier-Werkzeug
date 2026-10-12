# -*- coding: utf-8 -*-
"""Prüft, ob die in bauen.yml festgelegte Python-Version die neueste ihrer
Reihe ist, die es für Windows (x64) gibt. Diese Laufzeit wird in die exe
eingebaut - Sicherheitskorrekturen kommen nur mit einer neueren Version an.

    python tools/python_aktuell.py .github/workflows/bauen.yml

Exit-Code 0 = aktuell, 1 = neuere Version verfügbar oder Prüfung nicht möglich.
"""
import json
import re
import sys
import urllib.request

MANIFEST = "https://raw.githubusercontent.com/actions/python-versions/main/versions-manifest.json"


def festgelegt(workflow):
    with open(workflow, encoding="utf-8") as f:
        m = re.search(r'python-version:\s*"(\d+\.\d+\.\d+)"', f.read())
    if not m:
        raise SystemExit(f"Keine feste Python-Version (x.y.z) in {workflow} gefunden.")
    return m.group(1)


def tupel(v):
    return tuple(int(x) for x in v.split("."))


def neueste_windows(manifest, reihe):
    kandidaten = [e["version"] for e in manifest if e.get("stable") and re.fullmatch(r"\d+\.\d+\.\d+", e["version"])
                  and e["version"].startswith(reihe + ".")
                  and any(f.get("platform") == "win32" and f.get("arch") == "x64" for f in e.get("files") or [])]
    return max(kandidaten, key=tupel) if kandidaten else None


def main():
    version = festgelegt(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/bauen.yml")
    reihe = ".".join(version.split(".")[:2])
    with urllib.request.urlopen(MANIFEST, timeout=60) as r:
        manifest = json.load(r)
    neu = neueste_windows(manifest, reihe)
    if not neu:
        print(f"Für Python {reihe} gibt es keine Windows-Ausgaben mehr - auf eine neuere Python-Reihe wechseln.")
        return 1
    if tupel(neu) > tupel(version):
        print(f"Python {version} ist veraltet: {neu} ist für Windows verfügbar. In bauen.yml/pruefen.yml/sicherheit.yml "
              "anheben, testen und ein neues Release bauen.")
        return 1
    print(f"Python {version} ist die neueste Windows-Version der Reihe {reihe}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
