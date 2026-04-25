# 00 Installation und Grundbegriffe

## Ziel dieses Kapitels

Nach diesem Kapitel kannst du LicenseSeal installieren, prüfen, ob die CLI funktioniert, und verstehst die wichtigsten Begriffe.

## Voraussetzungen

Du benötigst:

- Python 3.10 oder neuer
- ein Terminal, zum Beispiel PowerShell, Windows Terminal, Terminal.app oder Bash
- optional Git, wenn du CI/CD, Bot oder Firehose-Scans nutzen möchtest
- optional Docker/Redis/PostgreSQL für Enterprise-Szenarien

Prüfe Python:

```powershell
python --version
```

Prüfe pip:

```powershell
python -m pip --version
```

## Installation aus dem Projektordner

Wechsle in den entpackten Projektordner:

```powershell
cd C:\LICENSE_SEAL
```

Installiere die Basisversion:

```powershell
python -m pip install -e .
```

Installiere die Vollversion mit allen optionalen Extras:

```powershell
python -m pip install -e ".[full]"
```

Auf macOS/Linux ist der Befehl identisch:

```bash
python -m pip install -e ".[full]"
```

## Einzelne Extras

Wenn du nicht alle Abhängigkeiten installieren möchtest, kannst du gezielt Extras wählen:

```powershell
python -m pip install -e ".[crypto]"
python -m pip install -e ".[lsp]"
python -m pip install -e ".[enterprise]"
python -m pip install -e ".[queue]"
python -m pip install -e ".[control-plane]"
python -m pip install -e ".[reports]"
```

Mehrere Extras können kombiniert werden:

```powershell
python -m pip install -e ".[crypto,lsp,enterprise]"
```

## Installation prüfen

```powershell
licenseseal --help
```

Erwartung: Du siehst eine Liste von Befehlen wie `inject`, `audit`, `compare`, `watermark`, `firehose`, `sca`, `graph`, `intercept` und weitere.

## Wichtige Begriffe

### Marker

Ein Marker ist ein maschinenlesbarer Block am Anfang einer Datei. Er beschreibt Lizenz, Projekt, Besitzer und optional Signaturinformationen.

### Boundary

Eine Boundary ist eine klare Grenze im Code, die sagt: Ab hier beginnt ein LicenseSeal-geschützter Abschnitt.

### Audit

Ein Audit prüft, ob Dateien korrekt markiert sind und ob Signaturen noch gültig sind.

### CONTENT_DIGEST

Ein Digest ist ein kryptografischer Fingerabdruck des Inhalts. Schon kleine Änderungen am relevanten Inhalt erzeugen einen anderen Digest.

### Watermark

Ein Watermark ist ein zusätzliches Wiedererkennungssignal. Es kann sichtbar, unsichtbar oder semantisch sein.

### Honey-Logic

Honey-Logic sind harmlose, funktional korrekte Code-Snippets mit sehr spezifischen mathematischen Strukturen. Sie dienen als starkes Indiz, wenn sie in fremden Repositories wieder auftauchen.

### Registry

Die Registry speichert bekannte Projekte, Fingerprints, Scan-Ergebnisse und Evidence Items.

### Firehose

Die Firehose ist der kontinuierliche Scanner. Sie prüft Kandidaten-Repositories und meldet Evidenz an die Registry.

## Typischer Installationsfehler: Multiple top-level packages

Wenn du siehst:

```text
Multiple top-level packages discovered in a flat-layout
```

dann findet Setuptools mehrere Paketordner. Dieses Projekt enthält bereits die nötige Korrektur in `pyproject.toml`:

```toml
[tool.setuptools.packages.find]
include = ["licenseseal", "licenseseal.*"]
exclude = ["Notebook_LM", "Notebook_LM.*", "tests", "tests.*"]
```

## Erste Diagnose

Wenn ein Befehl nicht gefunden wird:

```powershell
python -m licenseseal --help
```

Wenn das funktioniert, aber `licenseseal` nicht, liegt meist ein PATH-Problem der Python-Umgebung vor.

## Übung

1. Installiere LicenseSeal mit `python -m pip install -e .`
2. Führe `licenseseal --help` aus
3. Notiere drei Befehle, die du siehst
4. Öffne danach [Schnellstart](01-quickstart.md)
