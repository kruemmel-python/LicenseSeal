# 03 Jupyter Notebooks und Datensätze

## Warum eigene Unterstützung nötig ist

Jupyter Notebooks sind JSON-Dateien. Ein normaler Kommentarblock am Dateianfang würde das Notebook beschädigen. LicenseSeal behandelt `.ipynb` daher speziell.

Auch Datensätze wie `.jsonl` werden in KI-Projekten oft kopiert oder weitergegeben. LicenseSeal kann Sidecar-Provenance-Dateien verwenden, um sie nachvollziehbar zu machen.

## Notebook markieren

```powershell
licenseseal inject . --license MIT --owner "Data Science Team" --project "fraud-model"
```

Wenn `.ipynb`-Dateien enthalten sind, erzeugt LicenseSeal:

1. eine Markdown-Zelle am Anfang des Notebooks
2. Notebook-Metadaten unter `metadata.licenseseal`
3. einen Digest nur über relevante Code-Zellen

## Warum nur Code-Zellen für den Digest?

Notebook-Ausgaben ändern sich ständig:

- Ausführungsnummern
- Diagramme
- Logs
- zufällige Werte
- Zeitstempel

Wenn der Digest alle Outputs enthalten würde, wäre er nach jedem Run ungültig. Deshalb fokussiert LicenseSeal auf Code-Zellen.

## Notebook prüfen

```powershell
licenseseal audit .
```

## Beispielstruktur

```text
notebooks/
  experiment.ipynb
data/
  train.jsonl
  eval.jsonl
```

## JSONL-Datensätze

Für `.jsonl`-Dateien kann LicenseSeal eine Sidecar-Provenance-Datei anlegen. Das ist sicherer als das direkte Verändern der Daten, weil Trainingsdaten exakt reproduzierbar bleiben.

Beispiel:

```text
data/train.jsonl
data/train.jsonl.licenseseal.json
```

Die Sidecar-Datei kann enthalten:

```json
{
  "schema": "licenseseal.dataset.v1",
  "license": "Proprietary",
  "owner": "ACME GmbH",
  "content_digest": "..."
}
```

## Best Practices für ML-Teams

1. Markiere Notebooks vor dem Teilen.
2. Speichere Sidecar-Dateien zusammen mit Datensätzen.
3. Prüfe Notebooks in CI, aber ignoriere große Output-Diffs.
4. Committe keine sensiblen Daten, nur Provenance-Metadaten.
5. Nutze klare Projektnamen, zum Beispiel `risk-model-q4`.

## Übung

1. Erstelle ein Notebook mit einer Code-Zelle
2. Führe `licenseseal inject .` aus
3. Öffne das Notebook und suche die Markdown-Markerzelle
4. Führe das Notebook aus und prüfe danach mit `licenseseal audit .`
