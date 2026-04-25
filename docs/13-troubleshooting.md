# 13 Troubleshooting

## `licenseseal` wird nicht gefunden

Versuche:

```powershell
python -m licenseseal --help
```

Wenn das funktioniert, liegt ein PATH-Problem vor. Aktiviere deine virtuelle Umgebung oder prüfe Scripts-Pfade.

## Editable Install schlägt fehl

Fehler:

```text
Multiple top-level packages discovered in a flat-layout
```

Dieses Projekt enthält bereits die Korrektur in `pyproject.toml`. Prüfe, ob du die aktuelle ZIP-Version verwendest.

## `[full]` dauert lange

Das Full-Extra installiert auch schwere AI-Abhängigkeiten wie Torch und Sentence Transformers. Für Grundtests reicht:

```powershell
python -m pip install -e .
```

Oder gezielt:

```powershell
python -m pip install -e ".[crypto,lsp]"
```

## WeasyPrint installiert nicht

Reports mit PDF können systemabhängige Bibliotheken benötigen. Nutze zunächst HTML/JSON-Reports oder installiere das `reports`-Extra später.

## Redis/Celery nicht verfügbar

Der lokale Firehose-Modus funktioniert trotzdem:

```powershell
licenseseal firehose scan ./suspected
```

Queue-Funktionen benötigen Redis/Celery:

```powershell
python -m pip install -e ".[queue]"
```

## Ollama nicht erreichbar

Prüfe:

```powershell
curl http://localhost:11434
```

Starte Ollama und prüfe Modellnamen.

## LM Studio nicht erreichbar

In LM Studio muss der lokale Server aktiviert sein. Häufig:

```text
http://localhost:1234/v1
```

## Audit meldet fehlende Marker

Führe aus:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --update
```

Oder im CI Bot:

```powershell
licenseseal bot autofix . --license MIT --owner "ACME GmbH"
```

## Signaturprüfung schlägt fehl

Mögliche Ursachen:

- Datei wurde nach Signierung geändert
- falscher Public Key
- Marker manuell verändert
- Zeilenenden wurden geändert

Lösung:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --sign-key private.pem --update
```

## SCA blockiert Inject

Prüfe:

```powershell
licenseseal sca check . --license MIT
```

Nur bewusst überschreiben:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --force
```

## Debug-Strategie

1. `licenseseal --help`
2. `licenseseal <command> --help`
3. kleine Testdatei isoliert prüfen
4. `--dry-run` verwenden
5. optionales Extra gezielt installieren
6. Exit Code und Fehlermeldung notieren
