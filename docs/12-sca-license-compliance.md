# 12 SCA und Lizenzkonflikte

## Ziel

LicenseSeal soll nicht nur Marker setzen, sondern auch verhindern, dass falsche oder widersprüchliche Lizenzinformationen injiziert werden.

## Was ist SCA?

SCA bedeutet Software Composition Analysis. Es geht darum, Projektmetadaten und Abhängigkeiten auf Lizenzrisiken zu prüfen.

## Unterstützte Manifest-Dateien

LicenseSeal kann unter anderem auswerten:

- `pyproject.toml`
- `package.json`
- `pom.xml`
- `Cargo.toml`
- `go.mod`
- `requirements.txt`

## Projekt prüfen

```powershell
licenseseal sca check . --license MIT
```

Mit Fehlercode bei Konflikten:

```powershell
licenseseal sca check . --license AGPL-3.0 --fail-on-error
```

## Inject mit SCA

Standardmäßig wird beim Inject geprüft:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH"
```

Wenn ein Konflikt erkannt wird, kann LicenseSeal warnen oder blockieren.

## Force und Skip

Nur bewusst verwenden:

```powershell
licenseseal inject . --license AGPL-3.0 --owner "ACME GmbH" --force
```

SCA komplett überspringen:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --skip-sca
```

## Beispielkonflikte

| Projektsituation | Geplante Lizenz | Ergebnis |
|---|---|---|
| Projekt deklariert MIT | MIT | OK |
| Projekt deklariert Proprietary | AGPL-3.0 | Warnung/Fehler |
| package.json deklariert Apache-2.0 | MIT | meist kompatibel, prüfen |
| AGPL-Abhängigkeit in proprietärem Projekt | Proprietary | hohes Risiko |

## Wichtiger Hinweis

LicenseSeal ersetzt keine Rechtsberatung. Das Tool liefert technische Hinweise und Compliance-Warnungen. Lizenzentscheidungen sollten bei relevanten Projekten durch Legal geprüft werden.

## Empfohlener Workflow

```text
1. sca check ausführen
2. Konflikte prüfen
3. Lizenzentscheidung dokumentieren
4. inject ausführen
5. audit in CI aktivieren
```

## Übung

1. Lege eine `package.json` mit `"license": "MIT"` an
2. Führe `licenseseal sca check . --license MIT` aus
3. Wiederhole mit `--license AGPL-3.0`
4. Vergleiche Warnungen und Exit Codes
