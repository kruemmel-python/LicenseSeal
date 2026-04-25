# 10 CI/CD Bot und GitHub Actions

## Ziel

CI/CD soll Compliance nicht nur blockieren, sondern automatisch reparieren können.

## Einfacher Audit in GitHub Actions

Beispiel `.github/workflows/licenseseal.yml`:

```yaml
name: LicenseSeal

on:
  pull_request:
  push:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -e ".[crypto]"
      - run: licenseseal audit . --format github
```

## Auto-Remediation Bot

Der Bot kann fehlende Marker injizieren und optional einen Pull Request erstellen.

Lokal:

```powershell
licenseseal bot autofix . --license MIT --owner "ACME GmbH"
```

Mit PR-Erstellung:

```powershell
licenseseal bot autofix . --license MIT --owner "ACME GmbH" --create-pr
```

## GitHub Action mit Auto-Fix

Beispiel:

```yaml
name: LicenseSeal Auto Fix

on:
  pull_request:

permissions:
  contents: write
  pull-requests: write

jobs:
  licenseseal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install -e ".[bot,crypto]"
      - run: |
          licenseseal bot autofix . \
            --license MIT \
            --owner "ACME GmbH" \
            --create-pr
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
```

## Was der Bot tun kann

- Audit ausführen
- fehlende Marker ergänzen
- vorhandene Marker aktualisieren
- Branch erzeugen
- Commit erzeugen
- Pull Request erstellen

## Was der Bot nicht tun sollte

- automatisch Lizenzentscheidungen treffen, die rechtlich unklar sind
- sensible Dateien ohne Review verändern
- generierte Artefakte markieren, wenn sie nicht Teil der Source-of-Truth sind

## Empfohlene Branch-Namen

```text
licenseseal/auto-fix
licenseseal/auto-fix-2026-04-26
```

## Übung

1. Erstelle ein Testrepo
2. Entferne Marker aus einer Datei
3. Führe `licenseseal bot autofix .` aus
4. Prüfe `git diff`
5. Entscheide, ob die Änderung commitfähig ist
