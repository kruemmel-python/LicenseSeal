# 02 Core Workflows: Inject, Audit, Compare, Remove

## Überblick

Die vier wichtigsten Grundbefehle sind:

```text
inject  → Marker einfügen oder aktualisieren
audit   → Projekt prüfen
compare → zwei Projekte strukturell vergleichen
remove  → Marker entfernen
```

## Inject

### Standard

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH"
```

### Mit Projektname

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --project "payment-service"
```

### Aktualisieren vorhandener Marker

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --update
```

### Konfigurationsdateien einschließen

Standardmäßig werden Quellcodedateien priorisiert. Wenn du auch Konfigurationsdateien markieren möchtest:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --include-configs
```

### Ordner ausschließen

```powershell
licenseseal inject . --exclude-dir node_modules --exclude-dir dist --exclude-dir build
```

## Signierte Marker

Für stärkere Integrität kannst du Schlüssel erzeugen:

```powershell
licenseseal keygen private.pem public.pem
```

Danach signiert injizieren:

```powershell
licenseseal inject . --license MIT --owner "ACME GmbH" --sign-key private.pem
```

Audit mit Signaturprüfung:

```powershell
licenseseal audit . --verify-key public.pem
```

## Audit

```powershell
licenseseal audit .
```

Mit GitHub-Annotationen für CI:

```powershell
licenseseal audit . --format github
```

Mit Signaturprüfung:

```powershell
licenseseal audit . --verify-key public.pem
```

## Compare

Vergleiche ein Originalprojekt mit einem verdächtigen Projekt:

```powershell
licenseseal compare C:\repos\original C:\repos\suspected --output compare.json
```

Typische Ausgabe enthält:

- strukturelle Ähnlichkeit
- Lizenzstatus
- betroffene Dateien
- Hinweise auf fehlende Marker

## Remove

```powershell
licenseseal remove .
```

Mit Backup:

```powershell
licenseseal remove . --backup
```

## Schreib-Policies

Je nach Projektstand kann eine Write-Policy sinnvoll sein. Beispiele:

```powershell
licenseseal inject . --write-policy skip-existing
licenseseal inject . --write-policy overwrite
```

Nutze `licenseseal inject --help`, um die im aktuellen Build verfügbaren Optionen zu sehen.

## Best Practices

1. Nutze `--dry-run`, bevor du ein großes Repository veränderst.
2. Schließe generierte Ordner aus.
3. Verwende Signaturen für Releases.
4. Nutze CI, damit Marker nicht versehentlich verschwinden.
5. Dokumentiere Owner und Lizenz konsistent.

## Mini-Workflow für echte Projekte

```powershell
git checkout -b chore/licenseseal
licenseseal inject . --license MIT --owner "ACME GmbH" --project "core-api" --backup
licenseseal audit .
git diff
git add .
git commit -m "Add LicenseSeal provenance markers"
```

## Übung

1. Markiere ein Testprojekt
2. Ändere eine markierte Datei
3. Führe Audit mit Signaturprüfung aus, falls du signierte Marker verwendest
4. Vergleiche zwei leicht unterschiedliche Projektkopien mit `compare`
