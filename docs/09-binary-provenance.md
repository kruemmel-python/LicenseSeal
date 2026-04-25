# 09 Binary Provenance

## Ziel

Source-Marker verschwinden oft beim Kompilieren. Binary Provenance bettet Herkunftsmetadaten in Build-Artefakte ein oder macht sie auditierbar.

## Unterstützte Ideen

LicenseSeal enthält Hilfen für:

- Go `-ldflags`
- C/C++ Section Source
- JAR Manifest Metadata
- Binary Audit per Byte-Scan

## CLI

```powershell
licenseseal binary --help
licenseseal binary create --help
licenseseal binary append --help
licenseseal binary audit --help
```

## Go Beispiel

Erzeuge Provenance-Daten:

```powershell
licenseseal binary create --project "payment-service" --owner "ACME GmbH" --output provenance.json
```

Baue mit Go-LDFlags:

```powershell
go build -ldflags "-X main.LicenseSealProvenance=$(Get-Content provenance.json -Raw)" .
```

Praktisch wird man die JSON-Zeichenkette oft vorher minifizieren oder escapen.

## C/C++ Beispiel

LicenseSeal kann eine kleine C-Datei erzeugen, die Provenance-Daten in eine Section legt. Danach wird sie in den Build eingebunden.

Beispielkonzept:

```c
__attribute__((section(".note.licenseseal")))
const char LICENSESEAL_PROVENANCE[] = "{...}";
```

## JAR Beispiel

Für Java-Artefakte können Metadaten in `META-INF/MANIFEST.MF` abgelegt werden:

```text
LicenseSeal-Project: payment-service
LicenseSeal-Owner: ACME GmbH
LicenseSeal-Digest: ...
```

## Binary prüfen

```powershell
licenseseal binary audit .\app.exe
licenseseal binary audit .\service.jar
```

## Best Practices

1. Bette Provenance im Release-Build ein.
2. Speichere Build-Logs und Commit-SHA.
3. Verknüpfe Binary-Provenance mit Source-Audit.
4. Signiere Release-Artefakte zusätzlich.
5. Dokumentiere Build-Rezepte reproduzierbar.

## Übung

1. Erzeuge eine Provenance-Datei
2. Hänge sie an ein Test-Binary an
3. Führe `licenseseal binary audit` aus
4. Prüfe, ob Metadaten erkannt werden
