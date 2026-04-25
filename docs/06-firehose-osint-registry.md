# 06 Registry, Firehose und OSINT

## Ziel

Dieses Kapitel erklärt, wie LicenseSeal vom lokalen Audit zum kontinuierlichen IP-Radar wird.

## Registry

Die Registry speichert:

- Projekte
- Fingerprints
- Honey-Logic-Signaturen
- Scan-Ergebnisse
- Evidence Items
- Scores
- Zeitpunkte

Initialisieren:

```powershell
licenseseal registry init
```

Projekt registrieren:

```powershell
licenseseal registry register .
```

Suchen oder listen:

```powershell
licenseseal registry list
licenseseal registry search "payment-service"
```

## Firehose

Die Firehose scannt Kandidaten:

```powershell
licenseseal firehose scan C:\repos\suspected
```

Oder eine Git-URL, falls Git verfügbar ist:

```powershell
licenseseal firehose scan https://github.com/example/suspected-repo.git
```

## Queue-Modus

Für Enterprise-Skalierung kann die Firehose Jobs in eine Queue legen:

```powershell
licenseseal firehose enqueue https://github.com/example/suspected-repo.git
licenseseal firehose worker
```

Redis/Celery sind optional. Ohne Infrastruktur bleibt der lokale Modus nutzbar.

## OSINT

OSINT-Module suchen aktiv nach Kandidaten auf Plattformen wie GitHub oder GitLab.

```powershell
licenseseal osint --help
```

Typische Idee:

```powershell
licenseseal osint github --query "_ls_fold_a1b2" --enqueue
```

Je nach Build können konkrete Subcommands variieren. Prüfe:

```powershell
licenseseal osint --help
```

## Empfohlener Enterprise-Ablauf

```text
1. Eigenes Projekt markieren
2. Projekt in Registry registrieren
3. OSINT sucht Kandidaten
4. Kandidaten landen in Queue
5. Worker scannen Kandidaten
6. Evidence Items werden gespeichert
7. Control Plane zeigt Alerts
8. Legal-Team prüft Reports
```

## Datenschutz und Rate Limits

Bei öffentlichen APIs gilt:

- API-Token sicher speichern
- Rate Limits beachten
- keine unnötigen Daten klonen
- nur rechtmäßig zugängliche Quellen scannen
- Ergebnisse intern prüfen, bevor Maßnahmen erfolgen

## Übung

1. Registriere ein Testprojekt
2. Kopiere es in einen zweiten Ordner
3. Scanne den zweiten Ordner mit Firehose
4. Prüfe, welche Evidence Signals erzeugt werden
