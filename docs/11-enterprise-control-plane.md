# 11 Enterprise Control Plane

## Ziel

Die Control Plane ist ein API- und Dashboard-Grundgerüst für Teams, Legal, Security und Compliance.

## Installation

```powershell
python -m pip install -e ".[control-plane]"
```

## Starten

```powershell
licenseseal control-plane serve --port 8787
```

Dann im Browser öffnen:

```text
http://localhost:8787
```

Je nach Konfiguration kann auch nur die API bereitstehen.

## Authentifizierung

Die Control Plane unterstützt API-Key-basierte Authentifizierung als robuste lokale Basis. SSO/OIDC/SAML sind als Enterprise-Erweiterung vorbereitet und hängen in der Praxis vom Identity Provider ab.

Typische Rollen:

| Rolle | Rechte |
|---|---|
| admin | alles |
| legal | Reports, Evidence, Alerts |
| developer | Projekt- und Scanansicht |
| viewer | nur Lesen |

## Wichtige Bereiche

### Projekte

- registrierte Projekte
- Lizenzen
- Owner
- Fingerprints
- Status

### Scans

- Firehose-Ergebnisse
- Kandidaten
- Scores
- Evidence Items

### Alerts

- High Similarity
- Honey-Logic Treffer
- inkompatible Lizenzen
- verdächtige LLM-Ausgabe

### Webhooks

- Slack
- Jira
- generische HTTP-Endpoints
- interne SOAR/SIEM-Systeme

## Beispiel Webhook Event

```json
{
  "event": "high_similarity_detected",
  "project": "payment-service",
  "score": 0.91,
  "candidate": "https://github.com/example/suspected"
}
```

CLI Event senden:

```powershell
licenseseal control-plane event --help
```

## Produktionshinweise

Für Produktion:

1. hinter Reverse Proxy betreiben
2. TLS aktivieren
3. API Keys rotieren
4. PostgreSQL statt lokaler Dateien verwenden
5. Logs zentral sammeln
6. Webhook-Ziele whitelisten
7. RBAC regelmäßig prüfen

## Übung

1. Starte die Control Plane lokal
2. Rufe die API im Browser auf
3. Registriere ein Testprojekt
4. Sende ein Testevent
5. Prüfe, ob es in der Alert-Ansicht erscheint
