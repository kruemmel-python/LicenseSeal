# LicenseSeal Dokumentation

Willkommen zur Schulungs- und Anwenderdokumentation für LicenseSeal.

Diese Dokumentation richtet sich ausdrücklich auch an Einsteigerinnen und Einsteiger. Sie erklärt nicht nur die Befehle, sondern auch den Zweck dahinter: Wie markiere ich eigenen Code? Wie prüfe ich ein Projekt? Wie erkenne ich mögliche Kopien? Wie nutze ich die Enterprise-Funktionen sicher?

## Lernpfad für Anfänger

Empfohlene Reihenfolge:

1. [Installation und Grundbegriffe](00-installation.md)
2. [Schnellstart: erstes Projekt schützen](01-quickstart.md)
3. [Core Workflows: Inject, Audit, Compare, Remove](02-core-workflows.md)
4. [Jupyter Notebooks und Datensätze](03-jupyter-datasets.md)
5. [Watermarking und Honey-Logic](04-watermark-honey-logic.md)
6. [Audit, Vergleich und Reports](05-audit-compare-reports.md)
7. [Registry, Firehose und OSINT](06-firehose-osint-registry.md)
8. [IDE/LSP und Inbound Paste Protection](07-ide-lsp-inbound-protection.md)
9. [LLM Red-Team, Ollama, LM Studio und Interceptor](08-llm-redteam-interceptor.md)
10. [Binary Provenance](09-binary-provenance.md)
11. [CI/CD Bot und GitHub Actions](10-cicd-bot-github-actions.md)
12. [Enterprise Control Plane](11-enterprise-control-plane.md)
13. [SCA und Lizenzkonflikte](12-sca-license-compliance.md)
14. [Troubleshooting](13-troubleshooting.md)
15. [Glossar](14-glossary.md)

## Was LicenseSeal ist

LicenseSeal ist ein defensives Provenance-, Audit- und IP-Schutzwerkzeug. Es hilft dabei, eigene Softwareprojekte mit maschinenlesbaren Lizenz- und Herkunftsmarkern zu versehen, die Integrität später zu prüfen und mögliche unautorisierte Übernahmen besser zu erkennen.

## Was LicenseSeal nicht ist

LicenseSeal ist kein Tool zum Entfernen fremder Schutzmechanismen, kein Exploit-Framework und kein Angriffswerkzeug. Alle Funktionen sind für defensive Nutzung, Compliance, Audit, Herkunftsnachweis und interne Qualitätssicherung gedacht.

## Häufige Tagesaufgaben

| Aufgabe | Einstieg |
|---|---|
| Projekt markieren | [Core Workflows](02-core-workflows.md) |
| Projekt prüfen | [Schnellstart](01-quickstart.md) |
| Zwei Projekte vergleichen | [Audit und Reports](05-audit-compare-reports.md) |
| Notebook schützen | [Jupyter und Datensätze](03-jupyter-datasets.md) |
| Lizenzkonflikt prüfen | [SCA](12-sca-license-compliance.md) |
| IDE integrieren | [IDE/LSP](07-ide-lsp-inbound-protection.md) |
| LLM-Ausgaben prüfen | [LLM Interceptor](08-llm-redteam-interceptor.md) |
| CI automatisch reparieren | [CI/CD Bot](10-cicd-bot-github-actions.md) |
| Enterprise Dashboard starten | [Control Plane](11-enterprise-control-plane.md) |

## Schreibweise in dieser Dokumentation

Beispiele für Windows PowerShell verwenden:

```powershell
python -m pip install -e ".[full]"
licenseseal audit .
```

Beispiele für macOS/Linux verwenden:

```bash
python -m pip install -e ".[full]"
licenseseal audit .
```

Wenn kein Unterschied besteht, funktioniert der Befehl auf allen Plattformen.
