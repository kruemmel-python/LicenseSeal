# LicenseSeal

LicenseSeal ist eine defensive **Enterprise IP Protection Suite** für Software-Provenance, Lizenz-Compliance und Auditierbarkeit. Das Tool versieht Quellcode, Notebooks, Datensätze und Build-Artefakte mit maschinenlesbaren Herkunftssignalen und kann später prüfen, ob Code ohne Marker kopiert, refaktorisiert oder durch KI-Systeme umgeschrieben wurde.

LicenseSeal ist **kein DRM**, kein Exploit-Framework und kein Rechtsgutachten. Es ist ein Provenance-, Compliance- und Evidence-Werkzeug, das technische Indizien nachvollziehbar sammelt.

---

## Inhalt dieses Builds

Diese Version enthält die Enterprise-IP-Radar-Erweiterungen bis v3:

- klassische LicenseSeal-Marker, Audit und Compare
- kryptografische Signaturen
- Jupyter-Notebook- und `.jsonl`-Dataset-Unterstützung
- Honey-Logic und Multi-Language Honey-Logic
- Firehose Scanner und optionale Celery/Redis Queue
- OSINT Discovery für GitHub/GitLab
- Side-by-Side Evidence Diff
- Red-Team Stress Tests mit lokalem Fallback, Ollama und LM Studio
- Binary Provenance
- semantisches morphendes Watermarking
- CFG/DFG Graph Fingerprinting
- Auto-Remediation Bot für CI/CD
- LLM Prompt/Context Interceptor für Ollama, LM Studio und OpenAI-kompatible Endpunkte
- FastAPI Enterprise Control Plane mit API-Key/RBAC-Grundlage
- SCA-/Lizenzkonfliktprüfung vor Injection

---

## Installation

### Lokale Basisinstallation

Im entpackten Projektordner:

```powershell
python -m pip install -e .
```

### Vollinstallation mit allen optionalen Features

```powershell
python -m pip install -e ".[full]"
```

Die Vollinstallation zieht unter anderem optionale Pakete für Crypto, Tree-Sitter, LSP, Enterprise Registry, Reports, Queue, Control Plane und Bot-Unterstützung nach.

### Einzelne Extras

```powershell
python -m pip install -e ".[crypto]"
python -m pip install -e ".[treesitter]"
python -m pip install -e ".[lsp]"
python -m pip install -e ".[enterprise]"
python -m pip install -e ".[queue]"
python -m pip install -e ".[control-plane]"
python -m pip install -e ".[bot]"
python -m pip install -e ".[reports]"
```

### Hinweis zum Packaging-Fix

Dieses Paket nutzt explizite Setuptools Package Discovery:

```toml
[tool.setuptools.packages.find]
include = ["licenseseal", "licenseseal.*"]
```

Dadurch werden zusätzliche Ordner im Repository, zum Beispiel `Notebook_LM/`, nicht versehentlich als Python-Package installiert. Falls du wieder den Fehler `Multiple top-level packages discovered` siehst, prüfe, ob diese Sektion in `pyproject.toml` vorhanden ist.

---

## Schnellstart

### Marker trocken testen

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --dry-run
```

### Marker schreiben

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --backup
```

### Marker aktualisieren

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --update --backup
```

### Audit ausführen

```powershell
licenseseal audit .
```

### GitHub-Annotationen erzeugen

```powershell
licenseseal audit . --format github
```

### Marker entfernen

```powershell
licenseseal remove . --backup
```

---

## Kryptografische Provenance

Schlüssel erzeugen:

```powershell
licenseseal keygen --private-key .licenseseal/private_key.pem --public-key .licenseseal/public_key.pem
```

Beim Injizieren signieren:

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --sign-key .licenseseal/private_key.pem --update
```

Audit mit Public Key:

```powershell
licenseseal audit . --verify-key .licenseseal/public_key.pem
```

Marker enthalten dann zusätzlich:

```text
CONTENT_DIGEST: sha256:...
AI_SIGNATURE: ...
```

---

## SCA- und Lizenzkonfliktprüfung

LicenseSeal prüft vor dem Inject lokale Manifestdateien und warnt bei Konflikten zwischen Ziel-Lizenz und Projekt-/Dependency-Kontext.

Unterstützte Manifesttypen:

- `pyproject.toml`
- `package.json`
- `pom.xml`
- `Cargo.toml`
- `go.mod`
- `requirements.txt`

Beispiele:

```powershell
licenseseal sca check . --license AGPL-3.0 --fail-on-error
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp"
```

Kontrollierte Ausnahmen:

```powershell
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp" --force
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp" --skip-sca
```

`--force` fährt trotz Blockern fort. `--skip-sca` deaktiviert die Manifestprüfung vollständig.

---

## Jupyter Notebooks und KI-Datensätze

`.ipynb`-Dateien werden als Notebooks behandelt, nicht als normaler Text. LicenseSeal fügt eine idempotente erste Markdown-Zelle ein und speichert maschinenlesbare Daten unter:

```text
metadata.licenseseal
```

Der Notebook-Digest basiert auf Code-Zellen. Outputs, Execution Counts und flüchtige Notebook-Zustände invalidieren die Provenance nicht.

```powershell
licenseseal inject notebooks/ --owner "ACME Corp" --license MIT --update
licenseseal audit notebooks/
```

`.jsonl`-Datensätze werden über Sidecar-Dateien geschützt:

```text
dataset.jsonl.licenseseal.json
```

Dadurch werden Trainingsdaten nicht verändert.

---

## Honey-Logic und Multi-Language Honey-Logic

Honey-Logic sind kleine, funktional harmlose, aber mathematisch spezifische Code-Sentinels. Sie dienen als robuste Provenance-Spur, die Umbenennungen und Formatierung besser übersteht als Kommentare.

Python-Honey-Logic und Watermarks:

```powershell
licenseseal watermark embed . --project-id acme-core --signature stable-signature --strength robust
```

Multi-Language Honey-Logic für Python, JavaScript, TypeScript, Go, Rust und Java:

```powershell
licenseseal honey-multilang inject . --project-id acme-core --signature "$env:LICENSESEAL_SECRET"
licenseseal honey-multilang scan .
```

Die Firehose erkennt diese Fingerprints als Evidence Signal.

---

## Projektvergleich und Evidence Diff

Klassischer Strukturvergleich:

```powershell
licenseseal compare ./original ./suspected --output report.json
```

Side-by-Side AST-/Line-Mapping für Reports und Web-UI:

```text
POST /api/diff
```

Die Mappings zeigen, welche Bereiche im Original und im verdächtigen Projekt strukturell zusammengehören, auch wenn Bezeichner umbenannt wurden.

---

## CFG/DFG Graph Fingerprinting

Graph Fingerprinting ergänzt AST-Shingling um normalisierte Kontrollfluss- und Datenfluss-Fingerprints. Das hilft gegen starke Refactorings und KI-Code-Laundering.

```powershell
licenseseal graph compare ./original ./suspected --output graph-report.json
```

Der Firehose Scanner kann zusätzlich `graph_similarity` als Evidence Item erfassen, wenn Projektwurzeln verfügbar sind.

---

## Firehose Scanner

Der Firehose Scanner prüft lokale Pfade oder Git-URLs gegen registrierte Provenance-Signale.

```powershell
licenseseal firehose scan ./suspected-copy --output firehose-report.json
```

Mit Registry:

```powershell
licenseseal registry init --database-url postgresql://localhost:5432/licenseseal
licenseseal registry register . --database-url postgresql://localhost:5432/licenseseal --owner "ACME Corp" --license-id MIT --project-id acme-core
licenseseal firehose scan ./suspected-copy --database-url postgresql://localhost:5432/licenseseal --output firehose-report.json
```

Der Scanner speichert `scan_results` und feingranulare `evidence_items`, statt automatisch juristische Schlüsse zu ziehen.

---

## Verteilte Firehose Queue

Für Enterprise-Skalierung kann die Firehose über Celery/Redis verteilt werden.

```powershell
licenseseal firehose enqueue https://github.com/example/repo
licenseseal firehose worker
```

Alternativ direkt mit Celery:

```powershell
celery -A licenseseal.firehose_queue.celery_app worker --loglevel=INFO
```

Redis/Celery sind optionale Dependencies. Ohne Queue läuft der Scanner lokal synchron.

---

## OSINT Discovery

Der OSINT-Crawler sucht über offizielle APIs nach seltenen Honey-Logic-Terms und kann Treffer in die Firehose Queue einspeisen.

```powershell
licenseseal osint --provider github --term _ls_fold_a1b2c3 --enqueue
licenseseal osint --provider gitlab --term _ls_fold_a1b2c3 --base-url https://gitlab.example.com/api/v4
```

Tokens werden vom Nutzer bereitgestellt. LicenseSeal umgeht keine Zugriffskontrollen.

---

## Red-Team Stress Tests

Stress Tests simulieren autorisierte Refactoring- und Rewrite-Szenarien und messen, ob Watermarks/Honey-Logic erhalten bleiben.

```powershell
licenseseal stress-test . --mode local --sample-size 5
licenseseal stress-test . --mode ollama --ollama-model codellama
licenseseal stress-test . --mode lmstudio --lmstudio-url http://localhost:1234/v1/chat/completions
```

Der Zweck ist defensiv: eigene Markierungen gegen legitime Rewrite-Simulationen testen.

---

## Semantisches morphendes Watermarking

Das semantische Morphing kann Watermark-Invarianten in ungefährliche Code-Transformationen einweben. Es unterstützt lokalen deterministischen Fallback, Ollama und LM Studio.

```powershell
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend local
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend ollama --ollama-model codellama
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend lmstudio --lmstudio-model local-model
licenseseal semantic-morph verify src/module.py --seed "$env:LICENSESEAL_SECRET"
```

---

## Binary Provenance

LicenseSeal kann Provenance-Metadaten für Build-Systeme erzeugen oder in Test-Artefakte einbetten.

Go `-ldflags`:

```powershell
licenseseal binary create . --format go-ldflags
```

C/C++ Section Source:

```powershell
licenseseal binary create . --format c-section --output licenseseal_note.c
```

JAR Manifest:

```powershell
licenseseal binary create . --format jar-manifest
```

Append/Audit für Testartefakte:

```powershell
licenseseal binary append . ./dist/app --output ./dist/app.sealed
licenseseal binary audit ./dist/app.sealed
```

---

## LSP und IDE-Integration

Das LSP-Modul unterstützt:

- Diagnostics für fehlende/ungültige Marker
- Code Actions / Quick Fixes für Marker-Injection
- Inbound Paste-Protection-Primitiven für große eingefügte Codeblöcke
- Lizenz- und Boundary-Erkennung für IDE-Integrationen

Workspace-Defaults in VS Code:

```json
{
  "licenseseal.owner": "ACME Corp",
  "licenseseal.license": "MIT",
  "licenseseal.project": "acme-core"
}
```

---

## LLM Prompt und Context Interceptor

Der Interceptor ist ein defensiver lokaler Scanner/Proxy für Ollama, LM Studio und OpenAI-kompatible Workflows. Er prüft Prompts und Antworten auf LicenseSeal-Marker, Zero-Width-Watermarks, Honey-Logic und Copyleft-Indikatoren.

Datei scannen:

```powershell
licenseseal intercept scan suspicious-output.py
```

Proxy für Ollama:

```powershell
licenseseal intercept serve --target ollama --port 11435
```

Proxy für LM Studio:

```powershell
licenseseal intercept serve --target lmstudio --port 1235
```

---

## Auto-Remediation Bot

Der Bot kann Audits ausführen, Marker injizieren/aktualisieren und optional in GitHub Actions einen Pull Request erzeugen.

```powershell
licenseseal bot autofix . --license MIT --owner "ACME Corp" --create-pr
```

Die GitHub Action unterstützt:

```yaml
with:
  root: "."
  license: MIT
  owner: ACME Corp
  auto-fix: "true"
  create-pr: "true"
```

Ohne GitHub-Token kann der Bot lokal als Autofix/Dry-Run genutzt werden.

---

## Enterprise Control Plane

Die FastAPI Control Plane stellt APIs für Projekte, Scans, Alerts und Webhooks bereit. API-Key-Auth und einfache RBAC-Rollen sind enthalten; OIDC/SAML kann in Enterprise-Deployments davor geschaltet oder optional ergänzt werden.

Start:

```powershell
$env:LICENSESEAL_API_KEY="dev-local"
licenseseal control-plane serve --port 8787
```

Header:

```text
X-LicenseSeal-API-Key: dev-local
```

Typische Rollen:

```text
admin
legal
developer
viewer
```

---

## Weboberfläche

Lokale Weboberfläche starten:

```powershell
licenseseal web --open-browser
```

Standardadresse:

```text
http://127.0.0.1:8765/
```

Sicherheitshinweis: Die lokale Weboberfläche bindet standardmäßig an `127.0.0.1`. Binde sie nur bewusst an `0.0.0.0`, wenn der Zugriff abgesichert ist.

---

## Pre-Commit

Beispielkonfiguration:

```yaml
repos:
  - repo: local
    hooks:
      - id: licenseseal-audit
        name: LicenseSeal Audit
        entry: licenseseal audit . --format github
        language: system
        pass_filenames: false
```

---

## GitHub Action

Beispielworkflow:

```yaml
name: LicenseSeal

on:
  pull_request:
  push:
    branches: [ main, master ]

jobs:
  licenseseal:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: LicenseSeal audit
        uses: ./
        with:
          root: "."
          license: MIT
          owner: ACME Corp
          include-configs: "true"
          auto-fix: "true"
          create-pr: "true"
```

---

## Unterstützte Dateitypen

Unter anderem:

- Python, Shell, Ruby, Perl, R, Julia
- JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, Swift, Kotlin, Scala, PHP, Dart
- SQL, Lua, Haskell, Erlang, Elixir, Clojure, Lisp
- Jupyter Notebooks (`.ipynb`)
- `.jsonl`-Datasets über Sidecar-Provenance
- ausgewählte Configs mit `--include-configs`

---

## Sicherheit und Abgrenzung

LicenseSeal ist defensiv ausgelegt.

LicenseSeal:

- verändert keine fremden Repositories ohne lokalen Schreibzugriff des Nutzers
- führt keine Angriffe aus
- exfiltriert keine Daten
- umgeht keine Zugriffskontrollen
- entfernt keine fremden Provenance-Marker
- sammelt technische Evidenz, ersetzt aber keine juristische Bewertung

Red-Team-, Interceptor- und Firehose-Funktionen sollten nur für Code verwendet werden, den du besitzt oder für den du eine ausdrückliche Prüfberechtigung hast.

---

## Rechtlicher Hinweis

LicenseSeal kann Herkunftssignale, strukturelle Ähnlichkeiten und technische Indizien dokumentieren. Für Durchsetzung, DMCA/Takedown, Vertragsfragen oder gerichtliche Nutzung sollten Repository-Historie, Commits, Lizenzdateien, Distributionswege und fachliche Begutachtung zusätzlich einbezogen werden.
