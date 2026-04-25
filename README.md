# LicenseSeal is a defensive **Enterprise IP Protection Suite** for software provenance, license compliance, and auditability. The tool marks source code, notebooks, datasets, and build artifacts with machine-readable origin signals and can later verify whether code without markers was copied, refactored, or rewritten by AI systems.

LicenseSeal is **not DRM**, not an exploit framework, and not legal advice. It is a provenance-, compliance-, and evidence-tool that reliably collects technical evidence.

In this build’s content

## This version includes the Enterprise-IP Radar extensions up to v3:

This version includes the Enterprise IP Radar extensions up to v3:

- classic LicenseSeal markers, Audit and Compare
- cryptographic signatures
- Jupyter Notebook and `.jsonl`-Dataset support
- Honey-Logic and Multi-Language Honey-Logic
- Firehose Scanner and optional Celery/Redis Queue
- GitHub/GitLab OSINT Discovery
- Side-by-Side Evidence Diff
- Red-Team Stress Testing with Local Fallback, Ollama, and LM Studio
- Binary Provenance
- Semantic Morphing Watermarking
- CFG/DFG Graph Fingerprinting
- Automatic Remediation Bot for CI/CD
- LLM Prompt/Context Interceptor for Ollama, LM Studio, and OpenAI-compatible endpoints
- FastAPI Enterprise Control Plane with API-key/RBAC foundation
- Static Code Analysis (SCA)/License Conflict Check Before Injection

## Installation

### Local Base Installation

In the unpacked project folder:

```powershell
python -m pip install -e .
```

### Full installation with all optional features

```powershell
python -m pip install -e ".[full]"
```

The full installation includes optional packages for Crypto, Tree-Sitter, LSP, Enterprise Registry, Reports, Queue, Control Plane, and Bot support.

### Individual Add-ons

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

### Note on packaging fix

This package uses explicit Setuptools Package Discovery:

```toml
[tool.setuptools.packages.find]
include = ["licenseseal", "licenseseal.*"]
```

This package uses explicit Setuptools Package Discovery: `Notebook_LM/` `Multiple top-level packages discovered` `pyproject.toml`

## Quick Start

### Dry-run markers testing

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --dry-run
```

### Write markers

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --backup
```

### Update Marker

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --update --backup
```

### Run Audit

```powershell
licenseseal audit .
```

### Create GitHub Annotations

```powershell
licenseseal audit . --format github
```

### Remove Marker

```powershell
licenseseal remove . --backup
```

## Cryptographic provenance

Generate key:

```powershell
licenseseal keygen --private-key .licenseseal/private_key.pem --public-key .licenseseal/public_key.pem
```

Sign during injection:

```powershell
licenseseal inject . --license MIT --owner "ACME Corp" --project "acme-core" --sign-key .licenseseal/private_key.pem --update
```

Audit with public key then contains additionally:

```powershell
licenseseal audit . --verify-key .licenseseal/public_key.pem
```

Marker include additional:

```text
CONTENT_DIGEST: sha256:...
AI_SIGNATURE: ...
```

## Source Conflict and License Check

LicenseSeal checks local manifest files before injection and warns about conflicts between target license and project/dependency context.

Supported manifest types:

- `pyproject.toml`
- `package.json`
- `pom.xml`
- `Cargo.toml`
- go.mod `go.mod`
- requirements.txt `requirements.txt`

Examples:

```powershell
licenseseal sca check . --license AGPL-3.0 --fail-on-error
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp"
```

Controlled Exceptions:

```powershell
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp" --force
licenseseal inject . --license AGPL-3.0 --owner "ACME Corp" --skip-sca
```

`"--force` continues despite blockers. `--skip-sca` completely disables manifest validation."` `--force`

## Jupyter Notebooks and AI Datasets

.ipynb files are treated as notebooks, not regular text. LicenseSeal adds an idempotent first Markdown cell and saves machine-readable data under: `.ipynb`

```text
metadata.licenseseal
```

The Notebook Digest is based on code cells. Outputs, Execution Counts, and transient notebook states do not invalidate the provenance.

```powershell
licenseseal inject notebooks/ --owner "ACME Corp" --license MIT --update
licenseseal audit notebooks/
```

.jsonl `.jsonl`

```text
dataset.jsonl.licenseseal.json
```

Training data is not modified by this process.

## Honey-Logic and Multi-Language Honey-Logic

Honey-Logic are small, functionally harmless but mathematically specific code sentinels. They serve as robust provenance markers that better withstand renaming and formatting changes than comments.

Python-Honey Logic and Watermarks:

```powershell
licenseseal watermark embed . --project-id acme-core --signature stable-signature --strength robust
```

Multi-language Honey Logic for Python, JavaScript, TypeScript, Go, Rust, and Java:

```powershell
licenseseal honey-multilang inject . --project-id acme-core --signature "$env:LICENSESEAL_SECRET"
licenseseal honey-multilang scan .
```

The Firehose detects these fingerprints as evidence signals.

## Project comparison and Evidence Diff

Classic structural comparison:

```powershell
licenseseal compare ./original ./suspected --output report.json
```

Side-by-side AST/Line Mapping for Reports and Web UI:

```text
POST /api/diff
```

The mappings show which areas in the original and suspicious project structurally belong together, even if identifiers have been renamed.

## CFG/DFG Graph Fingerprinting

Graph Fingerprinting enhances AST-Shingling with normalized control-flow and data-flow fingerprints. This helps against strong refactorings and AI code laundering.

```powershell
licenseseal graph compare ./original ./suspected --output graph-report.json
```

The Firehose Scanner can additionally capture `graph_similarity` as an Evidence Item when project roots are available.

## Firehose Scanner

The Firehose Scanner checks local paths or Git URLs against registered provenance signals.

```powershell
licenseseal firehose scan ./suspected-copy --output firehose-report.json
```

Registry:

```powershell
licenseseal registry init --database-url postgresql://localhost:5432/licenseseal
licenseseal registry register . --database-url postgresql://localhost:5432/licenseseal --owner "ACME Corp" --license-id MIT --project-id acme-core
licenseseal firehose scan ./suspected-copy --database-url postgresql://localhost:5432/licenseseal --output firehose-report.json
```

The scanner saves `scan_results` and granular `evidence_items`, instead of drawing automatic legal conclusions.

## Distributed Firehose Queue

For enterprise scaling, the Firehose can be distributed using Celery/Redis.

```powershell
licenseseal firehose enqueue https://github.com/example/repo
licenseseal firehose worker
```

Alternative directly with Celery:

```powershell
celery -A licenseseal.firehose_queue.celery_app worker --loglevel=INFO
```

Redis/Celery are optional dependencies. Without a queue, the scanner runs locally synchronously.

## OSINT Discovery

The OSINT crawler searches for rare Honey-Logic terms via official APIs and can feed results into the Firehose Queue.

```powershell
licenseseal osint --provider github --term _ls_fold_a1b2c3 --enqueue
licenseseal osint --provider gitlab --term _ls_fold_a1b2c3 --base-url https://gitlab.example.com/api/v4
```

Tokens are provided by the user. LicenseSeal bypasses no access controls.

## Red-Team Stress Testing

Stress tests simulate authorized refactoring and rewrite scenarios and measure whether watermarks/honey logic remain intact.

```powershell
licenseseal stress-test . --mode local --sample-size 5
licenseseal stress-test . --mode ollama --ollama-model codellama
licenseseal stress-test . --mode lmstudio --lmstudio-url http://localhost:1234/v1/chat/completions
```

The purpose is defensive: testing own markings against legitimate rewrite simulations.

## Semantic Morphing Watermarking

The semantic morphing embeds watermark invariants into nearly harmless code transformations. It supports local deterministic fallback, Ollama, and LM Studio.

```powershell
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend local
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend ollama --ollama-model codellama
licenseseal semantic-morph embed src/module.py --seed "$env:LICENSESEAL_SECRET" --backend lmstudio --lmstudio-model local-model
licenseseal semantic-morph verify src/module.py --seed "$env:LICENSESEAL_SECRET"
```

## Binary Provenance

LicenseSeal can generate provenance metadata for build systems or embed it in test artifacts.

Go `-ldflags:` `-ldflags`

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

Append/Audit for Test Artifacts:

```powershell
licenseseal binary append . ./dist/app --output ./dist/app.sealed
licenseseal binary audit ./dist/app.sealed
```

## LSP and IDE Integration

The LSP module supports:

- Diagnostics for missing/invalid markers
- Quick Fixes for Marker Injection
- Inbound Paste-Protection Primitives for large pasted code blocks
- License and Boundary Detection for IDE Integrations

Workspace Defaults in VS Code:

```json
{
  "licenseseal.owner": "ACME Corp",
  "licenseseal.license": "MIT",
  "licenseseal.project": "acme-core"
}
```

## LLM Prompt and Context Interceptor

Interceptor is a defensive local scanner/Proxy for Ollama, LM Studio, and OpenAI-compatible workflows. It checks prompts and responses for LicenseSeal markers, Zero-Width Watermarks, Honey-Logic, and Copyleft indicators.

File scan:

```powershell
licenseseal intercept scan suspicious-output.py
```

Proxy for Ollama:

```powershell
licenseseal intercept serve --target ollama --port 11435
```

Proxy for LM Studio:

```powershell
licenseseal intercept serve --target lmstudio --port 1235
```

## Auto-Remediation Bot

The bot can run audits, inject/update markers, and optionally create a pull request in GitHub Actions.

```powershell
licenseseal bot autofix . --license MIT --owner "ACME Corp" --create-pr
```

The GitHub Action supports:

```yaml
with:
  root: "."
  license: MIT
  owner: ACME Corp
  auto-fix: "true"
  create-pr: "true"
```

Without a GitHub token, the bot can be used locally as an autofix/dry-run.

## Enterprise Control Plane

The FastAPI Control Plane provides APIs for projects, scans, alerts, and webhooks. API-key authentication and basic RBAC roles are included; OIDC/SAML can be enabled or optionally added in Enterprise deployments.

Start:

```powershell
$env:LICENSESEAL_API_KEY="dev-local"
licenseseal control-plane serve --port 8787
```

Header:

```text
X-LicenseSeal-API-Key: dev-local
```

Typical roles:

```text
admin
legal
developer
viewer
```

## Web interface

Start local web interface:

```powershell
licenseseal web --open-browser
```

Default address:

```text
http://127.0.0.1:8765/
```

Security Warning: The local web interface binds by default to `127.0.0.1`. Bind it only to `0.0.0.0` if access is secured.

## Pre-Commit

Example Configuration:

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

## GitHub Action

Example workflow:

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

## Supported file types

For example:

- Python, Shell, Ruby, Perl, R, Julia
- Python, Shell, Ruby, Perl, R, Julia
- SQL, Lua, Haskell, Erlang, Elixir, Clojure, Lisp
- Jupyter Notebooks (.ipynb) `.ipynb`
- .jsonl-Datasets über Sidecar-Provenance `.jsonl`
- selected configs with `--include-configs`

## Security and isolation

LicenseSeal is designed defensively.

does not modify foreign repositories without user-level write access

- does not modify foreign repositories without user-level write access
- conducts no attacks
- exfiltrates no data
- bypasses no access controls
- does not remove foreign provenance markers
- collects technical evidence but does not replace legal evaluation

Red-Team-, Interceptor-, and Firehose functions should only be used for code you own or for which you have explicit review authorization.

## Legal Notice

License Seal can document origin signals, structural similarities, and technical indicators. For enforcement, DMCA/Takedown requests, contract disputes, or court use, repository history, commits, license files, distribution channels, and expert review should be considered additionally.
