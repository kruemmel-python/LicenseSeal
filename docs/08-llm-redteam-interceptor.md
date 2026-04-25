# 08 LLM Red-Team, Ollama, LM Studio und Interceptor

## Ziel

Dieses Kapitel zeigt, wie LicenseSeal eigene Markierungen gegen Refactoring und LLM-Rewrites testet und wie Prompts/Antworten defensiv geprüft werden können.

## Red-Team Stress-Test

Ein Stress-Test simuliert, ob eigene Marker und Honey-Logic Refactoring überleben.

```powershell
licenseseal stress-test .
```

Mit lokalem Modus:

```powershell
licenseseal stress-test . --mode local
```

Mit Ollama:

```powershell
licenseseal stress-test . --mode ollama
```

Mit LM Studio:

```powershell
licenseseal stress-test . --mode lmstudio
```

## Ollama

Ollama läuft häufig unter:

```text
http://localhost:11434
```

Beispiel:

```powershell
licenseseal intercept serve --target ollama
```

## LM Studio

LM Studio bietet einen OpenAI-kompatiblen lokalen Server, häufig unter:

```text
http://localhost:1234/v1
```

Beispiel:

```powershell
licenseseal intercept serve --target lmstudio
```

## Interceptor

Der Interceptor kann Dateien scannen:

```powershell
licenseseal intercept scan src/app.py
```

Oder als lokaler Proxy dienen:

```powershell
licenseseal intercept serve --target ollama --port 11435
```

Dann konfigurierst du dein Tool so, dass es statt direkt zu Ollama zum Interceptor spricht.

## Was wird geprüft?

- Prompts
- Modellantworten
- Codeblöcke in Antworten
- LicenseSeal Boundary Marker
- Zero-Width Watermarks
- Honey-Logic
- Multi-Language Honey-Logic
- Copyleft-Indikatoren

## Sicherer Zweck

Der Red-Team-Modus ist dazu da, **eigene** Markierungen zu testen. Er ist nicht dazu gedacht, fremde Markierungen zu entfernen oder fremde Provenance-Systeme zu umgehen.

## Beispielauswertung

```text
Watermark Survival Rate: 80%
Honey-Logic Survival Rate: 100%
Recommendation: increase honey density for high-risk modules
```

## Übung

1. Markiere ein Testprojekt
2. Führe `licenseseal stress-test . --mode local` aus
3. Starte Ollama oder LM Studio
4. Wiederhole den Test mit dem passenden Modus
5. Vergleiche Survival Rates
