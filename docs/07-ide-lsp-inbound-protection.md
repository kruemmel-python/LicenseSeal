# 07 IDE/LSP und Inbound Paste Protection

## Ziel

LicenseSeal kann in Entwicklungsumgebungen helfen, fehlende Marker früh zu erkennen und riskante Code-Pastes zu melden.

## LSP starten

Installiere das LSP-Extra:

```powershell
python -m pip install -e ".[lsp]"
```

Starte den Server:

```powershell
licenseseal lsp
```

Je nach Editor wird der LSP-Server in den Einstellungen eingebunden.

## Einmaliger Check ohne Editor

```powershell
licenseseal lsp-check path\to\file.py
```

Lizenzvalidierung:

```powershell
licenseseal lsp-validate .
```

## Code Actions

Wenn eine Datei keinen LicenseSeal-Marker hat, kann der LSP eine Quick-Fix-Aktion anbieten:

```text
LicenseSeal Marker injizieren
```

Der Vorteil: Entwickler müssen die IDE nicht verlassen.

## Inbound Paste Protection

Inbound Paste Protection erkennt große eingefügte Codeblöcke und prüft sie auf:

- LicenseSeal Boundary Marker
- fremde Watermarks
- Copyleft-Indikatoren
- strukturelle Ähnlichkeit zu bekannten Komponenten
- riskante Lizenzhinweise

Mögliche Warnung:

```text
Warnung: Eingefügter Code weist starke Ähnlichkeit zu einer inkompatiblen Komponente auf.
```

## Empfohlene Policy

Für Unternehmen:

| Risiko | Empfehlung |
|---|---|
| AGPL/GPL in proprietärem Projekt | Error |
| unbekannter großer Paste | Warning |
| LicenseSeal-Marker fremder Organisation | Error |
| MIT/BSD-kompatibler Hinweis | Info/Warning |

## Grenzen

Der LSP kann nicht jede Lizenzverletzung beweisen. Er ist ein Shift-Left-Warnsystem, kein juristischer Entscheider.

## Übung

1. Starte den LSP
2. Öffne eine unmarkierte Datei
3. Prüfe, ob die Diagnose erscheint
4. Nutze die Quick Fix Aktion
5. Füge einen großen fremden Codeblock in eine Testdatei ein und beobachte Warnungen
