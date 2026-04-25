# 05 Audit, Vergleich und Reports

## Audit

Ein Audit prüft ein Projekt auf Markierungen und optional Signaturen.

```powershell
licenseseal audit .
```

Typische Fragen:

- Sind alle relevanten Dateien markiert?
- Fehlen Boundaries?
- Sind Signaturen gültig?
- Wurde eine Datei nachträglich geändert?

## Vergleich zweier Projekte

```powershell
licenseseal compare ./original ./suspected --output compare.json
```

Nutze diesen Befehl, wenn du zwei Codebasen vergleichen möchtest.

## Graph-Vergleich

Für stärker refaktorierten Code kann der CFG/DFG-Vergleich helfen:

```powershell
licenseseal graph compare ./original ./suspected
```

Graph-Fingerprinting betrachtet nicht nur Syntax, sondern auch Kontroll- und Datenfluss.

## Side-by-Side Diff

LicenseSeal kann Evidence für visuelle Vergleiche erzeugen. Ziel ist eine nachvollziehbare Darstellung:

```text
Original Datei        Verdächtige Datei
Zeile 10-25      ↔    Zeile 44-61
Honey-Logic      ↔    Honey-Logic
Shingle Match    ↔    Shingle Match
```

Nutze Report-Befehle:

```powershell
licenseseal report --help
licenseseal report dmca --help
licenseseal report certificate --help
```

## Legal- und Evidence-Reports

Ein professioneller Report sollte enthalten:

- Zeitpunkt des Scans
- Originalprojekt
- Kandidatenprojekt
- erkannte Marker
- Honey-Logic-Treffer
- strukturelle Ähnlichkeit
- Graph-Ähnlichkeit
- Dateipfade
- Hashes/Digests
- Tool-Version
- Grenzen der Aussagekraft

## Gute Interpretation

Ein Score ist ein technischer Hinweis, kein juristisches Urteil.

Starke Evidenz entsteht durch Kombination:

```text
Boundary Marker gefunden
+ Honey-Logic Treffer
+ hohe Shingle-Ähnlichkeit
+ ähnlicher CFG/DFG-Fingerprint
= hoher Verdachtswert
```

Schwache Evidenz:

```text
Nur ähnliche Dateinamen
= niedriger Verdachtswert
```

## Übung

1. Kopiere ein Testprojekt in zwei Ordner
2. Benenne im zweiten Ordner Variablen um
3. Führe `licenseseal compare` aus
4. Führe `licenseseal graph compare` aus
5. Vergleiche die Ergebnisse
