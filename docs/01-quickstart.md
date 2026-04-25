# 01 Schnellstart: erstes Projekt schützen

## Ziel dieses Kapitels

Du schützt ein kleines Beispielprojekt, prüfst das Ergebnis und verstehst den Grundablauf.

## Beispielprojekt anlegen

Erstelle einen Ordner:

```powershell
mkdir C:\tmp\hello-seal
cd C:\tmp\hello-seal
```

Lege eine Python-Datei an:

```powershell
@"
def add(a, b):
    return a + b

print(add(2, 3))
"@ | Out-File -Encoding utf8 app.py
```

Unter macOS/Linux:

```bash
mkdir -p /tmp/hello-seal
cd /tmp/hello-seal
cat > app.py <<'PY'
def add(a, b):
    return a + b

print(add(2, 3))
PY
```

## Projekt markieren

```powershell
licenseseal inject . --license MIT --owner "Example Corp" --project "hello-seal"
```

Erwartung:

```text
LicenseSeal result
==================
injected: 1
```

## Datei ansehen

Öffne `app.py`. Am Anfang sollte ein LicenseSeal-Block eingefügt worden sein.

Der eigentliche Code bleibt ausführbar:

```powershell
python app.py
```

Erwartung:

```text
5
```

## Projekt prüfen

```powershell
licenseseal audit .
```

Erwartung:

```text
Files missing boundary: 0
```

## Trockenlauf verwenden

Ein Trockenlauf zeigt, was passieren würde, ohne Dateien zu ändern:

```powershell
licenseseal inject . --license MIT --owner "Example Corp" --dry-run
```

## Marker aktualisieren

Wenn du bestehende Marker aktualisieren möchtest:

```powershell
licenseseal inject . --license MIT --owner "Example Corp" --update
```

## Marker entfernen

Nur für Tests oder bewusstes Entfernen:

```powershell
licenseseal remove .
```

Danach:

```powershell
licenseseal audit .
```

Jetzt sollte die Datei als unmarkiert erscheinen.

## Sicheres Arbeiten mit Backups

```powershell
licenseseal inject . --license MIT --owner "Example Corp" --backup
```

LicenseSeal erzeugt dann Sicherungskopien, bevor Dateien verändert werden.

## Häufige Anfängerfragen

### Verändert LicenseSeal meine Programmlogik?

Der normale `inject`-Befehl fügt Kommentarblöcke hinzu. Für typische Quellcodedateien verändert das die Programmlogik nicht.

### Muss ich jede Datei einzeln markieren?

Nein. Du kannst den Projektordner angeben. LicenseSeal erkennt unterstützte Dateitypen automatisch.

### Was mache ich bei generierten Dateien?

Generierte Dateien sollten meist ausgeschlossen werden:

```powershell
licenseseal inject . --exclude-dir generated --exclude-dir dist
```

## Übung

1. Lege ein Beispielprojekt mit zwei Dateien an
2. Führe `licenseseal inject .` aus
3. Führe `licenseseal audit .` aus
4. Entferne die Marker mit `licenseseal remove .`
5. Führe erneut `audit` aus und vergleiche das Ergebnis
