# 04 Watermarking und Honey-Logic

## Ziel

Dieses Kapitel erklärt zusätzliche Wiedererkennungssignale jenseits normaler Lizenzmarker.

## Arten von Watermarks

LicenseSeal unterstützt mehrere Signalarten:

| Art | Beschreibung | Stärke |
|---|---|---|
| Boundary Marker | sichtbarer Kommentarblock | stark bei direkter Kopie |
| Zero-Width Watermark | unsichtbare Unicode-Zeichen | gut gegen Header-Entfernung |
| Semantic Watermark | kleine semantische Strukturmerkmale | robuster gegen Formatierung |
| Honey-Logic | harmlose mathematische Code-Sentinels | starkes statistisches Indiz |
| Multi-Language Honey-Logic | Sentinels für Python, JS/TS, Go, Rust, Java | polyglotte Projekte |

## Watermark einbetten

Nutze die Hilfe, um die genauen Optionen deines Builds zu sehen:

```powershell
licenseseal watermark --help
licenseseal watermark embed --help
```

Typischer Ablauf:

```powershell
licenseseal watermark embed src/app.py --message "ACME:payment-service"
```

Watermark extrahieren:

```powershell
licenseseal watermark extract src/app.py
```

## Honey-Logic

Honey-Logic ist ausführbare, harmlose Logik mit seltenen Konstanten und Operatorfolgen. Sie ist nicht dafür gedacht, Verhalten zu sabotieren oder fremde Systeme zu beeinflussen. Sie dient nur der späteren Wiedererkennung eigener Softwarebestandteile.

## Multi-Language Honey-Logic erzeugen

```powershell
licenseseal honey-multilang --help
```

Beispielidee:

```powershell
licenseseal honey-multilang --language python --project "payment-service" --owner "ACME GmbH"
licenseseal honey-multilang --language go --project "payment-service" --owner "ACME GmbH"
licenseseal honey-multilang --language typescript --project "payment-service" --owner "ACME GmbH"
```

## Warum Honey-Logic funktioniert

Ein einzelner Name kann geändert werden. Deshalb bewertet LicenseSeal nicht nur Namen, sondern:

- Zahlenkonstanten
- Operator-Reihenfolge
- AST-Form
- Kontrollfluss
- Bitshifts und Masken
- projektabhängige Seeds

## Erkennung

Honey-Logic wird von Firehose, Interceptor und Scannern als Evidence Signal verwendet. Ein Treffer ist kein automatisches Urteil, aber ein starkes technisches Indiz.

## Vorsicht bei produktivem Code

Füge Honey-Logic nur dort ein, wo sie:

1. keine Performance-Probleme verursacht,
2. keine fachliche Logik verfälscht,
3. durch Code Review akzeptiert ist,
4. dokumentiert und intern genehmigt wurde.

## Übung

1. Erzeuge einen Honey-Logic-Snippet für Python
2. Füge ihn in ein Testprojekt ein
3. Kopiere die Datei in einen zweiten Ordner
4. Nutze Firehose oder Interceptor, um den Treffer zu erkennen
