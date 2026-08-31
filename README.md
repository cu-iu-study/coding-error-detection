# Vulnerability Scanner

Ein einfacher AST-basierter Schwachstellenscanner zur statischen Analyse von Quellcode. Der Scanner unterstützt derzeit **Python, Java und JavaScript** und erkennt die folgenden Schwachstellentypen:

* Hardcoded Credentials
* Unsafe Code Execution
* Command Injection

Die Analyse erfolgt ohne Ausführung des untersuchten Quellcodes. Der Quellcode wird zunächst mit Tree-sitter in einen Syntaxbaum (AST) überführt und anschließend durch einen sprachspezifischen Adapter in ein sprachunabhängiges Analysemodell transformiert. Auf diesem Modell werden die Schwachstellenregeln ausgeführt.

---

## 1. Voraussetzungen

Für die Ausführung des Scanners werden folgende Voraussetzungen benötigt:

* **Python 3.11 oder höher**
* **pip** zur Installation der Python-Abhängigkeiten
* Ein Betriebssystem, auf dem Python ausgeführt werden kann
* Der vollständige Projektordner einschließlich der Python-Dateien und Abhängigkeiten

Die aktuell unterstützten Programmiersprachen sind:

| Programmiersprache | Dateiendung |
| ------------------ | ----------- |
| Python             | `.py`       |
| Java               | `.java`     |
| JavaScript         | `.js`       |

Andere Dateiendungen werden vom Parser als nicht unterstützte Eingabe abgelehnt.

---

## 2. Installation

Zunächst wird das Projektverzeichnis geöffnet:

```bash
cd coding-error-detection
```

Anschließend wird empfohlen, eine virtuelle Python-Umgebung zu erstellen:

```bash
python -m venv .venv
```

Die virtuelle Umgebung wird anschließend aktiviert.

**Windows:**

```bash
.venv\Scripts\activate
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

Danach werden die benötigten Python-Pakete installiert:

```bash
pip install -r requirements.txt
```

Nach erfolgreicher Installation kann der Scanner direkt über `main.py` gestartet werden.

---

## 3. Abhängigkeiten

Der Scanner verwendet insbesondere **Tree-sitter** zur Erstellung und Verarbeitung der Syntaxbäume. Die sprachspezifischen Tree-sitter-Grammatiken werden über die entsprechenden Python-Pakete bereitgestellt.

Die wesentlichen Laufzeitabhängigkeiten sind:

```text
tree-sitter>=0.26.0
tree-sitter-java>=0.23.5
tree-sitter-javascript>=0.25.0
tree-sitter-python>=0.25.0

pytest>=9.1.1
```

Für die automatisierten Tests wird zusätzlich **pytest** verwendet.

Die vollständigen Abhängigkeiten sind in der Datei `requirements.txt` definiert.

---

## 4. Konfiguration

Die zu analysierende Datei wird beim Start des Programms als Kommandozeilenargument angegeben. Dadurch kann derselbe Scanner ohne Änderungen an der Konfiguration auf unterschiedliche Quellcodedateien angewendet werden.

Das aktuell unterstützte Eingabeformat wird anhand der Dateiendung bestimmt. Beispielsweise wird eine Datei mit der Endung `.py` automatisch als Python-Quellcode verarbeitet.

---

## 5. Start des Programms

Der Scanner wird aus dem Hauptverzeichnis des Projekts über `main.py` gestartet.

Die allgemeine Syntax lautet:

```bash
python main.py <QUELLCODE-DATEI>
```

Die Kommandozeilenoberfläche verwendet `argparse`. Wird das Programm ohne ausreichende Argumente oder mit der Option `--help` aufgerufen, werden Informationen zur korrekten Verwendung angezeigt.

```bash
python main.py --help
```

Dadurch kann die genaue Bedienung direkt über die Anwendung nachvollzogen werden.

---

## 6. Beispielaufruf

Im Projekt befinden sich Beispielprogramme im Verzeichnis `samples/`. Eine Analyse kann beispielsweise mit einer Python-Datei gestartet werden:

```bash
python main.py samples/hello.py
```

Alternativ können eigene Quelldateien angegeben werden:

```bash
python main.py /pfad/zur/quelldatei.py
```

Der Scanner erkennt die Programmiersprache automatisch anhand der Dateiendung und führt anschließend die für die Datei relevanten Analyse- und Schwachstellenregeln aus.

Die Ausgabe erfolgt direkt in der Konsole.

---

## 7. Erwartetes Ergebnis

Enthält die analysierte Quelldatei eine durch das Ruleset erkannte Schwachstelle, wird ein entsprechendes Finding ausgegeben. Die Ausgabe enthält unter anderem:

* Schwachstellentyp und Regel-ID
* Schweregrad
* Beschreibung der Schwachstelle
* Empfehlung zur Behebung
* Dateipfad
* Zeilen- und Spaltenposition
* einen Ausschnitt des betroffenen Quellcodes

Eine beispielhafte Ausgabe hat folgende Struktur:

```text
================================================================================
Vulnerability Scanner
================================================================================

File: samples/vulnerable/example.py

--------------------------------------------------------------------------------
[HIGH] Hardcoded Credentials (HC-001)

Location:
  samples/vulnerable/example.py:3:1

Description:
  ...

Recommendation:
  ...

Code:

     1 | def authenticate():
     2 |     username = "admin"
>    3 |     password = "secret123"
     4 |     return authenticate_user(username, password)

================================================================================
Summary

Total findings : 1

LOW      : 0
MEDIUM   : 0
HIGH     : 1
CRITICAL : 0
================================================================================
```

Die tatsächliche Beschreibung und Bewertung eines Findings hängt von der ausgelösten Regel ab.

Enthält die analysierte Datei keine erkannten Schwachstellen, wird stattdessen eine entsprechende Meldung ausgegeben:

```text
================================================================================
Vulnerability Scanner
================================================================================

No vulnerabilities detected.

================================================================================
```

### Nicht unterstützte Dateien

Wird eine Datei mit einer nicht unterstützten Dateiendung übergeben, beispielsweise eine C-Datei, kann der Scanner diese nicht analysieren. Der Parser beendet die Verarbeitung mit einer Fehlermeldung und nennt die unterstützten Dateiendungen.

### Tests ausführen

Die automatisierten Tests können aus dem Projektverzeichnis mit folgendem Befehl ausgeführt werden:

```bash
pytest
```

Damit werden die Unit- und Integrationstests des Projekts ausgeführt. Eine erfolgreiche Testausführung bestätigt die Funktionsfähigkeit der im Testkonzept definierten Komponenten und Verarbeitungsketten.

---

## Kurzreferenz

| Aktion                      | Befehl                            |
| --------------------------- | --------------------------------- |
| Hilfe anzeigen              | `python main.py --help`           |
| Quelldatei analysieren      | `python main.py <DATEI>`          |
| Tests ausführen             | `pytest`                          |
| Abhängigkeiten installieren | `pip install -r requirements.txt` |

Der Scanner benötigt somit lediglich eine unterstützte Quelldatei als Eingabe. Die Programmiersprache wird automatisch erkannt; eine separate Angabe der Sprache oder eine manuelle Auswahl der Schwachstellenregeln ist nicht erforderlich.
