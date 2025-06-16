# Playbook: Indicator Removal on Host – Timestamp Manipulation

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 2 – File Creation Time Changed)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code:"2"
  AND event.action:"A process changed a file creation time"
  AND file.extension : ("exe" OR "dll" OR "ps1" OR "bat" OR "vbs" OR "txt")
  AND NOT user.name : "SYSTEM"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1070 – Indicator Removal on Host  
  - T1070.006 – Timestomp

## 📌 Priorität
- **Einschätzung:** Hoch (Hinweis auf Verschleierungstechniken)
- **Eskalationsstufe:** SOC-Level 3, sofortige Prüfung

## 🚨 Initial Response
1. Prozess analysieren, der die Zeitstempeländerung ausgelöst hat (Pfad, Name, Parent)
2. Betroffene Datei identifizieren – legitime Änderung oder verdächtiges Binary?
3. Benutzeraktivität prüfen – war es ein Admin oder regulärer User?

## 🔍 Forensik
- Vergleich alter vs. neuer Zeitstempel (falls vorhanden)
- Prüfen, ob Datei im Anschluss ausgeführt oder gelöscht wurde
- Command Line und Hash des Prozesses erfassen
- Kontext prüfen: läuft das Binary als persistente Malware oder Script-Dropper?
- Suche nach ähnlichen Aktivitäten auf anderen Hosts (Pivoting)

## 🛡️ Maßnahmen
- Datei und Prozess blockieren, falls verdächtig
- Host ggf. isolieren für tiefere Analyse
- IOC-Erweiterung: andere Dateien mit veränderten Timestamps
- Hash blockieren (AV/EDR/Elastic)

## 📋 Kommunikation
- Sicherheitsverantwortliche informieren
- Bei aktiver Manipulation: Incident-Response-Plan starten
- Forensische Untersuchung dokumentieren

## 📁 Artefakte
- Sysmon Event ID 2
- Datei-Pfade, Zeitstempel vorher/nachher
- Prozessdetails (Name, Path, Parent, CmdLine)
- Benutzername, Hostname, Zeitstempel

## ✅ Lessons Learned
- Timestamp-Modifikation ist typisches Zeichen für Verschleierungsversuche
- Weitere Erkennung auf ähnliche Aktivitäten implementieren
- Eventuelle Regel-Erweiterung um spezifische Tools (z. B. `Timestomp`, `Touch`) sinnvoll
- Präventivmaßnahmen: Application Control, Read-only-Systembereiche