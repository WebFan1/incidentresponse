# Playbook: Scheduled Task/Job Detection (Hybrid)

## 🧠 Detection
- **Quelle:** Windows Security Log & Sysmon
- **Rule-ID / Query:**
  ```elasticsearch
  (event.code: ("4698" OR "4702")) OR 
  (process.command_line : (*/create* OR */Create* OR */Run* OR */run*) AND process.name : "schtasks.exe") OR 
  process.name : "at.exe"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1053 – Scheduled Task/Job  
  - T1053.005 – Scheduled Task (Windows)  
  - T1053.002 – At (Windows)

## 📌 Priorität
- **Einschätzung:** Hoch – verdächtige geplante Tasks sind häufige Methode für Persistenz, Ausführung oder laterale Bewegung
- **Eskalationsstufe:** SOC-Level 3 bei unbekanntem Kontext oder unerwarteter Erstellung

## 🚨 Initial Response
1. Taskname, Kommandozeile und Benutzer identifizieren
2. Zeitpunkt und Herkunft prüfen: Interaktiv oder über Skript/API?
3. Kontext prüfen: legitimer Admin-Vorgang oder potenzieller Angriffsvektor?

## 🔍 Forensik
- Inhalt und Trigger-Zeit des Tasks untersuchen
- Kommandozeile analysieren auf verdächtige Inhalte (z. B. Base64, -enc, netcat, etc.)
- Parent-Prozess analysieren (RemoteShell, PsExec, Malware)
- Vergleich mit bekannten legitimen Tasknamen

## 🛡️ Maßnahmen
- Task deaktivieren oder löschen, falls unautorisiert
- Host überwachen oder isolieren bei starkem Verdacht
- IOC (Task-Name, Pfad, Hash) dokumentieren
- Registry prüfen auf persistente Scheduled Tasks (z. B. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule`)

## 📋 Kommunikation
- Sicherheits- und Windows-Teams informieren
- Änderungsprotokoll der Aufgabe dokumentieren
- Eskalieren bei Angriff oder APT-Verdacht

## 📁 Artefakte
- Event ID: 4698, 4702 (Security Log)
- Prozessname: `schtasks.exe`, `at.exe`
- Kommandozeile, Benutzer, Hostname
- Zeitstempel, Parent-Prozess, Registry-Spuren

## ✅ Lessons Learned
- Scheduled Task-Verwendung regelmäßig reviewen
- SOC-Alerting auf Task-Erstellung/Änderung standardisieren
- Whitelisting legitimer Task-Namen und Erstellungswege