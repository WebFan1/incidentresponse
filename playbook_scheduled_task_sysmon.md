# Playbook: Scheduled Task via Process (Sysmon)

## 🧠 Detection
- **Quelle:** Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code: "1" AND 
  process.name: ("schtasks.exe" OR "powershell.exe") AND 
  process.command_line: "*register*task*"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1053.005 – Scheduled Task/Job: Scheduled Task

## 📌 Priorität
- **Einschätzung:** Hoch – Taskregistrierung über schtasks oder PowerShell kann auf Persistenzversuch hindeuten
- **Eskalationsstufe:** SOC-Level 3 – sofort untersuchen, wenn nicht eindeutig legitim

## 🚨 Initial Response
1. Kommandozeile analysieren: was genau wird registriert?
2. Kontext prüfen: Benutzer, Elternprozess, Hostname, Uhrzeit
3. Legitimität des Tasks gegen bekannte/verzeichnete Admin-Aktivitäten prüfen

## 🔍 Forensik
- Prozess- und Kommandozeile im Detail auswerten
- Datei- und Registry-Zugriffe durch den Task untersuchen
- Netzwerkanfragen oder Folgeprozesse prüfen
- Parent- und Child-Prozesse erfassen (komplettes Prozess-Tree)

## 🛡️ Maßnahmen
- Task deaktivieren oder löschen, falls verdächtig
- Benutzer und Host analysieren (weitere Spuren, persistente Komponenten)
- Endpoint ggf. isolieren zur weiteren Analyse
- IOC (Command-Line, Hash, Taskname) in Monitoring aufnehmen

## 📋 Kommunikation
- IT-Security und Systemadministration involvieren
- Dokumentation mit Taskparametern, Zeit, Host und User erstellen
- Information an Threat Intel/IR-Teams weitergeben bei APT-Verdacht

## 📁 Artefakte
- Sysmon Event ID 1
- Prozessname: schtasks.exe / powershell.exe
- Komplette Kommandozeile (inkl. Pfade, Flags)
- Benutzerkontext, Hostname, Zeit
- ggf. erstellte Dateien oder Registry-Keys

## ✅ Lessons Learned
- Tasküberwachung im Prozesskontext ergänzen (nicht nur Event ID 4698)
- Whitelist bekannter Task-Ersteller-Kommandos
- Awareness für schtasks/powershell-basierte Persistenzmechanismen stärken