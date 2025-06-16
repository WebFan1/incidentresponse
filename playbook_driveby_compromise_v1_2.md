# Playbook: Drive-by Compromise V 1.2

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  data_stream.dataset : "windows.sysmon_operational" AND 
  process.parent.name : "firefox.exe" AND 
  event.code : "1" AND 
  process.name : (
    "wscript.exe" OR 
    "mshta.exe" OR 
    "powershell.exe" OR 
    "cmd.exe" OR 
    "rundll32.exe" OR 
    "certutil.exe" OR 
    "regsvr32.exe" OR 
    "msiexec.exe" OR 
    "bitsadmin.exe"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1189 – Drive-by Compromise  
  - T1059 – Command and Scripting Interpreter  
  - T1204 – User Execution

## 📌 Priorität
- **Einschätzung:** Hoch (mögliche ungewollte Ausführung von Code über kompromittierte Webseite)
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. Ursprung der Firefox-Session untersuchen (Referrer, Download, aktive Tabs)
2. Analyse der gestarteten Datei bzw. Command-Line
3. Prüfen, ob der Startprozess signiert, legitim oder Teil eines Exploits ist

## 🔍 Forensik
- Parent- und Child-Prozesse analysieren (Kommandozeile, Hashes, Signatur)
- Netzwerkaktivität prüfen: Verbindungen zu verdächtigen Servern?
- Überprüfung der URL oder Website (Threat Intel, Reputation)
- Speicherauszüge, Filesystemänderungen, Registry-Aktivität sammeln

## 🛡️ Maßnahmen
- Prozess beenden, Host ggf. isolieren
- Datei und IPs blockieren
- Benutzer benachrichtigen und sensibilisieren
- Updates und Patchstand des Browsers überprüfen

## 📋 Kommunikation
- SOC/IR-Team informieren
- Benutzer aufklären über möglichen Exploit oder Download
- Technische Nachverfolgung im SIEM dokumentieren

## 📁 Artefakte
- Prozessdetails: firefox.exe → Payload
- Kommandozeile der gestarteten Binary
- Dateihashes, Netzwerkverbindungen, Speicherorte
- Zeitstempel, Benutzername, Hostname

## ✅ Lessons Learned
- Drive-by-Angriffe erfolgen häufig über Werbenetzwerke oder kompromittierte Seiten
- Kontrolle über Browser-Plugins und automatische Downloads verschärfen
- EDR und Browser-Telemetrie zur Absicherung nutzen
- Awareness-Kampagnen zu "gefährlichen Klicks" stärken