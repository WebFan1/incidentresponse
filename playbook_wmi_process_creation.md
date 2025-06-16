# Playbook: WMI Process Creation – Remote Execution via WMI

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Security Eventlog & Sysmon
- **Rule-ID / Query:**
  ```elasticsearch
  (event.code: "4688" AND process.parent.name : "wsmprovhost.exe") OR
  (event.code: "1" AND process.parent.name : "wsmprovhost.exe")
  ```
- **MITRE ATT&CK Mapping:**  
  - T1047 – Windows Management Instrumentation (WMI)

## 📌 Priorität
- **Einschätzung:** Hoch (WMI wird häufig für stille Remote Execution verwendet)
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. Quell-Host und Ziel-Host ermitteln
2. Welcher Benutzer hat den WMI-Befehl ausgeführt? (Remote Execution via `wmic`, `powershell`, oder Admin Tool?)
3. Kontext prüfen: Routinewartung oder Angriff? Falls unklar → eskalieren

## 🔍 Forensik
- Kommandozeile des gestarteten Prozesses sichern
- Prüfen, ob ungewöhnliche Tools, Skripte oder Pfade genutzt wurden
- Parallel nach Lateral Movement suchen (z. B. SMB, RDP, PsExec)
- Letzte Logins und Eventlogs auf Zielhost analysieren
- Identifizieren, ob Persistenz eingerichtet wurde (Scheduled Tasks, Registry)

## 🛡️ Maßnahmen
- Falls Angriff: Quell-Host untersuchen und ggf. isolieren
- Temporäre Sperre betroffener Konten (mit hoher Berechtigung)
- Prozesskette in EDR-Tool nachvollziehen und blockieren
- Detection Rule anpassen: z. B. nur bei bestimmten Eltern-Kind-Kombinationen alerten

## 📋 Kommunikation
- Information an Security Team, ggf. SOC-Lead oder Incident Response
- Bei legitimer Nutzung: Rücksprache mit Admin-Teams
- Bei Kompromittierung: CISO, Management und ggf. Datenschutz

## 📁 Artefakte
- Event 4688 (Windows Log) oder Event 1 (Sysmon)
- Prozessdetails: Name, Kommandozeile, Parent/Child Info
- Benutzername, Hostname, Zeitstempel
- Event-Kette (Login, Execution, Resulting Process)

## ✅ Lessons Learned
- WMI wird oft als stealthy Execution Path übersehen
- Erkennung durch Kombination von Events und Kommandozeilenprofilen verbessern
- WMI-Nutzung im Unternehmen dokumentieren und einschränken
- Regel erweitern um spezifische Prozessnamen, Argumente oder Ausführungskontexte