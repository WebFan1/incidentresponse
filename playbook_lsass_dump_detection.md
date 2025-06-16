# Playbook: LSASS Dump Detection – Verdächtiger Zugriff auf lsass.exe

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Sysmon (Event ID 1 – Process Creation, Event ID 10 – Process Access)
- **Rule-ID / Query:**
  ```elasticsearch
  (winlog.event_id: 1 OR winlog.event_id: 10) AND
  winlog.event_data.TargetImage: *lsass.exe AND 
  winlog.event_data.GrantedAccess: (
    "0x1000" OR "0x1010" OR "0x1410" OR "0x1fffff"
  ) AND NOT process.name : (
    "MicrosoftEdgeUpdate.exe", 
    "MsMpEng.exe",  
    "msedge.exe", 
    "svchost.exe",  
    "agentbeat.exe", 
    "elastic-endpoint.exe", 
    "wmiprvse.exe", 
    "CompatTelRunner.exe"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1003 – OS Credential Dumping  
  - T1003.001 – LSASS Memory

## 📌 Priorität
- **Einschätzung:** Kritisch – potenzieller Zugang zu gespeicherten Anmeldedaten
- **Eskalationsstufe:** SOC-Level 3 – sofortige Reaktion

## 🚨 Initial Response
1. Prüfen, welcher Prozess versucht hat, `lsass.exe` zu lesen
2. Parent-Prozess, Pfad, Kommandozeile, Hash sichern
3. Benutzerkontext und Ursprung der Aktivität analysieren (z. B. RDP, lokal, Dienstkonto)

## 🔍 Forensik
- Prozess- und Speicheranalyse (z. B. via procdump – falls aktiv)
- Prüfen, ob Tools wie Mimikatz, ProcDump, Task Manager etc. verwendet wurden
- Logons und Sessions der betroffenen Maschine prüfen
- Falls Dump erstellt wurde: Datei analysieren (Hash, Upload, Signaturprüfung)

## 🛡️ Maßnahmen
- Prozess sofort beenden, Host ggf. isolieren
- Hashes und zugehörige Artefakte blockieren
- Konto sperren oder überwachen
- Endpoint Protection & Audit-Richtlinien prüfen und anpassen

## 📋 Kommunikation
- Incident Response Team informieren
- Datenschutz und IT-Leitung bei erfolgreichen Dump-Vorgängen benachrichtigen
- Management involvieren, falls kritische Systeme oder Domänenkonten betroffen

## 📁 Artefakte
- Prozessinformationen (Name, PID, Parent, Pfad)
- Event Logs (ID 10 mit Zugriff auf `lsass.exe`)
- Kommandozeilenparameter
- Dump-Dateien, Speicherorte, Zeitstempel

## ✅ Lessons Learned
- LSASS-Zugriffe durch legitime Tools whitelisten, aber eng beobachten
- Memory Dump Detection mit Thresholds und Kontext anreichern
- Ergänzende Detection: Zugriff via `MiniDump`, `comsvcs.dll`, `rundll32`, etc.
- Anwendung von Credential Guard in Windows 10/11 aktivieren