# Playbook: Bitsadmin.exe Detected – Verdächtige Nutzung des BITS-Tools

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "1"
  AND winlog.event_data.Description : "BITS administration utility"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1197 – BITS Jobs  
  - T1105 – Ingress Tool Transfer (bei Download via BITS)  
  - T1564 – Hide Artifacts (durch Nutzung legitimer Systemtools)

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch (je nach Prozesskontext)
- **Eskalationsstufe:** SOC-Level 2

## 🚨 Initial Response
1. Ursprung des BITS-Aufrufs prüfen (Benutzer, Pfad, Kommandozeile)
2. Command Line analysieren – Download, Upload, Execution?
3. Falls verdächtig:
   - Host analysieren
   - Nach bekannten Dateiübertragungen suchen (z. B. `.exe`, `.ps1`)

## 🔍 Forensik
- Vollständige Prozessdaten analysieren (Parent, CmdLine, Hash)
- Netzwerkanalyse: Welche Verbindung wurde über BITS initiiert?
- Logs nach anderen LOLBins durchsuchen (z. B. `certutil.exe`, `mshta.exe`)
- Suche nach Payloads in TEMP-/Downloads-Ordnern
- BITS-Auftragsliste prüfen mit `bitsadmin /list /allusers`

## 🛡️ Maßnahmen
- Prozess blockieren, falls schädlich
- IOC-Verteilung bei schädlicher URL oder Hash
- System und Benutzerkonto überwachen
- BITS für Standardbenutzer per GPO oder Applocker sperren

## 📋 Kommunikation
- Sicherheitsteam über missbräuchliche Nutzung informieren
- Bei Exfiltration oder Toolnutzung durch Angreifer → Incident eskalieren
- Management einbeziehen bei Datenabflussverdacht

## 📁 Artefakte
- Sysmon Event ID 1
- Kommandozeile, Dateipfade, Argumente
- Netzwerkinformationen (Ziel-URL/IP)
- Nutzerkontext und Zeitstempel

## ✅ Lessons Learned
- BITS wird oft zur Umgehung klassischer Download-Erkennung genutzt
- Ergänzung der Regel um Ausführungsparameter (z. B. `/transfer`) sinnvoll
- Weitere Überwachung von `bitsadmin.exe` durch EDR oder basierend auf Netzverhalten
- Ergänzend neue Regeln für `bitsadmin` in ungewöhnlichen Kontexten (z. B. Scheduled Tasks)