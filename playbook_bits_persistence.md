# Playbook: Persistence Attempt with BITS – Registry Channel Modification

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 13 – Registry Value Set)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "13"
  AND registry.path : "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/*"
  AND process.executable : "*svchost.exe"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1197 – BITS Jobs  
  - T1547 – Boot or Logon Autostart Execution  
  - T1112 – Modify Registry

## 📌 Priorität
- **Einschätzung:** Hoch (mögliche Persistenz durch Systemkomponenten)
- **Eskalationsstufe:** SOC-Level 3

## 🚨 Initial Response
1. Verifizieren, welcher `svchost.exe`-Kontext aktiv war (Command Line, Parent)
2. Registry-Wertänderung analysieren – welche Daten wurden verändert?
3. Zusammenhang mit BITS-Task prüfen (Command, Zeitplan, Ziel)

## 🔍 Forensik
- Gesamte Registry-Änderung dokumentieren
- Nach zugehörigem BITS-Task suchen mit `bitsadmin /list /allusers`
- Prüfen, ob Scheduled Task, Service oder Script referenziert wird
- Netzwerkanalyse: Gab es BITS-Kommunikation zu externen Quellen?

## 🛡️ Maßnahmen
- Registry-Wert zurücksetzen
- Verdächtigen Task löschen und blockieren
- Hash des involvierten Prozesses untersuchen und ggf. blockieren
- IOC-Verteilung im EDR/AV
- Applocker oder GPO zur Einschränkung von BITS-Nutzung konfigurieren

## 📋 Kommunikation
- IT-Security-Team über Registry-Manipulation mit Persistenz-Potenzial informieren
- Ggf. Incident Response Team involvieren
- Bei kompromittierten Hosts → Eskalation an CISO und ggf. Datenschutz

## 📁 Artefakte
- Sysmon Event ID 13
- Registry Key/Value (vorher/nachher)
- BITS-Task-Konfiguration
- Prozessname, Pfad, Benutzerkontext
- Netzwerkinformationen zu evtl. genutzten URLs/IPs

## ✅ Lessons Learned
- BITS ist ein effektiver Persistenzmechanismus – wird häufig übersehen
- Regel regelmäßig mit neuen Registry-Pfaden und Kontexten aktualisieren
- Nutzung legitimer Windows-Komponenten wie svchost für Persistenz verstärkt Monitoring-Bedarf
- GPO-basierte Einschränkung und Logging auf Windows-Event-Channels ausweiten