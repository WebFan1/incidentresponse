# Playbook: Audit Log Cleared

## 🧠 Detection
- **Quelle:** Windows Security Eventlog
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "1102"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1070.001 – Clear Windows Event Logs

## 📌 Priorität
- **Einschätzung:** Kritisch – direkte Verschleierungsmaßnahme
- **Eskalationsstufe:** SOC-Level 3 – muss sofort untersucht werden

## 🚨 Initial Response
1. Feststellen, welcher Benutzer die Löschung durchgeführt hat
2. Zeitpunkt und Kontext analysieren (z. B. andere Events kurz vorher)
3. Prüfen, ob dies Teil eines autorisierten Wartungsfensters war

## 🔍 Forensik
- Host- und Benutzerinformationen aus Event ID 1102 sichern
- Alle vor dem Log-Clear aufgetretenen kritischen Events analysieren
- Prüfen, ob gleichzeitig Prozesse oder Services beendet wurden
- EDR- oder Sysmon-Daten nutzen, um versteckte Aktivitäten zu rekonstruieren

## 🛡️ Maßnahmen
- Host in Quarantäne setzen
- Benutzerkonto sperren, wenn unautorisierte Aktion vorliegt
- Sicherung der Logs aus SIEM oder anderen Forwardern
- Prüfung der Logging-Konfiguration (GPO, WEF, Sysmon etc.)

## 📋 Kommunikation
- IR-Team und CISO sofort informieren
- ggf. rechtliche Stellen oder Datenschutz beiziehen
- Kommunikationssperre intern, bis Incident bewertet wurde

## 📁 Artefakte
- Event ID 1102
- Hostname, Benutzername, SID
- Zeitstempel
- Log-Level und vorhandene SIEM-Daten
- EDR-Telemetrie

## ✅ Lessons Learned
- Ereignis 1102 darf nie ohne nachvollziehbaren Grund auftreten
- Forwarding der Logs an zentrales System muss erzwungen werden
- Überwachung auf PowerShell/CLI-Befehle wie `Clear-EventLog` oder `wevtutil`
- Überwachung des Auditpolicings – z. B. über Event ID 4719