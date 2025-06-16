# Playbook: Windows Event Logging Stopped

## 🧠 Detection
- **Quelle:** Windows System Eventlog
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "6006"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1562.002 – Impair Defenses: Disable Windows Event Logging

## 📌 Priorität
- **Einschätzung:** Hoch – mögliches Anzeichen für Verschleierungsversuch
- **Eskalationsstufe:** SOC-Level 2–3 – je nach Kontext (wartungsbedingt oder böswillig)

## 🚨 Initial Response
1. Hostname und Zeitstempel erfassen
2. Kontext prüfen: Wartung, Shutdown, Restart oder gezieltes Logging-Stoppen?
3. Benutzer- und Prozesskontext ermitteln (EDR/Sysmon/Process Tracking)

## 🔍 Forensik
- Vorherige und nachfolgende Events analysieren (Event ID 6005 für Neustart, 1102 für Loglöschung)
- Befehlshistorie prüfen: wurde `wevtutil`, `Stop-Service` oder `sc stop` genutzt?
- EDR- oder Sysmon-Logs nach auffälligen Prozessen untersuchen

## 🛡️ Maßnahmen
- Logging-Dienst wieder aktivieren
- Host ggf. isolieren, wenn Manipulation vorliegt
- Logging-Konfiguration prüfen (Gruppenrichtlinie, Monitoring-Tools)
- Automatisches Alerting auf weitere 6006-Events einrichten

## 📋 Kommunikation
- SOC/IR-Team informieren
- IT-Operations ggf. einbeziehen zur Abklärung legitimer Wartung
- Eskalation an CISO, falls Zusammenhang mit aktiven Bedrohungen vermutet wird

## 📁 Artefakte
- Event ID 6006
- Hostname, Zeitstempel
- Kontext (Shutdown, Neustart, gezielte Manipulation)
- EDR/Sysmon-Begleitinformationen

## ✅ Lessons Learned
- Logging-Ausfälle dürfen nie unbemerkt bleiben
- Redundante Logweiterleitung (z. B. Winlogbeat, WEF) sicherstellen
- Alert bei Logging-Unterbrechungen muss automatisch erfolgen
- Logging-Härtung (z. B. restriktive Rechte auf Eventlog-Dienste)