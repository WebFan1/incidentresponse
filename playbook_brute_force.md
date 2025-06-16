# Playbook: Brute Force Attempt – Windows Logon Failures

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Eventlog (Event ID 4625)
- **Rule-ID / Query:**
  ```sql
  FROM logs*
  | WHERE event.code == "4625"
  | STATS failed_logins = COUNT(*), ip_count = COUNT_DISTINCT(source.ip) BY user.name, host.name
  | WHERE failed_logins >= 5 AND ip_count >= 1
  ```
- **MITRE ATT&CK Mapping:**  
  - T1110 – Brute Force  
  - T1110.001 – Password Guessing

## 📌 Priorität
- **Einschätzung:** Mittel
- **Eskalationsstufe:** SOC-Level 2 (erhöht bei Admin-Konten oder externen IPs)

## 🚨 Initial Response
1. Benutzername und Hostname analysieren: Echt? Admin? Kritisch?
2. Quell-IP verifizieren (intern vs. extern, bekanntes System?)
3. Falls verdächtig:
   - IP blockieren (Firewall/EDR)
   - Benutzerkonto sperren oder MFA forcieren
   - Alert eskalieren an IR-Team

## 🔍 Forensik
- Logs auf Event ID 4624 (erfolgreiche Logins) prüfen
- Welche Prozesse starteten nach einem Login?
- Zeitfenster analysieren: Versuchsmuster erkennbar?
- DHCP oder EDR nutzen, um Quellgerät der IP zu ermitteln
- Lateral Movement oder Anomalien auf Zielsystem?

## 🛡️ Maßnahmen
- Falls False Positive → Benutzer informieren, keine weiteren Schritte
- Falls legitim, aber kritisch → Monitoring ausweiten
- Konto ggf. resetten und MFA aktivieren
- Regel mit Zeitfilter und Geolokation optimieren
- Optional: Canary Account zur Täuschung einsetzen

## 📋 Kommunikation
- Interne Doku im SIEM-Ticket
- Benutzer-Sensibilisierung bei wiederholtem Auftreten
- Meldung an IT-Security-Management bei Admin-Konto-Betreuung
- Keine externe Kommunikation nötig (sofern kein erfolgreicher Angriff)

## 📁 Artefakte
- Event Logs: 4625 (fehlgeschlagen), ggf. 4624 (erfolgreich)
- Benutzername, Hostname, Quell-IP
- Zeitstempel & Screenshot der Detection
- DHCP- oder AD-Zuordnung der IP

## ✅ Lessons Learned
- Schwellenwert von 5 ist ein guter Start, aber ggf. zu niedrig bei legitimen Nutzern
- Zeitfenster (z. B. 5 Versuche in 10 Min) erhöhen Präzision
- Kombination mit 4624 (erfolgreicher Login) sinnvoll
- MFA-Abdeckung regelmäßig überprüfen