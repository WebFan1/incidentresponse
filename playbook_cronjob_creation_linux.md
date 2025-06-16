# Playbook: Cronjob-Erstellung (Linux)

## 🧠 Detection
- **Quelle:** Auditd (über Auditbeat oder Elastic Agent)
- **Rule-ID / Query:**
  ```elasticsearch
  event.module: "auditd" AND
  event.action: "executed" AND
  process.name: "crontab"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1053.003 – Scheduled Task/Job: Cron

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch – Cronjobs werden häufig zur Persistenz oder Datenexfiltration missbraucht
- **Eskalationsstufe:** SOC-Level 2 bis 3 – abhängig vom Benutzerkontext und Task-Inhalt

## 🚨 Initial Response
1. Prüfen, welcher Benutzer den Cronjob angelegt hat
2. Kommandozeile und übergebene Parameter analysieren
3. Kontext analysieren (z. B. interaktiv oder automatisiert durch Skript)

## 🔍 Forensik
- Inhalt der Cronjob-Dateien (z. B. `/var/spool/cron/`, `/etc/crontab`, `/etc/cron.d/`)
- Historie der betroffenen Datei(en) (z. B. `audit.log`, `bash_history`, `journalctl`)
- Netzverbindungen oder Dateiaktivitäten im Zeitrahmen des Cronjobs prüfen
- Analyse von Parent-Prozess, Schreibaktionen, Child-Prozessen

## 🛡️ Maßnahmen
- Verdächtigen Cronjob deaktivieren oder löschen
- Benutzerrechte prüfen (vor allem bei root)
- Weiteres Verhalten des Hosts überwachen oder isolieren
- IOC-Analyse und eventuelle Payloads sichern

## 📋 Kommunikation
- Security-Team informieren
- Dokumentation mit Hostname, User, Pfad, Zeitpunkt
- Eskalation an Linux-Admin bei Systemkonten

## 📁 Artefakte
- Auditd-Log (process.name = "crontab")
- Kommandozeile, Benutzer, Zeitpunkt
- Dateiinhalt und Pfad des neuen Cronjobs
- Quell-IP (wenn remote erfolgt)

## ✅ Lessons Learned
- Baseline für legitime Cronjobs definieren
- Alarmierung bei verdächtigen Zeitplänen oder Nutzern (z. B. alle 5 Min)
- Einsatz alternativer persistenzfähiger Tools regelmäßig prüfen