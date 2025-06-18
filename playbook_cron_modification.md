# Playbook: Cron Jobs Modification

## 🧠 Detection
- **Quelle:** Auditd / File Integrity Monitoring / Elastic Agent
- **Rule-ID / Query:**
  ```elasticsearch
  tags : "cron_modification" AND file.path : (/etc/cron* OR /var/spool/cron*)
  ```

- **MITRE ATT&CK Mapping:**  
  - T1053.003 – Scheduled Task/Job: Cron

## 📌 Priorität
- **Einschätzung:** Hoch – Cronjob-Manipulation wird häufig für Persistenz oder regelmäßige Ausführung von Malware verwendet
- **Eskalationsstufe:** SOC-Level 3 bei nicht autorisierten Änderungen

## 🚨 Initial Response
1. Dateiänderung analysieren: Wer hat wann was modifiziert?
2. Inhalt der Datei auslesen und auf verdächtige Befehle untersuchen
3. Prüfen, ob Änderung über Skript, Root-Shell oder Remote-Login erfolgt ist

## 🔍 Forensik
- Diff der betroffenen Crondaten (vorher/nachher)
- Benutzer- und Prozesskontext analysieren
- Nachgelagerte Prozesse beobachten (z. B. Malware-Download, Datenexfiltration)
- ggf. andere Hosts auf gleiches Muster prüfen

## 🛡️ Maßnahmen
- Cronjob rückgängig machen oder entfernen
- betroffenen Benutzer prüfen und ggf. sperren
- Host isolieren, wenn weitere Kompromittierungsanzeichen bestehen
- IOC (Pfad, Inhalt, User, Zeit) extrahieren

## 📋 Kommunikation
- Security- und Linux-Administratoren informieren
- Änderung und Analyse dokumentieren
- ggf. Eskalation an Incident Response oder Threat Hunting Team

## 📁 Artefakte
- Dateien: `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`
- Benutzer, Zeitstempel, Inhalt der Änderung
- Prozesshistorie zum Änderungszeitpunkt
- Verdächtige Befehle oder Pfade im Cronjob

## ✅ Lessons Learned
- Monitoring für Cron-Modifikationen aktivieren (FIM/Auditd)
- Berechtigungen auf Crontabs restriktiv halten
- Cron-Aktivitäten regelmäßig automatisiert prüfen
- Awareness für persistente Cron-basierte Bedrohungen im Team stärken