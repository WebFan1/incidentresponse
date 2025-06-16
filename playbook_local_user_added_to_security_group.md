# Playbook: Local User Added to Security-Enabled Group

## 🧠 Detection
- **Quelle:** Windows Security Eventlog – Lokale Gruppenänderung
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "4732" AND 
  event.action : "added*" AND 
  winlog.keywords : "Audit Success"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Hoch – Benutzer erhält zusätzliche lokale Rechte
- **Eskalationsstufe:** SOC-Level 2–3 – abhängig von Zielgruppe (z. B. "Administrators")

## 🚨 Initial Response
1. Prüfen, welcher Benutzer hinzugefügt wurde und zu welcher Gruppe
2. Kontext analysieren: war dies geplant oder durch eine Richtlinie gesteuert?
3. Ursprung (Benutzer, System, Remote oder lokal?) untersuchen

## 🔍 Forensik
- Event 4732 analysieren: TargetUser, TargetGroup, SubjectUser
- Ereignisse davor/danach: neue Benutzer (4720), Gruppenänderungen (4733)
- Prüfen, ob System gehärtet ist oder Skripte zum Einsatz kommen (z. B. via PowerShell, net.exe)

## 🛡️ Maßnahmen
- Mitgliedschaft bei Bedarf rückgängig machen
- Benutzerkonto sperren oder überprüfen
- Gruppenrichtlinien auf Manipulation prüfen
- Ereignisquellen durch andere Logs (z. B. EDR, Sysmon) ergänzen

## 📋 Kommunikation
- IR-Team informieren
- Systemverantwortliche benachrichtigen
- ggf. Management oder CISO einbeziehen, wenn privilegierte Gruppen betroffen

## 📁 Artefakte
- Eventlog ID 4732
- Benutzername, Zielgruppe, ausführender Benutzer
- Hostname, Zeitstempel
- Weitere Gruppenänderungen (Korrelation mit 4728, 4756)

## ✅ Lessons Learned
- Lokale Gruppenänderungen sollten regelmäßig auditiert werden
- Adminrechte sollten möglichst über zentrale Mechanismen (GPO) vergeben werden
- Gruppenmitgliedschaften nur temporär und mit Dokumentation gewähren