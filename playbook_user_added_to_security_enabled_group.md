# Playbook: User Added to Security-Enabled Group

## 🧠 Detection
- **Quelle:** Windows Security Eventlog
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : "4728" AND 
  event.action : "added*" AND 
  winlog.keywords : "Audit Success"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Hoch – mögliches Privilege Escalation durch Gruppenmitgliedschaft
- **Eskalationsstufe:** SOC-Level 2–3 – besonders bei privilegierten Gruppen

## 🚨 Initial Response
1. Bestimmen, **wer hinzugefügt wurde** und **zu welcher Gruppe**
2. Prüfen, ob Aktion legitim war (z. B. über Change Management oder Tickets)
3. Historie des ausführenden Benutzers/Systems analysieren

## 🔍 Forensik
- Details aus Event 4728 sichern (TargetUser, TargetGroup, SubjectUser)
- Event 4732 (if group is domain local), 4720 (user creation) prüfen
- Prüfen, ob `net group`, `dsadd`, PowerShell oder ADUC verwendet wurde
- Weitere Aktivitäten durch denselben Benutzer analysieren

## 🛡️ Maßnahmen
- Gruppenmitgliedschaft ggf. rückgängig machen
- Benutzeraccount sperren, wenn böswillige Aktion vermutet
- Überprüfung weiterer Rechteänderungen im Umfeld
- Alerts für weitere Gruppenänderungen aktivieren

## 📋 Kommunikation
- IT-Security Team benachrichtigen
- ggf. CISO informieren, wenn administrative Gruppen betroffen sind
- Dokumentation im IR-Tool mit Benutzername, Gruppe, Zeit, System

## 📁 Artefakte
- Security Eventlog (ID 4728)
- Benutzername, Gruppe, Zeitstempel
- Hostname, Domaincontroller
- Kontext des ausführenden Benutzers

## ✅ Lessons Learned
- Gruppenänderungen sollten über Change Management abgesichert sein
- Auditing und Alerting für alle sicherheitsrelevanten Gruppen aktivieren
- Automatisiertes Monitoring von Gruppenmitgliedschaften sinnvoll
- Regelmäßige Review-Prozesse für privilegierte Gruppen etablieren