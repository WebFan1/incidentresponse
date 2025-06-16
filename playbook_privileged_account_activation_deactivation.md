# Playbook: Activation/Deactivation of Privileged Accounts

## 🧠 Detection
- **Quelle:** Windows Security Eventlog
- **Rule-ID / Query:**
  ```elasticsearch
  (winlog.event_id: 4722 OR winlog.event_id: 4725) AND
  (event.action: enabled-user-account OR event.action: disabled-user-account) AND
  (winlog.event_data.TargetSid : *-50* OR 
   winlog.event_data.TargetSid : *-51* OR  
   winlog.event_data.TargetSid : *-52* OR  
   winlog.event_data.TargetSid : *-54*)
  ```
- **MITRE ATT&CK Mapping:**  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Kritisch – Aktivierung oder Deaktivierung privilegierter Konten
- **Eskalationsstufe:** SOC-Level 3 – Zugriff auf hochsensible Funktionen

## 🚨 Initial Response
1. Zielkonto identifizieren: SID und Benutzername
2. Kontext der Aktion analysieren: geplante Maßnahme oder nicht autorisiert?
3. Benutzer, der die Aktion durchgeführt hat, überprüfen

## 🔍 Forensik
- Logs zu Benutzeraktivierung/Deaktivierung analysieren
- Korrelierende Events prüfen (4720: Erstellung, 4738: Modifikation)
- Prüfen, ob Aktion durch legitime Admin-Konsole oder Skript ausgelöst wurde
- Prozesskontext per EDR oder Sysmon nachvollziehen

## 🛡️ Maßnahmen
- Konto bei Verdacht deaktivieren
- Gruppenmitgliedschaften rückgängig machen
- Administratoren über unautorisierte Änderung informieren
- Logging- und GPO-Policy auf Konsistenz prüfen

## 📋 Kommunikation
- Security-Team und ggf. Domain Admins informieren
- Dokumentation der Maßnahme im SOC-Ticketsystem
- CISO bei kritischen Konten aktiv einbeziehen

## 📁 Artefakte
- Eventlog: 4722 / 4725
- TargetSID, Benutzername, ausführender Benutzer
- Hostname, Zeitstempel
- Event-Vorgeschichte des Kontos (Erstellung, Änderung, Gruppenzugehörigkeit)

## ✅ Lessons Learned
- Aktivierung und Deaktivierung privilegierter Konten muss nachvollziehbar sein
- Regelmäßige Kontrolle privilegierter Konten notwendig (z. B. GPO, Reporting)
- Alerting auf SIDs mit Admin-Rechten besonders priorisieren