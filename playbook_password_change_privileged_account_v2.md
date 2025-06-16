# Playbook: Password Change for a Privileged Account

## 🧠 Detection
- **Quelle:** Windows Security Eventlog
- **Rule-ID / Query:**
  ```elasticsearch
  (winlog.event_id: 4723 OR winlog.event_id: 4724) AND
  (event.action : changed-password OR event.action : reset-password) AND
  (winlog.event_data.TargetSid : *-50* OR 
   winlog.event_data.TargetSid : *-51* OR  
   winlog.event_data.TargetSid : *-52* OR  
   winlog.event_data.TargetSid : *-54*)
  ```
- **MITRE ATT&CK Mapping:**  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Kritisch – Änderung an privilegiertem Konto
- **Eskalationsstufe:** SOC-Level 3 – hoher Sicherheitskontext

## 🚨 Initial Response
1. Identifiziere betroffenen Benutzer und dessen Rolle (z. B. Administrator)
2. Prüfe, ob die Aktion legitim war (z. B. durch IT-Support, Passwortwechsel durch Nutzer)
3. Ermittle, ob die Änderung im Zusammenhang mit verdächtigen Ereignissen steht

## 🔍 Forensik
- Analyse des auslösenden Accounts (SubjectUserName)
- Historie des Kontos (z. B. vorherige Gruppenmitgliedschaften, Passwortänderungen)
- Korrelierte Ereignisse: 4624 (Logon), 4625 (Fehlgeschlagene Logons), 4738 (Account Changes)
- Prüfung auf Tools wie net.exe, PowerShell, DSMod

## 🛡️ Maßnahmen
- Passwort ggf. zurücksetzen, falls unklar ob Änderung autorisiert war
- Konto temporär deaktivieren bis Analyse abgeschlossen ist
- Administrative Rechte prüfen und ggf. temporär entziehen
- Logging- und Monitoring-Strategie für privilegierte Konten anpassen

## 📋 Kommunikation
- Incident Response Team und Domain Admins benachrichtigen
- CISO informieren bei kritischen Konten oder bekannten Bedrohungssignaturen
- Dokumentation mit Eventdaten, Hostname, SID, Zeitstempel

## 📁 Artefakte
- Event ID 4723 (Passwortänderung) oder 4724 (Passwortrücksetzung)
- Target SID, Benutzername, ausführender Benutzer
- Hostname, Datum/Uhrzeit
- Alle relevanten Folgeereignisse (z. B. Logon, Gruppenänderungen)

## ✅ Lessons Learned
- Etablierung eines Whitelistings für autorisierte Passwortänderungen
- Alerting bei Änderungen an privilegierten Konten mit Reportingpflicht
- Review-Prozesse für Passwortmanagement stärken