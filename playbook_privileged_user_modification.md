# Playbook: Modification of a Privileged User Account

## 🧠 Detection
- **Quelle:** Windows Security Eventlog – Benutzerkontenänderung
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id : 4738 AND 
  event.action : "modified-user-account" AND 
  (winlog.event_data.TargetUserName : *Admin* OR winlog.event_data.TargetUserName : *admin*)
  ```
- **MITRE ATT&CK Mapping:**  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Hoch – Änderung an einem privilegierten Konto
- **Eskalationsstufe:** SOC-Level 3 – besonders bei Domain Admins oder lokalen Admins

## 🚨 Initial Response
1. Identifizieren, **welches Konto** geändert wurde und **durch wen**
2. Kontext prüfen: legitime Änderung oder unautorisierter Zugriff?
3. Änderungen prüfen: Passwort, Gruppen, Flags (z. B. Passwort nie ablaufend)

## 🔍 Forensik
- Event 4738 analysieren: Alte und neue Werte vergleichen
- Events 4720, 4722, 4723 und 4724 korrelieren (Konto erstellt, aktiviert, PW geändert)
- Prozess, der Änderung durchführte, per EDR/Sysmon überprüfen
- Benutzer- und Gruppenmitgliedschaften prüfen

## 🛡️ Maßnahmen
- Konto bei Verdacht sperren oder zurücksetzen
- Gruppenmitgliedschaften zurücksetzen
- Änderung dokumentieren, ggf. GPO prüfen
- Endpoint auf weitere Anomalien prüfen

## 📋 Kommunikation
- SOC- und AD-Team informieren
- CISO und ggf. Compliance informieren bei administrativen Änderungen
- Benutzer ggf. kontaktieren zur Verifikation

## 📁 Artefakte
- Event ID 4738 – mit Benutzername, Änderungen, Hostname, Zeit
- Weitere korrelierte Events (4720, 4722, 4724)
- Prozessdetails (falls per EDR/Sysmon vorhanden)
- Benutzerkontext und -aktivitäten

## ✅ Lessons Learned
- Änderungen an privilegierten Accounts müssen besonders überwacht werden
- Alerting auf Änderungen an „admin“-ähnlichen Accounts einrichten
- Starke Richtlinien für Änderungskontrollen und Rollentrennung einführen