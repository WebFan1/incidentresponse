# Playbook: AD User Creation with Subsequent Admin Group Assignment

## 🧠 Detection
- **Quelle:** Windows Security Eventlog
- **Rule-ID / Query (EQL):**
  ```eql
  sequence by user.name with maxspan=5m
    [any where event.action == "added-user-account" and winlog.event_id == "4720"]
    [any where event.action == "changed-password" and (winlog.event_id == "4723" or winlog.event_id == "4724")]
    [any where event.action == "added-member-to-group" and (winlog.event_id == "4728" or winlog.event_id == "4732")]
  ```
  - **Event ID 4720**: Benutzerkonto wurde erstellt
  - **Event ID 4723/4724**: Passwort gesetzt oder zurückgesetzt
  - **Event ID 4728/4732**: Hinzufügen zu einer sicherheitsrelevanten Gruppe

- **MITRE ATT&CK Mapping:**  
  - T1136.002 – Create Account: Domain Account  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Hoch – typisches Verhalten bei Privilege Escalation und persistenter Zugang
- **Eskalationsstufe:** SOC-Level 3 – sofort untersuchen

## 🚨 Initial Response
1. Prüfen, ob die Kontoerstellung autorisiert war (Change Request, HR-Prozess)
2. Gruppenmitgliedschaft analysieren: Welche Rechte wurden vergeben?
3. Uhrzeit, Benutzer, Zielsystem, auslösendes Konto ermitteln

## 🔍 Forensik
- Wer hat das Konto angelegt? (Admin-Script oder interaktiv?)
- Von welchem Host wurde es durchgeführt?
- Parallele verdächtige Aktionen in der Umgebung prüfen (Logons, Änderungen)
- Login-Versuche oder -Erfolge des neuen Accounts beobachten

## 🛡️ Maßnahmen
- Konto ggf. deaktivieren
- Gruppenmitgliedschaft rückgängig machen
- Audit-Logs sichern
- Passwort zurücksetzen oder Ablauf erzwingen

## 📋 Kommunikation
- IT-Security-Team informieren
- Abstimmung mit AD-Admins und HR (bei legitimer Erstellung)
- Management informieren, falls es sich um einen externen Vorfall handelt

## 📁 Artefakte
- Event IDs 4720, 4723/4724, 4728/4732 mit Benutzer- und Gruppennamen
- Hostname, Quell-IP, Uhrzeit
- Kontext-Logs (GPOs, PowerShell, verdächtige Tools)

## ✅ Lessons Learned
- Automatisiertes Alerting bei Kontoerstellung + Admin-Zuweisung etablieren
- Rollenbasierte Zugriffskontrolle (RBAC) und striktere Genehmigungsprozesse einführen
- Logging und Überwachung der Gruppenmitgliedschaften stärken