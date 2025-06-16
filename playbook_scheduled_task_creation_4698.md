# Playbook: Scheduled Task Creation (Event ID 4698)

## 🧠 Detection
- **Quelle:** Windows Security Log (via Winlogbeat / Elastic Agent)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "4698" AND 
  event.provider : "Microsoft-Windows-Security-Auditing"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1053.005 – Scheduled Task/Job: Scheduled Task

## 📌 Priorität
- **Einschätzung:** Hoch – geplante Tasks werden häufig für Persistenz und Malware-Trigger verwendet
- **Eskalationsstufe:** SOC-Level 3 – untersuchungspflichtig bei unbekannten Aufgaben oder ungewöhnlichen Benutzern

## 🚨 Initial Response
1. Taskname, -pfad und ausführende Datei analysieren
2. Benutzer identifizieren, der den Task erstellt hat
3. Kontext prüfen: war dies ein legitimes Admin-Event?

## 🔍 Forensik
- Vergleich des Task-Inhalts mit bekannten legitimen Tasks
- Elternprozess und Command Line prüfen
- Korrelieren mit weiteren Events desselben Benutzers (z. B. PowerShell, Registry-Änderungen)
- Netzwerkverbindungen des Tasks analysieren, falls vorhanden

## 🛡️ Maßnahmen
- Task deaktivieren/löschen bei Verdacht
- User-Account sperren oder überprüfen
- Forensische Kopien relevanter Dateien sichern
- Taskplaner-Verzeichnis auf Manipulation prüfen

## 📋 Kommunikation
- IT-Security-Team und Windows-Admins informieren
- Management benachrichtigen bei bestätigtem Vorfall
- Dokumentation im IR-Ticket inkl. Taskdefinition und Zeitpunkt

## 📁 Artefakte
- Event ID 4698
- Taskname, Taskpfad, Pfad zur Binärdatei
- Benutzername, Hostname, Uhrzeit
- Parent-Prozess, Logon-Session

## ✅ Lessons Learned
- Whitelisting legitimer Tasks im SOC definieren
- Automatisierte Alerting-Logik für kritische Tasknamen (z. B. "update", "svchost")
- Konfigurationsmanagement zur Tasküberwachung implementieren