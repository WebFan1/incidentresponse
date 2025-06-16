# Playbook: OS Credential Dumping – Ungewöhnliche passwd-Nutzung (Linux)

## 🧠 Detection
- **Quelle:** Elastic SIEM – Auditd (Auditbeat)
- **Rule-ID / Query:**
  ```elasticsearch
  tags: "Passwd-Aenderung"
  AND NOT auditd.data.a2 : 80000
  AND NOT auditd.summary.how : *accounts-daemon*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1003 – OS Credential Dumping  
  - T1003.008 – /etc/passwd and /etc/shadow Access

## 📌 Priorität
- **Einschätzung:** Hoch
- **Eskalationsstufe:** SOC-Level 3, sofortige Untersuchung erforderlich

## 🚨 Initial Response
1. Benutzer und ausführender Prozess prüfen
2. War die Änderung legitim (z. B. durch Admin) oder nicht autorisiert?
3. Falls verdächtig:
   - Host sperren oder isolieren
   - Prüfen, ob Rootrechte missbraucht wurden
   - Sofort an Incident Response eskalieren

## 🔍 Forensik
- Prüfe den genauen Befehl über `auditd.summary.exe` / `auditd.summary.name`
- Host-Logs: Zeitgleiche sudo-/su-Aktivität prüfen
- Dateizugriffe auf `/etc/passwd`, `/etc/shadow`, `/etc/group` untersuchen
- Bash History, Prozessbaum und Logins (z. B. `last`) sichern
- Mögliche Persistenz durch neue Benutzerkonten analysieren

## 🛡️ Maßnahmen
- Host vom Netz trennen
- Passwortänderung rückgängig machen oder alle Passwörter zurücksetzen
- Root-Passwort ändern
- IOC-Jagd auf mögliche Rootkits oder bekannte Credential-Dumping-Tools (z. B. mimipenguin)

## 📋 Kommunikation
- Sofortmeldung an das IR-Team und IT-Security-Leitung
- Benutzer und Admins über Incident informieren (intern)
- Meldung an Datenschutz/Compliance bei Hinweis auf Datendiebstahl

## 📁 Artefakte
- Auditd-Einträge (komplette Eventdetails)
- Bash History
- /etc/passwd, /etc/shadow – Vergleich Vorher/Nachher
- Prozessdaten zum Zeitpunkt der Aktivität
- Verdächtige Dateien oder Scripts

## ✅ Lessons Learned
- Alarm sinnvoll bei jeder Änderung der passwd-Datei außerhalb von legitimen Services
- Überwachung auf alle Methoden der lokalen Passwortänderung erweitern
- Regel zusätzlich auf `/etc/shadow`-Zugriffe anpassen
- Einführung eines „Change Management“-Audit-Loggers empfehlenswert