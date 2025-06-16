# Playbook: Hidden Users – Verdächtige Benutzeranlage unter Linux

## 🧠 Detection
- **Quelle:** Elastic SIEM – Auditd (Auditbeat) & Prozessüberwachung
- **Rule-ID / Query:**
  ```elasticsearch
  tags : ("Passwd-Aenderung" OR "ShadowAenderung" OR "SUDO-Ausfuerung")
  AND (
    process.title : *useradd -r -s* OR
    process.title : *-M* OR
    process.title : *echo*\:*x\:0\:0* OR
    process.title : *tee -a /etc/passwd* OR
    process.title : *tee -a /etc/shadow*
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1136 – Create Account  
  - T1136.001 – Local Account  
  - T1098 – Account Manipulation

## 📌 Priorität
- **Einschätzung:** Hoch
- **Eskalationsstufe:** SOC-Level 3 – mögliche Privilegieneskalation oder Persistenz

## 🚨 Initial Response
1. Prüfen, ob ein neuer Benutzer mit UID 0 oder Root-Shell angelegt wurde
2. Host und Benutzer ermitteln, von dem der Befehl ausging
3. Sofortmaßnahmen:
   - Host trennen oder unter Beobachtung stellen
   - Erstellte Benutzer manuell identifizieren und deaktivieren

## 🔍 Forensik
- Audit-Logs und Bash History analysieren
- Neue Einträge in `/etc/passwd`, `/etc/shadow`, `/etc/group` prüfen
- Prüfen, ob Benutzer ohne Homeverzeichnis und Login-Shell existieren
- Suche nach sudo-Logeinträgen und evtl. missbräuchlicher Ausführung
- Tools wie `chkrootkit`, `rkhunter` zur Rootkit-Erkennung einsetzen

## 🛡️ Maßnahmen
- Host ggf. isolieren
- Unautorisierte Benutzer entfernen
- Passwörter aller privilegierten Konten zurücksetzen
- Audit-Regeln erweitern (z. B. auf „groupadd“, „usermod“)
- Regel um Zeitfenster und Benutzerkontext (z. B. wer führt den Befehl aus?) erweitern

## 📋 Kommunikation
- Sicherheitsverantwortliche und Linux-Administratoren informieren
- Interne Kommunikation über möglichen Privilegienmissbrauch
- Eskalation an IR-Team und ggf. Datenschutzbehörde (bei aktiver Kompromittierung)

## 📁 Artefakte
- `/etc/passwd`, `/etc/shadow`, `/etc/group` – Vorher/Nachher
- Prozessdaten: PID, Kommandozeile, Parent-Process
- Auditd Events & Sysmon-Daten (sofern hybrid)
- Benutzeraktivität um den Zeitpunkt der Aktion

## ✅ Lessons Learned
- Besonders heimliche Benutzer (z. B. UID 0, no shell) müssen schnell erkannt werden
- Regel auf andere User-Management-Binaries ausweiten (`adduser`, `vipw`, `visudo`)
- Einsatz von zentralem User-Account-Management erwägen
- Incident in Use-Case-Katalog aufnehmen und mit Threat Hunt ergänzen