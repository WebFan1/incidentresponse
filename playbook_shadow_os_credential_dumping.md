# Playbook: Shadow File Modification – OS Credential Dumping (Linux)

## 🧠 Detection
- **Quelle:** Elastic SIEM – Auditd (über Auditbeat)
- **Rule-ID / Query:**
  ```elasticsearch
  tags: "ShadowAenderung"
  AND NOT auditd.data.a2 : 80000
  AND NOT auditd.summary.how : *accounts-daemon*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1003 – OS Credential Dumping  
  - T1003.008 – /etc/shadow Access

## 📌 Priorität
- **Einschätzung:** Hoch (Zugriff auf Passworthashes oder Manipulation)
- **Eskalationsstufe:** SOC-Level 3 – kompromittierender Zugriff

## 🚨 Initial Response
1. Quelle identifizieren: Welcher Benutzer/Prozess griff auf `/etc/shadow` zu?
2. Legitimer Systemprozess oder manuelle Änderung?
3. Unmittelbare Reaktion:
   - Hash-Vergleich der Datei mit vorheriger Version
   - Benutzerkontext prüfen (Root, Sudo?)

## 🔍 Forensik
- Audit-Logs zu `/etc/shadow` sichern
- Prüfen, ob Änderungen mit Tools wie `vipw`, `usermod` oder direkt per `echo`/`tee` erfolgten
- Bash History und Prozessbaum analysieren
- Vergleich vorher/nachher der Datei (`sha256sum`, `diff`)
- Neue Benutzer oder veränderte Hashwerte identifizieren

## 🛡️ Maßnahmen
- Verdächtige Konten deaktivieren oder zurücksetzen
- Neue Benutzer/Manipulationen rückgängig machen
- Root-Passwort ändern
- Auditbeat-Regeln erweitern: Schreibzugriffe auf Shadow-Datei durch andere als `vipw`

## 📋 Kommunikation
- IR-Team sofort benachrichtigen
- IT-Sicherheitsleitung und ggf. Datenschutz informieren
- Interne Doku im IR-Ticket mit vollständigem Zeitverlauf

## 📁 Artefakte
- Auditd-Einträge (kompletter Zugriff inkl. User, PID, Cmdline)
- Vergleich der `/etc/shadow`-Datei (vorher/nachher)
- Hashes, Logfiles, Prozessinfos
- Benutzerkontext und Zeitpunkt der Änderung

## ✅ Lessons Learned
- Shadow-Dateizugriff ist hochkritisch – Regel weiter ausbauen
- Alle direkten Schreiboperationen außerhalb legitimer Tools erfassen
- Root-Schutzmechanismen stärken (z. B. Audit auf `echo`, `tee`, `sed` mit Shadow-Bezug)
- Einführung eines Change-Control-Prozesses für sensible Dateien