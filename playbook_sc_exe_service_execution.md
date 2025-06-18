# Playbook: SC.EXE - System Services: Service Execution

## 🧠 Detection
- **Quelle:** Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code: "1" AND process.name : "sc.exe"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1569.002 – System Services: Service Execution

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch – `sc.exe` wird oft zur Service-Installation, -Start oder -Manipulation verwendet
- **Eskalationsstufe:** SOC-Level 2 bis 3 – je nach Kontext und Benutzer

## 🚨 Initial Response
1. Kommandozeile analysieren: Wird ein Service erstellt, gestartet oder konfiguriert?
2. Kontext prüfen: Welcher Benutzer, welcher Parent-Prozess?
3. Zielservice identifizieren und bewerten, ob dieser legitim ist

## 🔍 Forensik
- Kommandozeile, Parent-Prozess, Zeitstempel analysieren
- Registry-Pfade und Dienstkonfiguration untersuchen
- Netzverhalten des betroffenen Dienstes analysieren (wenn zutreffend)
- Nachgelagerte Prozesse des Dienstes prüfen (z. B. bei Payload-Ausführung)

## 🛡️ Maßnahmen
- Dienst deaktivieren oder entfernen, falls verdächtig
- ggf. Prozess beenden und Host überwachen oder isolieren
- IOC (Service-Name, Binary-Pfad, Hash) sichern und einspeisen
- Benutzeraktionen prüfen und ggf. Zugriff temporär sperren

## 📋 Kommunikation
- IT-Security und zuständige Windows-Admins informieren
- Dokumentation im IR-Ticket: Host, User, Kommandozeile, Kontext
- Optional: Eskalation an Threat Intel, falls APT-Verdacht

## 📁 Artefakte
- Sysmon Event ID 1
- Prozessname: `sc.exe`
- Komplette Kommandozeile
- Benutzer, Hostname, Zeit
- Konfiguration und Pfad des Ziel-Dienstes

## ✅ Lessons Learned
- Whitelist der erlaubten `sc.exe`-Operationen definieren
- Überwachung von Dienstkonfigurationen (z. B. autorun oder persistente Services)
- Logging und Monitoring stärken für Service-bezogene Aktivitäten