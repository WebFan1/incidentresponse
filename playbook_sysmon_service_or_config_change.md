# Playbook: Sysmon Service State or Configuration Change

## 🧠 Detection
- **Quelle:** Sysmon Logs
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "4" OR event.code : "16"
  ```
  - **Event ID 4**: Sysmon Service state change (e.g. started, stopped)
  - **Event ID 16**: Sysmon configuration change

- **MITRE ATT&CK Mapping:**  
  - T1562.002 – Impair Defenses: Disable or Modify Tools

## 📌 Priorität
- **Einschätzung:** Hoch – Änderungen an Sysmon können auf Evasion-Versuche hindeuten
- **Eskalationsstufe:** SOC-Level 3 – unmittelbare Untersuchung erforderlich

## 🚨 Initial Response
1. Ermitteln, welcher Benutzer oder Prozess die Änderung vorgenommen hat
2. Kontext der Änderung analysieren: War es Teil eines autorisierten Admin-Vorgangs?
3. Prüfen, ob andere sicherheitsrelevante Dienste ebenfalls betroffen sind

## 🔍 Forensik
- Wer, wann, wie: Ausführender Prozess, Benutzername, Zeitstempel
- Konfiguration vergleichen mit gesicherter/Version-kontrollierter Datei
- Prüfung auf parallele Ereignisse (z. B. Log-Deaktivierung, AV-Stopp)
- Überwachung auf Folgeaktionen (Process Injection, Remote Access)

## 🛡️ Maßnahmen
- Konfiguration ggf. sofort wiederherstellen
- Monitoring aktivieren für Wiederholungen
- Endpoint- oder Systemzugriff temporär einschränken
- Änderungen dokumentieren und vergleichen mit Change Management

## 📋 Kommunikation
- IT-Security und Systemadministration informieren
- Falls extern verursacht: Eskalation an Incident Response
- Dokumentation für Audit und Compliance

## 📁 Artefakte
- Sysmon Event ID 4 und/oder 16
- Prozessname, Pfad, User
- Alte vs. neue Konfiguration (wenn möglich)
- Zeitstempel und Hostname

## ✅ Lessons Learned
- Sysmon-Konfiguration versionieren und zentral verwalten
- Regelmäßige Integritätsprüfung der Konfiguration
- Detektions- und Eskalationsstrategie bei Tool-Veränderungen überprüfen