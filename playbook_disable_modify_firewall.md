# Playbook: Disable or Modify System Firewall

## 🧠 Detection
- **Quelle:** Windows Eventlog, Sysmon, Registry Monitoring
- **Rule-ID / Query:**
  ```elasticsearch
  (winlog.event_id : "1" AND process.args : *advfirewall*) OR 
  (registry.path : "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" AND winlog.event_id : "12")
  ```
- **MITRE ATT&CK Mapping:**  
  - T1562.004 – Impair Defenses: Disable or Modify System Firewall

## 📌 Priorität
- **Einschätzung:** Hoch – Deaktivierung oder Modifikation der Windows-Firewall kann zu ungeschützten Systemen führen
- **Eskalationsstufe:** SOC-Level 3 – potenziell Vorbereitung für unentdeckte Kommunikation oder Persistenz

## 🚨 Initial Response
1. Erfassen, welcher Befehl oder welche Registry-Änderung ausgeführt wurde
2. Prozesskontext und Benutzer ermitteln
3. Prüfen, ob Änderung autorisiert war (z. B. durch GPO, Script, Softwareverteilung)

## 🔍 Forensik
- Prozesse mit `advfirewall`-Argument analysieren
- Registry-Änderung protokollieren und mit vorherigem Zustand vergleichen
- Weitere sicherheitsrelevante Änderungen am System prüfen
- Inbound/Outbound-Kommunikation des Hosts beobachten

## 🛡️ Maßnahmen
- Firewall-Regeln wiederherstellen oder Policy neu anwenden
- Host ggf. isolieren und auf weitere Veränderungen prüfen
- Nutzerkontext bewerten und ggf. sperren
- Monitoring-Tools auf Manipulation prüfen

## 📋 Kommunikation
- SOC- und Netzwerkteam informieren
- Dokumentation mit Befehl, Registryänderung, Benutzer und Hostname
- Eskalation an IT-Sicherheit, wenn Angriff oder Test ausgeschlossen ist

## 📁 Artefakte
- Event ID 1 (Sysmon) mit `advfirewall`-Befehl
- Event ID 12 mit Registry-Pfad
- Prozessname, User, Hostname
- Kontextinformationen (GPO, Scriptnamen, Adminrechte)

## ✅ Lessons Learned
- Registry-Monitoring für kritische Firewall-Pfade einrichten
- Whitelisting für autorisierte Änderungen implementieren
- Schutz kritischer Dienste (Firewall, Defender) gegen Manipulation durch Härtung und GPO