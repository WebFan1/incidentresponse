# Playbook: Group Policy Modification – Active Directory GPO Change

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Security Eventlog (Event ID 5136)
- **Rule-ID / Query:**
  ```elasticsearch
  host.name : "pdc"
  AND event.code : "5136"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1484 – Domain Policy Modification  
  - T1484.001 – Group Policy Modification

## 📌 Priorität
- **Einschätzung:** Hoch (potenziell kritische Rechteänderungen)
- **Eskalationsstufe:** SOC-Level 3, sofortige Untersuchung

## 🚨 Initial Response
1. Änderungsdetails analysieren:
   - Welche GPO wurde geändert?
   - Welche Attribute (z. B. `gPCFileSysPath`, `displayName`, `versionNumber`) wurden angepasst?
2. Wer hat die Änderung durchgeführt (Benutzername, Logon ID)?
3. Legitimität prüfen:
   - War dies eine geplante Änderung durch IT?
   - Änderungszeitpunkt mit Change Requests oder Wartungsfenster abgleichen

## 🔍 Forensik
- Vollständige Eventdaten sichern (Security Log 5136)
- AD-Replikationsstatus prüfen (wurden Änderungen bereits übernommen?)
- Vergleich mit vorherigem GPO-Stand (Backup/Snapshot, Versionierung)
- Prüfen, ob Änderungen zu erhöhten Berechtigungen oder Auto-Execution führen
- Nachfolgende Events auf betroffenen Systemen untersuchen (z. B. Event ID 4739, 4732, 4733)

## 🛡️ Maßnahmen
- Falls unautorisiert:
  - GPO rückgängig machen (Restore aus Backup oder Vorversion)
  - Konto sperren oder Untersuchung einleiten
  - Host/Benutzer unter Monitoring stellen
- Logging auf GPO-Verzeichnisse aktivieren
- GPO-Änderungen nur über dedizierte Management-Hosts zulassen

## 📋 Kommunikation
- Incident an AD/Domain-Team melden
- Sicherheitsverantwortliche benachrichtigen (CISO/CERT)
- Bei bestätigtem Vorfall: Management und ggf. Datenschutz informieren

## 📁 Artefakte
- Eventlog 5136 (vollständig)
- Benutzername, Hostname, Logon ID
- Zeitstempel, GPO-ID, geänderte Attribute
- Vergleich vorher/nachher der GPO (Backup oder AD-Versionsdatenbank)

## ✅ Lessons Learned
- Regel sinnvoll zur Erkennung von GPO-Missbrauch
- Ergänzung durch Event 4739 (Gruppenrichtlinienänderung) oder 4719 (Audit Policy)
- Verbesserung der GPO-Change-Logging-Prozesse
- Einrichtung von Alerting auf untypische GPO-Änderungszeiten (z. B. nachts)