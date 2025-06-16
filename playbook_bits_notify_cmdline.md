# Playbook: Persistence via BITS Job Notify Cmdline

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  event.type : "start"
  AND process.parent.name : "svchost.exe"
  AND process.parent.args : "BITS"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1197 – BITS Jobs  
  - T1547 – Boot or Logon Autostart Execution  
  - T1059 – Command and Scripting Interpreter

## 📌 Priorität
- **Einschätzung:** Hoch (Persistence-Versuch über legitimen Windows-Dienst)
- **Eskalationsstufe:** SOC-Level 3

## 🚨 Initial Response
1. Parent-Prozess `svchost.exe` mit Argumenten prüfen – ist ein BITS-JOB aktiv?
2. Command Line des Kindprozesses analysieren
3. Prüfen, ob ein NotifyCmdLine-Mechanismus genutzt wird, um ein Script oder Binary auszuführen

## 🔍 Forensik
- Nach aktiven BITS-Jobs suchen: `bitsadmin /list /allusers /verbose`
- Analyse der zugehörigen Downloads, Trigger und Befehle
- Prüfen, ob ungewöhnliche .exe, .ps1 oder .bat-Dateien nachgeladen wurden
- Hashes, Dateipfade und Signaturen der involvierten Dateien prüfen
- Registry- und Scheduled Task-Daten auf begleitende Persistenzhinweise untersuchen

## 🛡️ Maßnahmen
- Verdächtige BITS-Jobs löschen
- Alle referenzierten Dateien isolieren und analysieren
- Hashes in AV/EDR blockieren
- GPO- oder Applocker-Regeln zur Einschränkung von BITS persistenzfähig anpassen

## 📋 Kommunikation
- Incident Response Team benachrichtigen
- IT-Abteilung informieren bei legitimer Nutzung
- CISO und ggf. Datenschutz involvieren bei bestätigtem Persistenzangriff

## 📁 Artefakte
- Sysmon Event ID 1 (Prozessstart)
- Kommandozeile von Parent und Child
- BITS-Job-Konfiguration
- Referenzierte Dateien, Hosts und Benutzer

## ✅ Lessons Learned
- BITS NotifyCmdLine ist eine bekannte, aber oft übersehene Persistenzmethode
- Regel ergänzen mit Filter auf verdächtige Argumente (`/transfer`, `.ps1`, `.bat`)
- Detection Playbooks für andere LOLBins in Verbindung mit svchost erweitern
- Regelmäßige Auditierung laufender BITS-Jobs empfohlen