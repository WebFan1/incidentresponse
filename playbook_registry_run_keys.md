# Playbook: Registry Run Keys Modification

## 🧠 Detection
- **Quelle:** Windows Eventlog (z. B. Sysmon)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_id: "13" AND 
  process.name : reg* AND 
  registry.path : *\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder

## 📌 Priorität
- **Einschätzung:** Hoch – potenzieller Persistenzmechanismus
- **Eskalationsstufe:** SOC-Level 2–3 – je nach Prozesskontext

## 🚨 Initial Response
1. Feststellen, welches Programm in den Run-Key eingetragen wurde
2. Prüfen, ob dies Teil eines legitimen Installationsvorgangs war
3. Analyse des ausführenden Prozesses und dessen Herkunft

## 🔍 Forensik
- Registry-Änderung analysieren: Key, Value, hinzugefügter Pfad
- EDR oder Sysmon prüfen auf Datei- und Netzwerkaktivität des referenzierten Programms
- Kontext des Schreibprozesses analysieren (z. B. Pfad, Benutzerkontext)

## 🛡️ Maßnahmen
- Pfad oder Datei prüfen und ggf. isolieren
- Registry-Eintrag entfernen oder sichern
- Persistenz beseitigen, wenn bösartig
- Host härten, z. B. per GPO oder EDR-Blocking für Run-Key-Manipulation

## 📋 Kommunikation
- IT-Security und ggf. Endpoint-Team benachrichtigen
- Ticket mit Registry-Daten, Prozessinformationen und Benutzerbezug anlegen
- Eskalieren, wenn sensible Systeme betroffen sind

## 📁 Artefakte
- Event ID 13 (Registry Value Set)
- Registry-Pfad (`Run`)
- Prozessname (z. B. reg.exe, PowerShell, Setup.exe)
- Benutzername, Hostname, Zeitstempel
- Inhalte der hinzugefügten Werte

## ✅ Lessons Learned
- Registry Run Keys sind gängige Methoden für Malware-Persistenz
- Überwachung dieser Keys ist essenziell
- Nutzung legitimer Software zum Schreiben in Run-Keys sollte dokumentiert sein