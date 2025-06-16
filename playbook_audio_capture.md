# Playbook: Audio Capture – Zugriff auf Mikrofon-/Audioobjekte im System

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Eventlog (Registry Monitoring)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_data.ObjectName : *MMDevices\Audio\Capture* OR
  winlog.event_data.ObjectName : *InprocServer32* OR
  winlog.event_data.ObjectName : *CLSID\\BDCB0395-E52F-467C-8E3D-C45792591692*
  ```
- **MITRE ATT&CK Mapping:**  
  - T1123 – Audio Capture  
  - T1119 – Automated Collection (bei weitergehender Überwachung)

## 📌 Priorität
- **Einschätzung:** Hoch (Hinweis auf Spionage- oder Überwachungsaktivität)
- **Eskalationsstufe:** SOC-Level 3, hohe Vertraulichkeit

## 🚨 Initial Response
1. Ermitteln, welcher Prozess auf die Audioobjekte oder CLSIDs zugegriffen hat
2. Bewertung: legitimer Zugriff (z. B. durch Kommunikationssoftware) oder verdächtig?
3. Falls kein legitimer Kontext erkennbar:
   - Host zur weiteren Untersuchung kennzeichnen
   - Prozessdaten, Hashes und Benutzer erfassen

## 🔍 Forensik
- Zugriffskette analysieren: Welcher Pfad, Prozess, Benutzer?
- Registry-Änderungen oder Ladeversuche dokumentieren
- Speicherabbild des Prozesses ziehen (sofern zulässig)
- Netzwerkverbindungen prüfen (Exfiltration?)
- AV/EDR-Telemetrie nach paralleler Spionageaktivität durchsuchen

## 🛡️ Maßnahmen
- Host ggf. isolieren
- Prozess und Hash blockieren
- IOC-Erweiterung: ähnliche CLSIDs, Module, Pfade
- Benutzerkonten temporär sperren, falls interner Missbrauch nicht ausgeschlossen ist

## 📋 Kommunikation
- Eskalation an IR-Lead, ggf. CISO
- Dokumentation im IR-Ticket mit hoher Vertraulichkeit
- Bei Spionageverdacht: Geschäftsführung, Datenschutz und Rechtsabteilung einbinden

## 📁 Artefakte
- Event Logs mit Zugriff auf `MMDevices\Audio\Capture` oder `CLSID`
- Prozessinformationen: Name, Pfad, Hash, CmdLine
- Netzwerkdaten (Exfil-Verdacht)
- Benutzerkontext (SID, Hostname, Logon-Typ)

## ✅ Lessons Learned
- Audio-/Videoüberwachung ist ein kritisches Spionage-Indiz
- Regel auf weitere Audio-/Videoobjekte ausweiten (z. B. `VideoCapture`, `DeviceAccess`)
- EDR-Integration und Alerting über verdächtige Mikrofon-Zugriffe verbessern
- Awareness schaffen für "stille Überwachung" – besonders bei mobilen Geräten