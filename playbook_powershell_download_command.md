# Playbook: PowerShell Download Command – HTTP Download via PowerShell

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Event Logging (Sysmon oder PowerShell logs)
- **Rule-ID / Query:**
  ```elasticsearch
  host.os.type : "windows" AND 
  message : (*Download* AND *http*)
  ```
- **MITRE ATT&CK Mapping:**  
  - T1059.001 – PowerShell  
  - T1105 – Ingress Tool Transfer

## 📌 Priorität
- **Einschätzung:** Hoch (Download potenzieller Malware oder Tools über PowerShell)
- **Eskalationsstufe:** SOC-Level 2–3 – je nach Kontext und Ziel

## 🚨 Initial Response
1. Kommandozeile oder Scriptinhalt vollständig sichern
2. Prüfen, ob die heruntergeladene Datei gespeichert oder direkt ausgeführt wurde
3. Quelle der Verbindung analysieren (URL, IP, Domain Reputation)

## 🔍 Forensik
- Prozessdetails analysieren (`powershell.exe`, `cmd.exe` als Parent?)
- Download-Verhalten verifizieren: wurde Datei in `%TEMP%`, `%APPDATA%`, etc. abgelegt?
- Datei-Hash berechnen und mit VirusTotal oder YARA prüfen
- Netzwerkverbindungen auswerten (Paketdaten, DNS-Auflösung)

## 🛡️ Maßnahmen
- Prozess beenden und Datei isolieren
- URL und IP blockieren (Firewall, Proxy, DNS-Blacklist)
- GPO/Applocker überprüfen: erlauben sie solche Aktivitäten?
- Endpoint-Schutz aktualisieren mit IOCs

## 📋 Kommunikation
- Sicherheitsverantwortliche informieren
- Benutzer kontaktieren (gezielter Angriff vs. Script-Fehlverhalten?)
- Dokumentation und Eskalation an IR bei erfolgreicher Payload-Ausführung

## 📁 Artefakte
- Kommandozeile oder Script-Content
- URL, Hostname, IP-Adresse
- Datei-Hash, Speicherort
- Benutzer, Hostname, Zeitstempel

## ✅ Lessons Learned
- Downloads via PowerShell sollten selten legitim sein – engmaschig überwachen
- Regel um `.downloadfile`, `.webclient`, `.webrequest` ergänzen
- PowerShell ExecutionPolicy und Logging verschärfen
- Awareness beim Umgang mit Anhängen und Links stärken