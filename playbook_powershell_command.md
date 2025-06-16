# Playbook: Suspicious PowerShell Command – Obfuscated or Malicious Execution

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  host.os.type : "windows" AND 
  process.name : "powershell.exe" AND 
  message : (
    *DownloadString* OR 
    *-nop* OR 
    *-noni* OR 
    *iex* OR 
    *DownloadFile* OR 
    *Get-Content -Stream* OR 
    *Invoke-Expression* OR 
    *-e*
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1059.001 – PowerShell  
  - T1055 – Process Injection  
  - T1105 – Ingress Tool Transfer

## 📌 Priorität
- **Einschätzung:** Hoch (Hinweis auf verschleierte oder bösartige PowerShell-Nutzung)
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. PowerShell-Kommandozeile extrahieren und auf Obfuskation prüfen
2. Ursprung des Prozesses untersuchen: Benutzer, Parent-Prozess
3. Wenn URL/Download enthalten: Traffic blockieren, IOC-Erfassung

## 🔍 Forensik
- Kommandozeile analysieren: Base64-Decodierung, `-e`, `iex`, `DownloadString`
- Prozesse: Childs von `powershell.exe`, deren Pfade und Verhalten
- Dateiaktivitäten: Wurde ein Script geladen, geschrieben oder ausgeführt?
- Netzwerkaktivität: Verbindungen zu externen Servern

## 🛡️ Maßnahmen
- Prozess stoppen, Datei isolieren
- GPO/Applocker/Constrained Language Mode prüfen und verschärfen
- IOC-Erweiterung: Domains, Hashes, Pfade, Command Patterns
- Erweiterung der SIEM-Signatur um zusätzliche Parameter oder Obfuskationstechniken

## 📋 Kommunikation
- IR-Team informieren
- Benutzer kontaktieren (Fehlverhalten oder Ziel eines Angriffs?)
- Ggf. Information an CISO bei Verbindungsaufnahme nach außen

## 📁 Artefakte
- Vollständige Kommandozeile
- Netzwerkverbindungen, URLs, Domains
- Parent- und Child-Prozesse
- Zeitstempel, Benutzername, Hostname

## ✅ Lessons Learned
- PowerShell ist ein zentrales Angriffsvehikel – strenge Kontrolle notwendig
- Kombination mit Sysmon, AMSI (Antimalware Scan Interface) und Script Block Logging empfehlenswert
- Awareness für Devs/Admins: legitime Nutzung dokumentieren und kennzeichnen
- Regel regelmäßig um neue Obfuskationstechniken und Tools ergänzen