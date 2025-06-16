# Playbook: PowerShell Obfuscation Command Detection

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```kuery
  process.name : "powershell.exe" AND (
    process.command_line : "*`*" OR
    process.command_line : "*^*" OR
    process.command_line : "*+$*" OR
    process.command_line : "*[char*]*" OR
    process.command_line : "*FromBase64String*" OR
    process.command_line : "*[System.Text.Encoding]*" OR
    process.command_line : "*-enc*" OR
    process.command_line : "*-e*" OR
    process.command_line : "*iex*" OR
    process.command_line : "*Invoke-Expression*" OR
    process.command_line : "*Invoke-Command*" OR
    process.command_line : "*Invoke-WebRequest*" OR
    process.command_line : "*Invoke-Shellcode*" OR
    process.command_line : "*New-Object*" OR
    process.command_line : "*Reflection.Assembly*" OR
    process.command_line : "*Net.WebClient*" OR
    process.command_line : "*Add-Type*" OR
    process.command_line : "*&{*"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1059.001 – PowerShell  
  - T1027 – Obfuscated Files or Information

## 📌 Priorität
- **Einschätzung:** Hoch (verschleierte Befehle können Malware oder Payloads enthalten)
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. Kommandozeile vollständig extrahieren und ggf. entschlüsseln (Base64)
2. Ursprung und Benutzerkontext des PowerShell-Aufrufs prüfen
3. Netzwerkverbindungen und Dateischreibaktivitäten analysieren

## 🔍 Forensik
- Prozessinformationen erfassen (Hash, Pfad, Parent-Prozess)
- Erkennen, ob Skript aus Datei, über URL oder Base64 geladen wurde
- Command History des Benutzers untersuchen
- RAM oder Prozessdump anfertigen bei aktivem Payload-Verdacht

## 🛡️ Maßnahmen
- Host isolieren, falls Payload aktiv ist oder Netzwerkzugriffe bestehen
- PowerShell-Logging (ScriptBlockLogging, ModuleLogging) aktivieren
- ExecutionPolicy überprüfen
- IOC-Erweiterung: Base64-Payloads, Domains, IPs, verdächtige Pfade

## 📋 Kommunikation
- IR-Team informieren, Analyst zur manuellen Bewertung
- Benutzer kontaktieren (insb. bei verdächtigen Skripten aus E-Mails)
- Dokumentation im IR-Ticket mit Zeitstempel, Benutzer, Hostname

## 📁 Artefakte
- Kommandozeile (ggf. decodiert)
- Event-Daten zu Prozess, Host, Benutzer
- Datei- und Netzwerkartefakte (Downloads, geschrieben Dateien)
- Speicherabbild, falls Payload im RAM

## ✅ Lessons Learned
- PowerShell mit Base64 oder dynamischen Methoden ist extrem beliebt bei Angreifern
- Logging-Ausbau: ScriptBlockLogging, Transcription aktivieren
- Kombination mit EDR, AppLocker oder WDAC zur Blockade
- Benutzer-Awareness und Makro-Filterung bei Office-Dateien ergänzen