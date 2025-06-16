# Playbook: LOLBins Execution Detection

## 🧠 Detection
- **Quelle:** Sysmon / Elastic Agent (Windows Endpoints)
- **Rule-ID / Query:**
  ```elasticsearch
  (
    process.name : "certutil.exe" or
    process.name : "mshta.exe" or
    process.name : "rundll32.exe" or
    process.name : "regsvr32.exe" or
    process.name : "powershell.exe" or
    process.name : "wscript.exe" or
    process.name : "cscript.exe" or
    process.name : "forfiles.exe" or
    process.name : "bitsadmin.exe" or
    process.name : "installutil.exe" or
    process.name : "wmic.exe" or
    process.name : "schtasks.exe" or
    process.name : "cmd.exe" or
    process.name : "scriptrunner.exe"
  )
  and not user.name : "SYSTEM"
  and not process.parent.name : "explorer.exe"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1218 – Signed Binary Proxy Execution  
  - T1059 – Command and Scripting Interpreter

## 📌 Priorität
- **Einschätzung:** Hoch – LOLBins werden oft von Angreifern zur Umgehung von Schutzmaßnahmen verwendet
- **Eskalationsstufe:** SOC-Level 3 – bei ungewöhnlichen Kontexten oder mehrfacher Nutzung

## 🚨 Initial Response
1. Prozessdetails analysieren (Command-Line, User, Parent-Prozess)
2. Prüfen, ob Ausführung interaktiv oder durch Skript erfolgt
3. Netzwerkverbindungen und Dateioperationen korrelieren

## 🔍 Forensik
- Komplette Kommandozeile und zugehörige Aktivitäten sammeln
- Elternprozess analysieren (warum wurde LOLBin gestartet?)
- Netzwerkverbindungen während oder nach Ausführung prüfen
- Vergleich mit legitimen Nutzungsmustern im Unternehmen

## 🛡️ Maßnahmen
- Prozess und ggf. zugehörige Payloads isolieren
- Nutzer oder Systemzugang überprüfen/sperren
- Hashes und Pfade zur IOC-Liste hinzufügen
- Regelhärtung oder AppLocker-Einsatz prüfen

## 📋 Kommunikation
- IT-Security-Team benachrichtigen
- Vorgang dokumentieren mit Screenshot/Log-Auszügen
- Analyseergebnisse ggf. an Threat Intel weiterleiten

## 📁 Artefakte
- Prozessname, Elternprozess, Command-Line
- Benutzerkontext und Zeitpunkt
- Dateien, die ausgeführt oder geladen wurden
- Netzverbindungen, DNS, Payloads

## ✅ Lessons Learned
- Nutzung von LOLBins in legitimen Tools prüfen und dokumentieren
- Execution Restrictions (z. B. Applocker, WDAC) einsetzen
- Awareness bei Admins für typische LOLBin-Missbrauchsszenarien erhöhen