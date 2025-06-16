# Playbook: PowerShell & CMD Process Injection – Verdächtige Injektionstools

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  process.command_line : (
    *Invoke-Shellcode* OR 
    *InjectProc.exe* OR 
    *dll_inj*
  ) OR (
    *InjectProc.exe* OR 
    *dll_inj*
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1055 – Process Injection  
  - T1059.001 – PowerShell  
  - T1106 – Native API

## 📌 Priorität
- **Einschätzung:** Hoch (manuelle oder automatisierte Injektion in Prozesse)
- **Eskalationsstufe:** SOC-Level 3

## 🚨 Initial Response
1. Befehl und Prozess analysieren – wurde PowerShell mit `Invoke-Shellcode` oder `InjectProc.exe` genutzt?
2. Parent-Prozess und Benutzer identifizieren
3. Prüfen, ob Code-Injektion auf bekannte Prozesse (z. B. `explorer.exe`, `lsass.exe`) zielte

## 🔍 Forensik
- Kommandozeile vollständig sichern (Base64 dekodieren, falls verschleiert)
- Prozessbaum analysieren – wer hat was gestartet?
- Hashes und Pfade der involvierten Binaries prüfen
- RAM-/Prozessdump des Zielprozesses zur Analyse erstellen
- Korrelieren mit bekannten TTPs aus Threat Intel

## 🛡️ Maßnahmen
- Prozess stoppen, Host isolieren
- IOC-Erstellung aus Hashes, Domains, Tools
- EDR-Blocklisten aktualisieren
- Regel erweitern um typische Varianten (`Invoke-ReflectivePEInjection`, `Start-ProcessInjection`)

## 📋 Kommunikation
- Security- und IR-Teams sofort informieren
- Management ggf. einbinden bei Zielsystemen mit kritischem Kontext
- Benutzerüberprüfung durchführen (Missbrauch interner Konten)

## 📁 Artefakte
- Kommandozeilen-Parameter, Base64-Strings
- Prozesspfade, Hashes, Parent/Child-Beziehungen
- RAM- oder Prozessausschnitte
- Zeitstempel, Benutzer, Hostname

## ✅ Lessons Learned
- PowerShell-Injection ist stark verbreitet – Regel auf Obfuskation & Payload-Typen ausweiten
- Detection ergänzen durch Regex-basierte Argumentanalysen
- Whitelist legitimer Tools mit ähnlichen Namen vermeiden False Positives
- Monitoring aller ScriptRunner-Kontexte (z. B. Scheduled Task, Service) ausweiten