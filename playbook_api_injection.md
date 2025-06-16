# Playbook: Suspicious API-Call / Injection Attempt

## 🧠 Detection
- **Quelle:** Elastic SIEM – Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  process.command_line : (
    "VirtualAllocEx" OR 
    "WriteProcessMemory" OR 
    "CreateRemoteThread" OR 
    "RtlCreateUserThread"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1055 – Process Injection  
  - T1055.001 – Dynamic-link Library Injection  
  - T1055.002 – Portable Executable Injection

## 📌 Priorität
- **Einschätzung:** Hoch (Hinweis auf Code Injection oder Malware)
- **Eskalationsstufe:** SOC-Level 3 – direkte Untersuchung erforderlich

## 🚨 Initial Response
1. Identifizieren, welcher Prozess den API-Call durchgeführt hat (Name, Pfad, Signatur)
2. Parent-Prozess und Ausführungskontext prüfen (Adminrechte? Remote?)
3. Weitere Aktivitäten des Prozesses analysieren (z. B. Netzwerk, Dateioperationen)

## 🔍 Forensik
- Hash und Kommandozeile des verdächtigen Prozesses erfassen
- Untersuchen, welches Ziel per API-Aufruf betroffen war (PID, Name)
- Prozessspeicher des Ziels dumpen und analysieren (z. B. mit procdump)
- Prüfen, ob bekannte Tools wie Mimikatz, Cobalt Strike, Meterpreter beteiligt sind
- Korrelieren mit Logs aus EDR/Sandbox/YARA-Ergebnissen

## 🛡️ Maßnahmen
- Prozess terminieren oder Host isolieren
- Datei-Hashes blockieren (EDR, AV, Elastic)
- Benutzerkontext untersuchen und ggf. sperren
- IOC-Verteilung und Threat Hunt auf ähnliche Aktivitäten

## 📋 Kommunikation
- Incident an IR-Team übergeben
- Sicherheitsverantwortliche informieren
- Management involvieren bei erfolgreicher Injektion oder kritischem Kontext

## 📁 Artefakte
- Prozessdetails (Name, PID, Parent, CmdLine, Hash)
- Speicherabbild (RAM/Process Dump)
- API-Aufruf-Zielprozess (PID, Binary)
- Zeitstempel, Benutzer, Hostname

## ✅ Lessons Learned
- API-basierte Injektion ist ein zentraler Bestandteil vieler Angriffe
- Regel ergänzen um zeitliche Korrelation oder Prozessbeziehungen
- EDR-Integration zur Frühverhinderung empfehlenswert
- Code-Injection-Detection auch auf Service-Prozesse (LSASS, explorer.exe) ausweiten