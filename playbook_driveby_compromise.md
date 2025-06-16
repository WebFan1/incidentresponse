# Playbook: Drive-By Compromise – Suspicious Browser Spawned Process

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Sysmon (data_stream.dataset: "windows.sysmon_operational")
- **Rule-ID / Query:**
  ```elasticsearch
  data_stream.dataset : "windows.sysmon_operational"
  AND process.parent.name : "firefox.exe"
  AND event.code : "1"
  AND process.name : (
    "wscript.exe" OR "mshta.exe" OR "powershell.exe" OR "cmd.exe" OR
    "rundll32.exe" OR "certutil.exe" OR "regsvr32.exe" OR "msiexec.exe" OR
    "bitsadmin.exe"
  )
  ```
- **MITRE ATT&CK Mapping:**  
  - T1189 – Drive-by Compromise  
  - T1059 – Command and Scripting Interpreter  
  - T1203 – Exploitation for Client Execution

## 📌 Priorität
- **Einschätzung:** Hoch
- **Eskalationsstufe:** SOC-Level 2–3, abhängig vom Zielsystem

## 🚨 Initial Response
1. Quell-URL analysieren (z. B. Proxy-/DNS-Logs) → Welche Seite wurde besucht?
2. Überprüfen, ob das Kindprozess-Verhalten legitim ist (z. B. internes Skript oder IT-Tool)
3. Falls verdächtig:
   - Host in Quarantäne setzen oder Netzwerkzugriff einschränken
   - Prozesskette analysieren (Command Line, Hashes)
   - Incident eskalieren an IR-Team

## 🔍 Forensik
- Volle Prozesshierarchie analysieren (Parent > Child)
- Erfasste Command Line untersuchen (Argumente, URLs, Base64 etc.)
- Sysmon-Ereignisse im Zeitfenster untersuchen
- Browser-Verlauf (sofern vorhanden) sichern
- Suche nach Downloaddateien, Registry Keys, geplanten Tasks oder Persistenzmerkmalen

## 🛡️ Maßnahmen
- Sofort: Host isolieren, Speicher sichern (falls IR aktiv)
- Falls Malware bestätigt:
  - Datei-Hashes blockieren
  - IOC-Verteilung an AV/EDR
  - Kommunikation mit externen Domains blockieren (Proxy, DNS Sinkhole)
- Regel um weitere Browser ergänzen (chrome.exe, edge.exe etc.)

## 📋 Kommunikation
- Meldung an Security Team und ggf. betroffenen Benutzer
- IR-Ticket erstellen und dokumentieren
- Bei bestätigtem Angriff: Meldung an Datenschutz, falls Benutzer- oder Kundendaten betroffen

## 📁 Artefakte
- Prozessdaten (Parent/Child), Command Lines
- Verdächtige Dateien oder Skripte
- Proxy-/DNS-Logs (URL, IP, Zeit)
- Speicherabbild oder MFT/JL-Daten (wenn forensisch gesichert)

## ✅ Lessons Learned
- Regel sinnvoll für Initial Access über Browser-Exploits
- Weitere Browser ergänzen
- Sandbox-Test des Payloads empfohlen (z. B. Hybrid Analysis, Any.run)
- User Awareness Training: Vorsicht bei Downloads / JavaScript-Popups