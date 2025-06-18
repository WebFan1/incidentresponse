# Playbook: PsExec Used

## 🧠 Detection
- **Quelle:** Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "1" AND process.parent.executable : *PSEXESVC.exe*
  ```

- **MITRE ATT&CK Mapping:**  
  - T1021.002 – Remote Services: SMB/Windows Admin Shares  
  - T1569.002 – System Services: Service Execution

## 📌 Priorität
- **Einschätzung:** Hoch – PsExec wird oft für Lateral Movement und Remote Execution verwendet
- **Eskalationsstufe:** SOC-Level 3 – sofortige Untersuchung, ob autorisierte Nutzung vorliegt

## 🚨 Initial Response
1. Benutzer, Hostname und Zielprozess identifizieren
2. Kommandozeile analysieren – was wurde remote ausgeführt?
3. Verbindungskontext prüfen: Remote-Host, Authentifizierungsmechanismus, Zeit

## 🔍 Forensik
- Prozessbaum analysieren (Parent-Child-Struktur)
- Netzwerkverbindungen prüfen – SMB, Remote Shares
- Dateioperationen und gestartete Dienste untersuchen
- Hosthistorie prüfen auf wiederholte oder automatisierte Nutzung

## 🛡️ Maßnahmen
- Remotezugriff sperren (z. B. SMB deaktivieren oder blockieren)
- Konto/Host temporär isolieren, wenn nicht autorisiert
- IOC (Kommandozeile, IP, Hash, Prozesspfad) sammeln
- auf weiteren Hosts nach PsExec-Aktivitäten suchen

## 📋 Kommunikation
- Security-Team, Admins und ggf. IR-Team informieren
- Dokumentation mit Host, User, Befehlen, Zielsystemen
- Eskalation je nach Verdacht auf Missbrauch oder APT

## 📁 Artefakte
- Sysmon Event ID 1
- Parent: `PSEXESVC.exe`
- Kommandozeile, Remote-Hostname/IP, Zeitstempel
- Authentifizierungsdaten, Prozessname

## ✅ Lessons Learned
- PsExec-Nutzung dokumentieren und autorisierte Pfade einschränken
- Detection-Logik ergänzen mit SMB-Zugriffsüberwachung
- Use Cases zur Erkennung lateral bewegender Tools erweitern (z. B. `WinRM`, `WMIC`, `RDP`)