# Playbook: PsExec - System Services: Service Execution

## 🧠 Detection
- **Quelle:** Sysmon (Event ID 1 – Process Creation)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "1" AND process.parent.executable : "C:\\Windows\\PSEXESVC.exe"
  ```

- **MITRE ATT&CK Mapping:**  
  - T1569.002 – System Services: Service Execution  
  - T1021.002 – Remote Services: SMB/Windows Admin Shares

## 📌 Priorität
- **Einschätzung:** Hoch – PsExec wird häufig für Lateral Movement und Remote Execution verwendet
- **Eskalationsstufe:** SOC-Level 3 – kritisch prüfen, ob legitimer Admin oder Angreifer

## 🚨 Initial Response
1. Ausführende Identität prüfen – Benutzer, Hostname, Uhrzeit
2. Kommandozeile und Zielprozess analysieren
3. Verbindungskontext prüfen (remote IP, Authentifizierungsart)

## 🔍 Forensik
- Prozessbaum analysieren: welche Aktion wurde über PsExec ausgeführt?
- Netzwerkverbindungen prüfen (SMB, RPC, Remote Shares)
- Vergleich mit normalen PsExec-Adminaktionen
- Nachgelagerte Prozesse und Dateioperationen überwachen

## 🛡️ Maßnahmen
- Zugriff temporär unterbrechen (z. B. SMB blockieren, Konto sperren)
- Host isolieren bei Anzeichen von Missbrauch
- IOC sichern (CommandLine, Hash, User)
- weitere Systeme auf ähnliche PsExec-Nutzung prüfen

## 📋 Kommunikation
- Security-Team und Windows-Admins benachrichtigen
- Nutzung dokumentieren: User, Pfad, Remote-IP, Uhrzeit
- Entscheidung über Eskalation bei unautorisierter Nutzung

## 📁 Artefakte
- Sysmon Event ID 1
- Parent: `PSEXESVC.exe`
- Benutzer, Zielhost, Remote-IP
- Prozessbaum und Kommandozeile

## ✅ Lessons Learned
- PsExec-Nutzung klar definieren und beschränken
- Anomalie-Erkennung bei Remote-Tools wie PsExec, WMIC, WinRM
- Regelmäßige Kontrolle autorisierter Admin-Tools im Netzwerk