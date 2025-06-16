# Playbook: RDP Connection Attempt

## 🧠 Detection
- **Quelle:** Windows Security Logs (via winlogbeat, Elastic Agent)
- **Rule-ID / Query:**
  ```elasticsearch
  winlog.event_data.LogonType : "10" AND 
  process.executable : "C:\Windows\System32\svchost.exe"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1021.001 – Remote Services: Remote Desktop Protocol

## 📌 Priorität
- **Einschätzung:** Mittel – RDP-Zugriffe sind potenziell legitim, aber häufig von Angreifern genutzt
- **Eskalationsstufe:** SOC-Level 2 – erhöht, wenn ungewöhnliche Quelle oder Zeit

## 🚨 Initial Response
1. Quell-IP und Ziel-Hostname prüfen
2. Benutzeridentität verifizieren (Domänenkonto, Admin, Servicekonto)
3. Uhrzeit und Häufigkeit analysieren (z. B. viele fehlgeschlagene Logins?)

## 🔍 Forensik
- Korrelieren mit Event ID 4624 (erfolgreiches Logon), 4625 (Fehlgeschlagen), 4776 (NTLM Auth)
- Verhalten nach Logon untersuchen (z. B. Prozesse, Dateiaktivitäten)
- Quell-IP rückverfolgen (intern/extern, VPN, Jump Host)
- Session-Dauer und RemoteIP mit Geolokation oder Threat Intel abgleichen

## 🛡️ Maßnahmen
- IP blockieren bei verdächtigem Zugriff
- Benutzerpasswort ändern bei kompromittiertem Konto
- Netzwerksegmentierung/Firewall-Richtlinie prüfen
- MFA für RDP-Zugriff aktivieren

## 📋 Kommunikation
- IT-Security-Team und ggf. Netzwerkadmins informieren
- Dokumentation mit Quell-/Zielsystem, User, IP, Zeit, Geografie
- Falls extern: Rückmeldung an IR-Verantwortliche

## 📁 Artefakte
- Event mit `LogonType: 10` (RDP)
- Prozess: svchost.exe (für RDP-Sitzung relevant)
- Benutzername, IP-Adresse, Hostname
- Weitere Logons, Prozesse, Netzaktivität in Session-Zeitraum

## ✅ Lessons Learned
- RDP nur über sichere Kanäle wie VPN oder Jump Hosts
- Auditierung und Alerting auf externe RDP-Zugriffe verstärken
- RDP nur für autorisierte Benutzergruppen freigeben