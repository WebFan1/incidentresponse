# Playbook: Brute Force Attempt – Mehrfache Login-Fehlversuche

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Security Eventlog (Event ID 4625)
- **Rule-ID / Query:**
  ```sql
  FROM logs*
  | WHERE event.code == "4625"
  | STATS failed_logins = COUNT(*), ip_count = COUNT_DISTINCT(source.ip) BY user.name, host.name
  | WHERE failed_logins >= 5 AND ip_count >= 1
  ```
- **MITRE ATT&CK Mapping:**  
  - T1110 – Brute Force  
  - T1110.001 – Password Guessing

## 📌 Priorität
- **Einschätzung:** Mittel (bei Standardbenutzer) bis Hoch (bei Admin-Konten)
- **Eskalationsstufe:** SOC-Level 2

## 🚨 Initial Response
1. Benutzername und Hostname analysieren – legitime Nutzung oder Angriffsversuch?
2. Quell-IP bewerten – intern, VPN, extern, bekannt?
3. Ereignisse zeitlich einordnen – Einzelereignis oder Muster?

## 🔍 Forensik
- Weitere Authentifizierungsereignisse auswerten (z. B. 4624 – Erfolgreiche Anmeldung)
- Quell-IP per DHCP oder AD zuordnen
- Benutzeraktivität und mögliche Auswirkungen prüfen
- Prozess oder Anwendung identifizieren, die zu den Fehlversuchen führte (z. B. Remote Desktop, Web-Login)

## 🛡️ Maßnahmen
- Konto sperren, wenn Missbrauch vermutet wird
- Quell-IP temporär blockieren oder weiter überwachen
- Passwort zurücksetzen, MFA prüfen/erzwingen
- Regel mit Schwellenwert-Tuning optimieren

## 📋 Kommunikation
- IT-Security oder SOC-Team informieren
- Benutzer benachrichtigen, wenn Eingabeprobleme vorliegen
- Eskalation an IR bei gehäuftem oder systematischem Auftreten

## 📁 Artefakte
- Event Logs: 4625 (Fehlversuche), ggf. 4624 (Erfolg)
- Benutzername, Hostname, Quell-IP, Zeit
- Login-Versuchsfrequenz und -verteilung

## ✅ Lessons Learned
- Regel auf Zeitfenster eingrenzen (z. B. 5 Fehlversuche in 10 Minuten)
- Korrelation mit Login-Erfolg erhöht Aussagekraft
- Sensible Konten separat überwachen (Admin, Servicekonten)
- Benutzer regelmäßig über sichere Anmeldemechanismen informieren