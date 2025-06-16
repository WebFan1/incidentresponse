# Playbook: Password Spray Activity – Breiter Authentifizierungsangriff

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Security Eventlog (Event ID 4625)
- **Rule-ID / Query:**
  ```sql
  FROM logs*
  | WHERE event.code == "4625"
  | STATS failed_logins = COUNT(*), ip_count = COUNT_DISTINCT(source.ip) BY user.name, host.name
  | WHERE failed_logins >= 20 AND ip_count >= 3
  ```
- **MITRE ATT&CK Mapping:**  
  - T1110 – Brute Force  
  - T1110.003 – Password Spraying

## 📌 Priorität
- **Einschätzung:** Hoch (Angriff mit dem Ziel der Kontoübernahme)
- **Eskalationsstufe:** SOC-Level 2–3

## 🚨 Initial Response
1. Betroffenen Benutzernamen und Host identifizieren
2. Quell-IPs prüfen – stammen sie aus dem internen Netz oder extern?
3. Vergleich mit bekannten Scan-/Angreifer-IPs (Blacklist, Threat Intel)

## 🔍 Forensik
- Log-Analyse: Zeitfenster der Versuche, Frequenz, IPs
- Kombination mit 4624 (Erfolgreiche Anmeldung) prüfen → war ein Versuch erfolgreich?
- Benutzerstatus analysieren: Admin-Konto? Gesperrt? MFA aktiv?
- Netzwerkanalyse: IP-Zuordnung, DHCP, VPN-Endpunkte

## 🛡️ Maßnahmen
- Konten mit hohem Risiko (Admin, Servicekonten) manuell sperren
- MFA forcieren oder Passwort zurücksetzen
- IP-Adressen blockieren oder auf Quarantäneliste setzen
- Alerting für weitere 4625-Serien aktivieren

## 📋 Kommunikation
- IT und Benutzer über ungewöhnliche Login-Versuche informieren
- Eskalation an IR-Team bei bestätigtem Angriff
- Management benachrichtigen bei Zugriff auf kritische Systeme

## 📁 Artefakte
- Event Logs 4625 und ggf. 4624
- Benutzername, Hostname, Quell-IP, Zeitstempel
- Zusammenhang mit parallelen Anmeldeversuchen

## ✅ Lessons Learned
- Regel ggf. mit Zeitfenster (z. B. 20 Versuche in 1 Stunde) verfeinern
- Passwortspray-Erkennung auf Servicekonten und Admins fokussieren
- Kombination mit Geolocation und Tageszeit zur Risikoeinschätzung sinnvoll
- Awareness-Kampagne für Benutzer zu Passwortsicherheit und MFA-Verwendung