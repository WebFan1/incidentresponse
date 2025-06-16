# Playbook: Suspicious DNS Request – WPAD Query

## 🧠 Detection
- **Quelle:** Elastic SIEM – Windows Sysmon (DNS Monitoring via Event ID 22)
- **Rule-ID / Query:**
  ```elasticsearch
  event.code : "22"
  AND event.action : "DNSEvent (DNS query)"
  AND dns.question.name : "wpad"
  ```
- **MITRE ATT&CK Mapping:**  
  - T1557 – Adversary-in-the-Middle  
  - T1557.001 – LLMNR/NBT-NS Poisoning and WPAD Relay

## 📌 Priorität
- **Einschätzung:** Mittel bis Hoch (je nach Netzwerk-Design und Kontext)
- **Eskalationsstufe:** SOC-Level 2, Prüfung erforderlich

## 🚨 Initial Response
1. Prüfen, ob WPAD im Netzwerk verwendet wird – viele Umgebungen nutzen es nicht mehr
2. Ursprung des Requests analysieren – welches Gerät? welcher Benutzer?
3. Prüfen, ob der Request zu einem legitimen internen Host führt oder eine externe Auflösung versucht wurde

## 🔍 Forensik
- Quell-Host, Quell-User, Timestamp und Auflösungspfad prüfen
- DNS-Logs oder Proxy-Logs untersuchen – wurde WPAD weitergeleitet?
- ARP/DHCP prüfen, ob sich Systeme als WPAD-Server ausgeben
- Suche nach Tools wie Responder oder Inveigh auf verdächtigen Hosts

## 🛡️ Maßnahmen
- Falls WPAD nicht verwendet wird:  
  - DNS-Antworten für `wpad` unterbinden  
  - WPAD via GPO deaktivieren (z. B. per Proxy Auto-Detection ausschalten)
- Quellgerät überprüfen – ggf. EDR, Prozessdaten sichern
- Monitoring auf weitere Anfragen wie `LLMNR`, `NBNS` oder `mDNS`

## 📋 Kommunikation
- Information an Netzwerkteam (zur DNS-Konfiguration)
- IT-Security-Team über potenziellen MITM-Angriffsversuch informieren
- Benutzerkommunikation in der Regel nicht erforderlich (außer Kompromittierung)

## 📁 Artefakte
- DNS Event Logs (event.code: 22)
- Quellgerät, Benutzername, IP-Adresse
- EDR oder Sysmon-Daten vom Quell-Host
- Kontext: DHCP/ARP-Informationen, Namensauflösung im Umfeld

## ✅ Lessons Learned
- WPAD-Anfragen bieten Angriffsfläche – sollten unterbunden werden, wenn nicht benötigt
- Regel durch Erkennung von `LLMNR`, `NBNS`, `mDNS` erweitern
- WPAD über IPv6 (z. B. SLAAC) prüfen – manche Tools nutzen Dual Stack
- Awareness-Training zu "Silent MITM"-Techniken ergänzen