---
layout: post
title: Find the leaking bucket! Write-up - STACK The Flags 2020
---

This is a challenge from the Cloud category of the inaugural STACK The Flags in 2020. (Team bella ciao) 

## Challenge Description

***

It was made known to us that agents of COViD are exfiltrating data to a hidden S3 bucket in AWS! We do not know the bucket name! One tip from our experienced officers is that bucket naming often uses common words related to the company’s business.

Do what you can! Find that hidden S3 bucket (in the format “word1-word2-s4fet3ch”) and find out what was exfiltrated!

Please ignore these troll buckets:
- s3://intelligent-intelligent-s4fet3ch/
- s3://steve-jobs-s4fet4ch/
- s3://mobile-cybersecurity-s4fet3ch/

***

### Company Website

A URL to the [company website](https://d1ynvzedp0o7ys.cloudfront.net/) is also given. (Not sure how long it will be up.) 

A screenshot of the website is shown below.

![website](./website.jpg)

## Constructing a Wordlist

Knowing that the format of the bucket name is "word1-word2-s4fet3ch", our first step is to scrape the website to contruct a list of words related to the company's business.

Conveniently, the webpage has a word cloud. After taking a quick look at the html source code, the keywords are nested within `<p>` tags, so the command below works to extract the keywords.

```
$ curl -s https://d1ynvzedp0o7ys.cloudfront.net/ | sed -n 's:.*>\(.*\)</p>.*:\1:p'
Safe Online Technologies
wireless
<SNIP>
mobile
intelligent
```

(Between the first and second `:` of the sed command is a regex that grabs text in between `>` and `</p>`.)

We just need to clean up the list a little by separating the company name into words.

Another way is to use a ruby app [CeWL](https://github.com/digininja/CeWL) which is a useful tool for creating custom wordlists. It has many more features that we are not using here, so you can check it out to learn more.

```
$ cewl https://d1ynvzedp0o7ys.cloudfront.net/
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
Safe
Online
Technologies
Home
<SNIP>
intelligent
```

Finally, there is a quote in an image at the bottom of the page.

![quote](./quote.jpg)

Let's manually extract the words from the quote, skipping the stop words, and add them to our wordlist.

* people
* crazy
* enough
* think
* change
* world
* ones
* steve
* jobs

We end up with a list of 37 keywords - `wordlist.txt`.

## Building a List of Possible Bucket Names

Now, we will use the words in `wordlist.txt` to generate a list of possible bucket names.

For a task like this, I used to whip up a bash script like this:

```
#!/bin/bash
# generatebucketlist.sh

list1="wordlist.txt"
list2="wordlist.txt"

while IFS= read -r word1
do
    while IFS= read -r word2
    do
        url="${word1}-${word2}-s4fet3ch"
        echo "$url" >> "bucket_list"
    done < "$list2"
done < "$list1"
```

But then I learned that text processing with a shell loop is not the best idea. ([Read about it here.](https://unix.stackexchange.com/questions/169716/why-is-using-a-shell-loop-to-process-text-considered-bad-practice))

So let's try to do better, with [awk](https://www.grymoire.com/Unix/Awk.html).

`awk '{a[$0]} END{for (i in a) for (j in a) print i"-"j"-s4fet3ch"}' wordlist.txt > bucket_list.txt`

Essentially, this command declares an associate array `a` using the first column (which is our list of words) as its index. Then we do a double loop through the keys to print all the possible bucket names.

Other than having less to type, using awk is much faster, as you can see below. While performance is not a concern here given our small wordlist, it can be in some cases, so this is a nice option to have.

```
$ time ./generatebucketlist.sh

real    0m0.088s
user    0m0.044s
sys     0m0.044s

$ time awk '{a[$0]} END{for (i in a) for (j in a) print i"-"j"-s4fet3ch"}' wordlist.txt > bucket_list.txt

real    0m0.004s
user    0m0.000s
sys     0m0.005s
```

## Brute-forcing buckets

Armed with `bucket_list.txt`, we can start bruteforcing to find the bucket.

But first let's talk about AWS S3 access controls.

This [article](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/) offers a great explanation of AWS S3 access controls. In particular, take note of the AuthenticatedUsers section. 

The point to note here is this odd setting in AWS that allows *any* authenticated user to access the bucket. This means that you can have zero relationship with the bucket owner and yet gain access to their bucket as long as you're logged into your AWS account.

What this means is that anyone who is motivated enough to setup an AWS account can gain access to the bucket.

To bruteforce with an AWS account, we need the **AWS CLI tool**. This [page](https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3) has concise instructions to help you install and set it up. In the configuration process, when prompted for the default region, enter `ap-southeast-1` for Singapore.

Now, we are ready to start.

While we can easily write a script with Bash or Python (using [Boto3 SDK for AWS](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)) for this step, let's use [aws-s3-data-finder](https://github.com/Ucnt/aws-s3-data-finder/).

Using this tool has two advantages, it conveniently stores the buckets you've found previously, and also detects suspicious files. It can also add a prefix or postfix to your bucket names, but since we've already done that earlier, we are not using this feature.

`$ python3 find_data.py --name_list bucket_list.txt`

After this command is done, we look into the buckets-found.txt for the buckets we can probe further.

```
~/tools/aws-s3-data-finder/list$ head buckets-found.txt 
bucketname
think-innovation-s4fet3ch.s3.amazonaws.com
```

With the AWS CLI tool, it's straightforward to find the suspicious files.

```
$ aws s3 ls s3://think-innovation-s4fet3ch/
2020-11-17 10:59:54     273804 secret-files.zip

$ aws s3 cp s3://think-innovation-s4fet3ch/secret-files.zip secret-files.zip
download: s3://think-innovation-s4fet3ch/secret-files.zip to ./secret-files.zip
```

And we got the zipfile that was exfiltrated!

## Decrypting secret-files.zip

Alas, the zip file prompts us for a password. We tried the bucket name as the password but it was incorrect.

```
$ unzip secret-files.zip 
Archive:  secret-files.zip
[secret-files.zip] flag.txt password:
   skipping: flag.txt          incorrect password
   skipping: STACK the Flags Consent and Indemnity Form.docx  incorrect password
```

### Cracking with John The Ripper

Let's try to crack it. To crack it with John The Ripper, we need to extact the hash with zip2john.

```
$ zip2john secret-files.zip -o flag.txt > hash           
Using file flag.txt as only file to check
ver 1.0 efh 5455 efh 7875 secret-files.zip/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=62, decmplen=50, crc=AF6FEBEF
```

Unfortunately, we are not able to crack it with the rockyou wordlist.

```
$ sudo john -w /usr/share/wordlists/rockyou.txt --format=PKZIP hash                           
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8                                                            
Loaded 1 password hash (PKZIP [32/64])                                                     
Will run 4 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
0g 0:00:00:00 DONE (2020-12-05 10:19) 0g/s 177300p/s 177300c/s 177300C/s 123456..sss 
Session completed
```

### Known Plaintext Attack

As we consider our options, we notice that the zip file contains two files:

* flag.txt
* STACK the Flags Consent and Indemnity Form.docx  

Perhaps a [known-plaintext](https://www.youtube.com/watch?v=FNGTkq9P6U8) attack?

A known-plaintext attack is possible when we have not only the ciphertext, but also at least part of the plaintext.

In this case, if we can get hold of the unencrypted `STACK the Flags Consent and Indemnity Form.docx`, we stand a chance.

A little bit of OSINT work here. By googling the exact document name, [we found it on the CTF website](https://ctf.tech.gov.sg/files/STACK%20the%20Flags%20Consent%20and%20Indemnity%20Form.docx)

After downloading it, we zip it up into `plaintext.zip`

The go-to tool for known-plaintext attack on PKZIP is [pkcrack](https://github.com/keyunluo/pkcrack). We can use it for conducting a known plaintext attack on the zip file.

This is the command:

`pkcrack -C secret-files.zip -c 'STACK the Flags Consent and Indemnity Form.docx' -p 'STACK the Flags Consent and Indemnity Form.docx' -P knowntext.zip -d decrypted.zip `

Essentially, the command above tells pkcrack the following:

* We want to decrypt `secret-files.zip`.
* We have the plaintext of the file named `STACK the Flags Consent and Indemnity Form.docx` within the zip. This plaintext is stored in a file with the same name, and we have it zipped up in `plaintext.zip`. 
* Finally, we ask pkcrack to place the decrypted files into `decrypted.zip`.

This is the output of pkcrack:

```
Files read. Starting stage 1 on Sun Dec  6 00:01:59 2020 
Generating 1st generation of possible key2_273321 values...done. 
Found 4194304 possible key2-values.
Now we're trying to reduce these...
Lowest number: 997 values at offset 265129
<SNIP>
Lowest number: 94 values at offset 247097
Done. Left with 94 possible Values. bestOffset is 247097.
Stage 1 completed. Starting stage 2 on Sun Dec  6 00:02:44 2020
Ta-daaaaa! key0=f5af793b, key1=6d3ea7ba, key2=9b71082d
Probabilistic test succeeded for 26229 bytes.
Ta-daaaaa! key0=f5af793b, key1=6d3ea7ba, key2=9b71082d
Probabilistic test succeeded for 26229 bytes.
Ta-daaaaa! key0=f5af793b, key1=6d3ea7ba, key2=9b71082d
Probabilistic test succeeded for 26229 bytes.
Stage 2 completed. Starting zipdecrypt on Sun Dec  6 00:02:49 2020
Decrypting flag.txt (1918da1aa13583f007af7db7)... OK!
Decrypting STACK the Flags Consent and Indemnity Form.docx (336ab103cd78d1b9756efc91)... OK!
Finished on Sun Dec  6 00:02:49 2020
```

Success!

(Note: With the `-d` flag, it will decrypt the zip immediately after cracking the keys so we can view its contents. If you leave out the `-d` flag, pkcrack will proceed to figure out the password and this process will take a *very long* time. While figuring out the password here is not necessary, you might be interested in this ability if you suspect password reuse.)

## Solving the Challenge

Following the successful decryption, we are able to unzip the output file without supplying any password and retrieve the flag.

```
$ unzip decrypted.zip 
Archive:  decrypted.zip
 extracting: flag.txt                
replace STACK the Flags Consent and Indemnity Form.docx? [y]es, [n]o, [A]ll, [N]one, [r]ename: n
$ cat flag.txt 
govtech-csg{EnCrYpT!0n_D0e$_NoT_M3@n_Y0u_aR3_s4f3}
```
Encryption does not mean you are safe. Indeed.

Finally, to appreciate the challenge in context, let's try to relate it to a framework like the MITRE ATT&CK:

* [Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/)
* [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

*References*

* [A deep dive into AWS S3 access control](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/)
* [HackTricks - AWS S3](https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3)
* [aws s3 data finder](https://github.com/Ucnt/aws-s3-data-finder/)
* [pkcrack](https://github.com/keyunluo/pkcrack)
* [PKZip Plaintext Attack Using Pkcrack (Step by Step)](https://securiteam.com/tools/5np0c009pu/)
* [Plaintext Attack on Zip](https://x3ero0.tech/posts/plaintext_attack_on_zip_legacy_crypto/)
