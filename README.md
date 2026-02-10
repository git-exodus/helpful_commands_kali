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
  

</details>

<details>
<summary style="cursor:pointer">dirbuster</summary>
  

</details>

<details>
<summary style="cursor:pointer">gobuster</summary>
  

</details>
