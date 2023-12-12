---
tags:
  - johntheripper
  - hashcat
---
- [[#Hashcat|Hashcat]]
	- [[#Hashcat#General Usage|General Usage]]
	- [[#Hashcat#Rules|Rules]]
- [[#John the Ripper|John the Ripper]]
	- [[#John the Ripper#General Usage|General Usage]]

## Hashcat
### General Usage
- hashcat -m (hash mode) -O (optimized kernel) hashfile wordlist_file
```
hashcat -m 500 -O secret rockyou.txt
```

- example hashes - when you want to know what the hash looks like that belongs to the format you selected
```
hashcat -m 500 --example-hashes
```

### Rules
- https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule
- https://github.com/stealthsploit/OneRuleToRuleThemStill
```
hashcat -m 500 -O md5.txt \wordlists\rockyou.txt -r OneRuleToRuleThemStill.rule
```


## John the Ripper
### General Usage
- john hashfile --wordlist=wordlist_location
	- `john hash --wordlist=/usr/share/wordlists/rockyou.txt`

- can also convert things to john format for cracking
	- for example, cracking ssh using ssh2john https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py
	- input ssh file for conversion and output to a file
		- `python3 ssh2john.py rsa_private_key > john-ssh`
	- feed into john for cracking
		- `john john-ssh --wordlist=/usr/share/wordlists/rockyou.txt`
	- use this technique if you manage to steal an ssh key, but it prompts for passphrase
		- `Enter passphrase for key 'id_rsa':`
