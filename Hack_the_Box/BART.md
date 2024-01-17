Windows | Medium

- nmap scan
```nmap_results FOLD
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-16 22:54 GMT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating Ping Scan at 22:54
Scanning 10.129.96.185 [2 ports]
Completed Ping Scan at 22:54, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:54
Completed Parallel DNS resolution of 1 host. at 22:54, 0.00s elapsed
Initiating Connect Scan at 22:54
Scanning 10.129.96.185 [1000 ports]
Discovered open port 80/tcp on 10.129.96.185
Completed Connect Scan at 22:54, 7.20s elapsed (1000 total ports)
Initiating Service scan at 22:54
Scanning 1 service on 10.129.96.185
Completed Service scan at 22:54, 6.97s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.96.185.
Initiating NSE at 22:54
Completed NSE at 22:54, 5.08s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.28s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Nmap scan report for 10.129.96.185
Host is up (0.072s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Did not follow redirect to http://forum.bart.htb/
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: 50465238F8A85D0732CBCC8EB04920AA
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Initiating NSE at 22:54
Completed NSE at 22:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.99 seconds
```
- only seeing one open port at 80, started with just trying to browse to the site
- was met with a "this site can't be reached" although some DNS is happening because the address changes to "forum.bart.htb"
- I remember doing this trick a lot when just starting out, but I used vim to edit the /etc/hosts file to set forum.bart.htb to the target ip address provided by htb (10.129.96.185)
- now, when I browse to the site via the IP address, all resolves and the site opens
- had some issues with gobuster (seemingly, I'm not the only one frustrated with its documentation/implementation). Trying feroxbuster
- very straightforward, works well with `feroxbuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://forum.bart.htb`
	- dir enumeration did not provide anything too interesting
```feroxbuster_results FOLD
200      GET       52l      137w     1112c http://forum.bart.htb/webste/my_style_id-35.css
200      GET       53l      110w     1315c http://forum.bart.htb/webste/front-flex.css
200      GET      254l     1591w   116217c http://forum.bart.htb/webste/ipad-606764_1280-550x365.jpg
200      GET      188l     1367w   105643c http://forum.bart.htb/webste/2.jpg
200      GET     3374l     7680w    73662c http://forum.bart.htb/webste/style.css
200      GET      142l      776w    60591c http://forum.bart.htb/webste/macbook-336704_1280-550x367.jpg
200      GET        8l      233w    16628c http://forum.bart.htb/webste/bootstrap.css
200      GET        6l       13w      154c http://forum.bart.htb/webste/sow-image-default-813df796d9b1.css
200      GET      236l     1355w   103689c http://forum.bart.htb/webste/1_002.jpg
200      GET     1127l     5713w   400182c http://forum.bart.htb/webste/header.jpg
200      GET      199l     1273w    91446c http://forum.bart.htb/webste/3.jpg
200      GET      173l     1045w    78865c http://forum.bart.htb/webste/imac-606765_1280-550x365.jpg
200      GET      216l      736w     9821c http://forum.bart.htb/webste/css.css
200      GET        2l      281w    10056c http://forum.bart.htb/webste/jquery-migrate.js
200      GET        6l     1435w    97184c http://forum.bart.htb/webste/jquery.js
200      GET      151l      757w    57593c http://forum.bart.htb/webste/emp5.jpg
200      GET      537l     3381w   270381c http://forum.bart.htb/webste/iphone-550x363.png
200      GET      878l     5333w   478480c http://forum.bart.htb/webste/1.jpg
200      GET      107l      189w     1606c http://forum.bart.htb/webste/styles.css
200      GET      273l     1715w   130663c http://forum.bart.htb/webste/4.jpg
200      GET        4l       66w    31000c http://forum.bart.htb/webste/font-awesome.css
200      GET      549l     2412w    35529c http://forum.bart.htb/
```
- I'm not sure this is a clue or anything but a lot of the pages I'm manually browsing to have a pound sign before the page (like http://forum.bart.htb/#pg-8-2). I wonder if I can tell feroxbuster to include that and then rerun?
	- ran across `ffuf` and found that that might be able to include the # using `ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://forum.bart.htb/#FUZZ`
	- this went crazy on me due to no filters. Everything was coming back with result 200. I filtered out response by size using -fs `ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://forum.bart.htb/#FUZZ -fs 35529`
- wappalyzer shows the following tech in use (of interest): 
	- IIS 10.0
	- PHP
	- MySQL
- searched around for vulnerabilities in iis 10, not much found.
- seeing the TRACE method enabled kinda makes it stick out, many people are saying this should definitely be disabled due to the security risk. Potential exposure of data. Maybe some sort of cross site tracing (XST) attack?
- manually browsing the site, I don't see anything of much interest. Nowhere to drop files or anything obvious. Not even a customer/employee/administrator login.
- inspecting source of the site, I found this comment: 
	- `<!-- Adding other employees breaks the CSS, I will fix it later.`
- Got a little stuck here, so I checked some walkthroughs, but only far enough to move me to the next step. My problem was the hosts file edit I made. I made the right move with adding forum.bart.htb, but I should've also added just bart.htb. The whole /etc/hosts file modification should've looked like this: `10.129.96.185 bart.htb forum.bart.htb`
- making this change to my hosts file allowed the directory enumeration to pick up on the stuff I missed before, I did the same as before with ffuf, but filtered on size 158607 (this site is configured to give 200s, I'm looking for other results). I could've achieved similar results by filtering status and excluding 200s. 
- Either way, ffuf revealed `forum` (we knew this one) and `monitor`
- `http://bart.htb/monitor/` this gets me a login page for some kind of server monitor
- Unfortunately, in one of the walkthroughs, I saw the password for the monitor site. However, I did try to emulate possible steps on how I got there. 
- I used cewl to generate a wordlist from the site
- Loaded the monitor site in burpsuite and captured the login with proxy, sent that to intruder
- selected username and pass fields, used clusterbomb attack using the wordlists I generated from cewl. I also used the firstnames of the users in the employee section of the site to generate my user field list. (Harvey, Robert, Samantha, Daniel)
- yep, just as expected, I was able to identify the successful login by the status (302) and the size difference between all the failed requests.
- **User and pass combo for monitor is `Harvey///potter`**
- after logging in, a lot of the webpages for monitor.bart.htb were failing to load. I fixed this by adding monitor.bart.htb to the /etc/hosts file like I did with the other names.
- Server monitor site has one server - http://internal-01.bart.htb/
- Added http://internal-01.bart.htb/ to my /etc/hosts file just like the others
- browsing to this gets my to an Internal Chat Login form
- `Harvey///potter` does not work here
- burp is very slow, so I went looking to see if ffuf can do brute forcing. it can! https://zerodayhacker.com/clusterbomb-or-pitchfork/
- I wanted to mention here too that I tried a fresh feroxbuster on the internal-01 address, some things were turned up, and I didn't let it go all the way. If I get stuck later, I may return to this. 
- I think next step is to create a username list and find a password list to try and brute force my way into this internal chat log. 


## Noteworthy Items
### Creds
- `http://bart.htb/monitor/` > `Harvey/potter`
- 