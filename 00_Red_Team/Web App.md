



### WFUZZ - Web Application Fuzzing
- Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.
- useful for many things, but obviously can be used to fuzz username/password combos
	- for example, if you have a username, but no password or vice versa
	- Good stand in for burp suite Intruder
- `wfuzz -w <wordlist> -d '<string to send>' -b '<cookie>' <url>`
- `wfuzz -w cewl.out -d 'username=FUZZ&passwd=Curling2018!&option=com_login&task=login&return=aW5kZXgucGhw&0a85978390ff26d49aabe82a8d03ca1e=1' -b '99fb082d992a92668ce87e5540bd20fa=gbl1b1cg0sfo4ku5fjv2uioajp' http://10.129.58.186/admministrator/index.php`
- In the above example, I ran the initial FUZZ request through burp suite proxy to get both the login request string to send as well as the cookie. After getting these from Burp, I went to wfuzz to test my list of usernames (cewl.out) with the known password (Curling2018!)
- You can make it a little easier to identify items worth investigating with these options:
	- `-c` -> use color in results (green/red for OK/error)
	- `--hl <line number>` hide results of specified line number
		- good for when you know the line number you get for failed logins. You can hide all those so when you get a successful login, it is listed



### Can I modify the templates?
- ask yourself this whenever you get access to the web interface of a CMS like joomla, wordpress, etc
- templates normally contain php, which you can exploit to get code execution