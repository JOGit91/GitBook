---
tags:
  - p5985
  - evil-winrm
  - cme-winrm
---
## Enumeration
- cme to enumerate and test user/pass connection for winrm auth
	- `cme winrm 10.129.96.157 -u users.txt -p passwords.txt`

## Lateral Movement
- evil-winrm
	- `evil-winrm -i 10.129.96.157 -u chase -p "Q4)sJu\Y8qz*A3?d"`
