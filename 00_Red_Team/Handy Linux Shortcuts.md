

## User
- find all objects owned by a user
	- `find / -user jimmy -ls 2>/dev/null`


## Network
- list listening TCP sockets (include port and process info)
	- `ss -lntp`
- start netcat listener on port
	- `nc -nvlp PORT`


## Apache
- enabled sites config data location
	- `/etc/apache2/sites-enabled`
	- this will give you servername, DocumentRoot, and IP:PORT info


## SSH Port Forwarding
- forward traffic for an internally accessible resource
- good for if something is hosted on a machine, but it is only hosted internally and not accessible from outside the network
	- `ssh -R 1337:127.0.0.1:52946 root@10.10.14.2`
	- The command above creates a remote SSH tunnel, which forwards all connections from port 1337 on our host to port 52946 on the box. Make sure that the SSH server is running and permits root login. The application can now be accessed by browsing to http://127.0.0.1:1337
	- `ssh -R new_port:host_ip:current_hosted_port local_root@attacker_ip`