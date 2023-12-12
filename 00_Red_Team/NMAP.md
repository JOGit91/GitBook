- I think this method here is scanning a host for all open ports, then feeding that into the command below.
`ports=$(nmap -p- --min-rate=1000 -T4 10.10.10.178 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`
`nmap -p$ports -sC -sV 10.10.10.178`