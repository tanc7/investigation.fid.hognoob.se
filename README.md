### INVESTIGATION - MASS WEB APPLICATION ATTACK TARGETING AMAZON LIGHTSAIL WEBSERVER NETBLOCKS

Variant: Win.Exploit.EQGRP-6322722-0 and generic multi-platform hydra.php webshell
Aggrieved Party: "LULLC" owned by a "CTL"
Motives of attackers: Cryptomining campaigns, banking trojans, Windows botnets, Remote Desktop and VNC servers

# Notes:

There may be multiple sub-factions with different objectives using the same ThinkPHP Remote Code Execution exploit. Each group has a different role, and their own separate web-delivery servers related to the hognoob.se

The one that has affected me is a Windows variant that failed to land. It however has similar forensic traits

1. UPX packed binary
2. Calls back to same fib.hognoob.se domain to download stagers
3. Installs persistence modules
4. May install a GUI remote-control desktop server to allow the attackers to log-in and control victim's machine remotely
5. Downloads about 26 to 54 different stagers that reconstitute into the malware
6. Is primarily written in Java, JSP pages, Powershell, cmd.exe, and PHP and uses the webclient on Windows to download stagers


### INCIDENT ###

Notes:

On March 25/26th, a visitor to my website delivered a web application attack. None of the commands he issued ever worked. Like he was basically going off a list of webservers and just casting a fishing net in his hacking campaign. He wrongly assumed. That my server was Windows, and running ThinkPHP. 

![](https://raw.githubusercontent.com/tanc7/investigation.fid.hognoob.se/master/pics/Screenshot%20from%202019-03-30%2010-18-54.png)

The attacker doesn't seem to know that I run Ubuntu. You see, on my website, I installed my own backdoor that is encrypted and obfuscated and requires a specific client to connect with. My password to interact with that backdoor is longer than 12 characters. It is designed as a "insurance policy" in the event that I was completely compromised and locked out of my own server.

The attacker used my internal website backdoor index.php webshell unsuccessfully (he doesn't know my password or have my client) to invoke PHP commands with a not-installed ThinkPHP framework to download cmd.exe for Windows. It returned HTTP code 400 (failure).


https://securitynews.sonicwall.com/xmlpost/thinkphp-remote-code-execution-rce-bug-is-actively-being-exploited/

But had it worked, the rest of the command would have..

1. Used the cmd.exe RFI binary to run a powershell command
2. Which then downloads download.exe stager from http://fib.hognoob.se/download.exe
3. Renames it to C:/Windows/Temp/{randomstring}.exe

A second attack string repeats the same ThinkPHP exploit to download 

1. A webshell into the webroot directory called hydra.php
2. The attacker failed again due to my directory permissions and htaccess policies


https://www.alibabacloud.com/blog/threat-alert-multiple-cryptocurrency-miner-botnets-start-to-exploit-the-new-thinkphp-vulnerability_594369

This guy basically failed twice ONLY BY A HAIR. Had my document/webroot/webapp directory had ThinkPHP installed (I do not. I have basic PHP7 and it does not enable anything else except JavaScript, Bootstrap, CSS, and HTML) with bad file/directory permissions with PHP support enabled, the attack may have worked.

Before I stopped maintaining my website I switched it over to a static site generator called Pelican. Which reduced my attack surface even further. The only source of frameworks and scripting languages for an attacker is my webroot directory.

# After incident report, injuries, and damages:

I believe I am fine and uninjured.

I am not certain if I am compromised or not. But the signs do point that the malware has failed to "land" a shell due to the HTTP 400 response codes to both injection attempts.

Currently I am performing a remote backup of all system logs and monitoring the nginx and apache access and error logs and monitoring web activityon the server. 

So far, outside of some very alarming activity on the logs, I see no further evidence that the server has been actually compromised. It is guarded by multiple firewalls, a very aggressive Intrusive Prevention System that bans attackers after 5 failed login attempts on my backend ports, and it uses static-site generators to create static HTML webpages that do not run web application code. Furthermore it is completely locked down against layer 3/4 volumetric DDoS attacks and little for a layer 7 attack to affect aside from HTTP, which will be met with challenge pages that are always on.

In the one and half years of running my webserver, it has auto-banned 1,923 attackers that targeted my SSH port in brute-forcing attempts.

### SUSPECTED HOSTS


195.128.126.241 Possible C2. Remote Desktop port discovered open after FIN scan. Multiple firewalled ports appear to receive and issue commands and payloads to the botnet
113.108.153.25 IP address of possible Chinese cybercafe* where command was issued to download stager from fib.hognoob.se
http://fib.hognoob.se/download.exe Windows stager payload
hognoob.se domain with dynamic DNS. Over 5 IP's were registered and hosting payloads in root directory

There are much more hosts related to that domain hognoob.se because the attackers are constantly shifting their origin IP every couple of days during their mass cyber attack campaign.

*A assumption. The initial attack strings, a GET request originated from this IP. It could be anything with a Chinese public IP. Even a VPN. It's a Chinese ISP.

![](https://raw.githubusercontent.com/tanc7/investigation.fid.hognoob.se/master/pics/Screenshot%20from%202019-03-30%2011-32-39.png)

# URL to original report of ThinkPHP to cmd.exe to Powershell to Cryptominer/Windows Botnet Malware
# That targets webpages with index.php discovered in root directory(or simply brutes a list regardless of whether or not they even properly enumerated the webserver and OS)

https://www.hybrid-analysis.com/sample/c57371c9cd07cc91acad61f313991658979e9cd90ef76c7da1e4782c6886eba9?environmentId=100

`?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id` Command string sent by attacker, actually as a GET request and not a POST or PUT. It requires the victim to have ThinkPHP installed with a webapp directory called think\app in your documentroot or webroot. It is used as https://domain.com/index.php?s=$payloadstring

### DISCOVERED A HANDLE ON POSSIBLE C2 SERVER ###

A nmap FIN scan on one of the linked IP addresses to a dynamic analysis of the download.exe binary from hybrid-analysis.com revealed a hidden remote desktop port 3386. We also discovered a possible handle from the SSL certificate's CN. 

3389/tcp  open          ssl/ms-wbt-server? tcp-response
| ssl-cert: Subject: commonName=stephov_107805
| Issuer: commonName=stephov_107805
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-03-24T21:57:29
| Not valid after:  2019-09-23T21:57:29
| MD5:   6052 491c 43c4 61e5 abb3 3b75 db9a b33f
| SHA-1: fa39 afd3 5aa0 a937 220b 6dbf 5906 2e58 5e8a 99c1
| -----BEGIN CERTIFICATE-----
| MIIC/DCCAeSgAwIBAgIQIi8wPjcloa5GUAzWNMDROTANBgkqhkiG9w0BAQsFADAn
| MSUwIwYDVQQDHhwAcwB0AGUAcABoAG8AdgBfADEAMAA3ADgAMAA1MB4XDTE5MDMy
| NDIxNTcyOVoXDTE5MDkyMzIxNTcyOVowJzElMCMGA1UEAx4cAHMAdABlAHAAaABv
| AHYAXwAxADAANwA4ADAANTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AJnPvKyC7AABk5LgGDOeCP0MK5cI5MhuM2sjD09vxFr+sVwph9MIA3baw6SIEbZy
| OHE4TARj8yiBxFaxjR8/j2WxKWzUsvLgp2Gd0ybnmx/5C6nDM2W5nprMN73ByY1F
| luvA4tDNo4bRJ92jS5XvEUQDxzXAWFBdmpVelVLR42Z+x9m0zBfUSV8TYTsY2qqk
| hKvz2beSWUTdLr+Qki+409ZbTqGzJoGM89x//nrEx8lPu6uSvBU0nh/h359LEJhY
| h1bTjNb5cEHIMpCWu/xOmlQQ9cRY2AV69ERUyeZPe7ZL7zrosdQhLRl36QyxYaul
| xYK6YQwDJr9nl2JA/E+7q4ECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQCWZUeKKJDRvRQSbxuJnaBZ
| /PSGaQpoSfsRYe4CAGuqgGvuj+FkQgd4eOCnmTeSAnIm5Gapr5+/TNxzVOZQDkXt
| 4oOcCkHjxEFctu6g67K/c/jm/HcYAjvdd+MaqCJ1aeLYrqjTBraIU7twpUgEr0+s
| rtu+TghQwzeLiiLDytoacGJweZ0yO1g8Emw3k3/m3d19Ey+CCND+820ytT/RzALC
| NPAhLFEuLy3CIz8Il+eD0tvU1IU0OtloynLBb9tkGTafrXJqbInmH57QuQhquF48
| WlUZYGInGyogCDBkQvRwurYVUgpeCNxexLmRhU4vwexMF0Zimg7qK342ArzMgyKi
|_-----END CERTIFICATE-----

This host is one of the older IP's 195.128.126.241 associated with the hognoob.se domain according to hybrid-analysis.com as it contacted to download the download.exe stager. It has since, been under a new domain in less than two weeks after initial discover on malware research websites. It changed from hognoob.se to energoresurs.net

49157/tcp open|filtered tcpwrapped         no-response
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Timing level 5 (Insane) used
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.70%E=4%D=3/30%OT=3389%CT=%CU=%PV=N%G=N%TM=5CA03886%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=105%TI=I%TS=7)
OPS(O1=M5B4NW0ST11%O2=M5B4NW0ST11%O3=M5B4NW0NNT11%O4=M5B4NW0ST11%O5=M5B4NW0ST11%O6=M5B4ST11)
WIN(W1=FA00%W2=FA00%W3=FA00%W4=FA00%W5=FA00%W6=FA00)
ECN(R=Y%DF=Y%TG=80%W=FA00%O=M5B4NW0NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=N)

Uptime guess: 1.094 days (since Fri Mar 29 18:33:34 2019)
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Randomized

TRACEROUTE
HOP RTT       ADDRESS
1   102.07 ms mail.energoresurs.net (195.128.126.241)


