# Checkmate — TryHackMe Writeup

- **Room theme:** Password security assessment / credential attacks
- **Target:** `10.49.175.15`
- **Category:** Password Cracking / OSINT / Web
- **Difficulty:** Easy

## TL;DR

Marco Bianchi, a sysadmin under deadline pressure, reused weak and predictable passwords across four internal services (a firewall console, an employee portal, a social platform, and SSH). By combining default credentials, website-scraped keywords, OSINT-based personal info, and a password pattern Marco accidentally revealed on his own social profile, we escalated through 5 levels of credential attacks to fully compromise his authentication practices.

## Recon

```bash
nmap -sV -p- -T4 -sC 10.49.175.15
```

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH 9.6p1) | Final target — SSH access with Marco's credentials |
| 5000 | HTTP (Werkzeug) | "Operation Checkmate" — landing page |
| 5001 | HTTP (Werkzeug) | "FirewallOS" — firewall console login |
| 5002 | HTTP (Werkzeug) | "Engineering Careers" — employee portal (jobs.thm) |
| 5003 | HTTP (Werkzeug) | "social.thm" — social platform login |

All four web services run on Werkzeug (Flask dev server) — a good sign these are custom-built lab apps rather than off-the-shelf software, so behavior/hints are intentional.

---

## Level 1 — FirewallOS Default Credentials (port 5001)

**Hint given:** feel out the default credentials of the firewall console.

**Approach:** Tried common default admin/guest credential pairs against the FirewallOS login on port 5001.

**Result:** Logged in using:
```
username: guest
password: 12345
```
A classic default-credential oversight — never changed from the factory/example login.

**Lesson:** Always test default vendor/product credentials first on any admin panel — many products ship with well-known defaults (`admin:admin`, `guest:12345`, etc.) that get left unchanged under time pressure.

---

## Level 2 — Employee Portal, Company Keywords (port 5002)

**Hint given:** Marco used "common company keywords" as passwords on the jobs.thm employee login.

**Approach — scrape the site itself for its own branding keywords:**
```bash
cewl http://10.49.175.15:5002/ -w wordlist.txt -m 4
```
The careers page displayed its own keyword badges directly in the HTML:
```
innovation, excellence, security, digital, cloud, future, talent
```

**Brute-force the login form:**
```bash
hydra -l marco -P wordlist.txt 10.49.175.15 -s 5002 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
```

**Result:** One of the 7 keywords matched directly as the plaintext password — no capitalization or suffix needed at this stage.

**Lesson:** A company's own marketing copy is often a direct source for "company keyword" style weak passwords — `cewl` turns that copy into a targeted wordlist in seconds, far more effective than blind dictionary attacks.

---

## Level 3 — Social Platform, Personal OSINT (port 5003)

**Hint given:** derive Marco's password from his personal info, visible on social.thm.

**Approach:** Gathered Marco's first name, surname, birthday, and nickname from his social.thm profile, then used `cupp` (Common User Passwords Profiler) to generate a personalized wordlist from that data:
```bash
cupp -i
# entered: Marco, Bianchi, nickname, birthdate
```

**Brute-force:**
```bash
hydra -l marco -P wordlist.txt 10.49.175.15 -s 5003 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
```

**Result:** A personal-info-based password (name/birthday combination) cracked the login.

**Lesson:** Personal details posted publicly on social media (even seemingly harmless ones like a birthday or nickname) are a direct pipeline into password-guessing tools. This is exactly why `cupp`-style profiling is a real technique red teamers use during password-spray prep.

---

## Level 4 — Reversing a Hashed Filename (port 5003)

**Hint given:** Marco's uploaded profile picture is renamed to `SHA256(original_filename).png` by the platform. Find the original filename.

**Approach:**
1. Right-clicked the profile image on social.thm and inspected the image filename directly, revealing the pre-hash name: `profile_image.png` (found via browser inspection rather than brute-force, once we knew what to look for).
2. Marco had also posted a status on social.thm hinting at his password construction rule:
   > "My tip for strong password: I take a company keyword, capitalize it, then append the year like 2024 or any other number and an exclamation mark."

**What we tried first (didn't work):** Assumed this password-construction rule also applied to the filename, and generated candidates like `Excellence2024!.png` using the Level 2 keyword list. Hashed each candidate and compared against the target hash — no match, across an extensive generated wordlist (~2,000–5,000 variants).

**What actually worked:** Since the filename pattern guess failed, we instead ran the target hash through `John the Ripper` using **rockyou.txt** — a generic breached-password wordlist — rather than a custom-built one:
```bash
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
john --format=raw-sha256 hash_to_crack.txt --show
```
This cracked it.

**Lesson (important one):** Not every hash on a box is protecting something built from the room's internal "lore" (keywords, personal info, a stated pattern). Sometimes a hash is just a hash, and the fastest path is a generic, massive wordlist like `rockyou.txt` — especially for a filename someone might have picked casually, unrelated to their password habits. **Don't force a fancy targeted wordlist onto every hash you find — try the boring, generic option too, especially when the targeted approach isn't landing.**

---

## Level 5 — SSH Brute-Force Using Marco's Own Password Rule

**Hint given:** Marco revealed his password *pattern* (not the password itself) via his social.thm status. Use that pattern — not personal info, not the filename hash — to brute-force SSH.

**Approach:** This is where the Level 4 status hint actually paid off — its real purpose was for **this** level, not the filename puzzle:
```
Capitalize(company keyword) + year/number + "!"
```

Generated a targeted wordlist applying that exact rule to all known company keywords (`innovation`, `excellence`, `security`, `digital`, `cloud`, `future`, `talent`), combined with a range of years and common numbers:
```
Innovation2024!
Excellence2025!
Security99!
Cloud2020!
...
```

**Brute-force SSH:**
```bash
hydra -l marco -P ssh_wordlist.txt -t 4 ssh://10.49.175.15
```

**Result:** SSH access obtained as `marco` using a password matching the stated construction rule.

**Lesson:** A password *pattern* leaked (even without the plaintext itself) is often just as dangerous as the password leaking directly — once you know someone's personal "formula," you can regenerate their entire password space for every other service they use it on. This is also a great real-world argument against publicly describing your own password habits, even as a "security tip."

---

## Full Command Reference

```bash
# Recon
nmap -sV -p- -T4 -sC 10.49.175.15

# Level 1 — FirewallOS default creds
# (manual login attempt) guest / 12345 @ port 5001

# Level 2 — Employee portal, company keywords
cewl http://10.49.175.15:5002/ -w wordlist.txt -m 4
hydra -l marco -P wordlist.txt 10.49.175.15 -s 5002 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# Level 3 — Social platform, personal OSINT
cupp -i
hydra -l marco -P wordlist.txt 10.49.175.15 -s 5003 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# Level 4 — Hashed filename (cracked via rockyou, not the stated pattern)
john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
john --format=raw-sha256 hash_to_crack.txt --show

# Level 5 — SSH via Marco's stated password pattern
# generate wordlist: Capitalize(keyword) + number + "!"
hydra -l marco -P ssh_wordlist.txt -t 4 ssh://10.49.175.15
ssh marco@10.49.175.15
```

---

## Key Takeaways

1. **Always try default credentials first** on any admin console — it costs nothing and frequently works under real-world time pressure, exactly as simulated here.
2. **A website's own marketing copy can become its own attack wordlist.** `cewl` turns "About us" pages and career listings into targeted password guesses in seconds.
3. **Public personal information is a direct password-cracking input**, not just a privacy concern in the abstract. Tools like `cupp` formalize this into a repeatable OSINT → wordlist pipeline.
4. **Don't assume every hash follows the "clever" pattern the room is teaching you.** We spent significant effort trying to apply Marco's stated password rule to the filename hash before realizing a generic wordlist (`rockyou.txt`) was the actual intended (or at least effective) solution. Generic wordlists remain valuable even in puzzles built around custom patterns.
5. **A leaked password *pattern* is nearly as dangerous as a leaked password.** Once Marco's construction rule was known, it could be replayed against an entirely different service (SSH) with a freshly generated, tightly-targeted wordlist — demonstrating exactly why password reuse *and* pattern reuse are both real organizational risks.
6. **Read hints carefully for which stage they actually apply to.** The password-pattern status update was posted during the Level 4 filename puzzle, but was actually the key for Level 5 — a reminder that not every clue found in one place is meant to solve the puzzle you find it in.

7. **`cupp` isn't limited to "personal info you already know" — it can also work from data pulled straight off a webpage.** Names, dates, nicknames, or keywords scraped from a company site (via `cewl`) can be fed into `cupp` (or combined with it) to generate a wordlist, the same way we did manually with company keywords — `cupp` just formalizes and extends that same OSINT-to-wordlist process.

## Defensive Recommendation: What a Strong Password Should Actually Look Like

Every password cracked in this lab failed because it was short, predictable, and built from guessable personal or company information. A genuinely strong password should combine:

- **Length ≥ 12 characters** (8 is now considered a minimum, not a target — longer is significantly harder to brute-force)
- **Mixed case** — both uppercase and lowercase letters
- **Numbers** — not just appended at the end (e.g. not just `Password2024`), ideally mixed throughout
- **Special characters** — `!`, `@`, `#`, `$`, etc., again not just as a single trailing character
- **No dictionary words, company names, or personal info** — even "clever" substitutions (like `P@ssw0rd`) are well-known to cracking tools and wordlists
- **Unique per service** — Marco's core failure wasn't just weak passwords, it was **reusing the same pattern** across every service, so cracking one exposed the logic behind all of them
- **Consider a password manager + passphrase** instead of a memorized pattern — a long, random passphrase (e.g. four unrelated words) is both stronger and easier to remember than a "formula" that, once discovered, becomes predictable everywhere else

The core lesson from Marco's case: a *memorable rule* for generating passwords is exactly what makes them crackable once an attacker learns the rule — which is precisely what happened here via his own social media post.
