# Offensive Security Practice

Hands-on offensive security practice by our team — CTF and TryHackMe writeups documenting our learning process, not just the wins.

This repository is where we explore CTFs and challenges from hacking education platforms (TryHackMe, HackTheBox, and others) as a team. We're here to practice, break things, get stuck, and write up not just *what* worked, but *why* — the reasoning behind every step, the dead ends we hit, and what we'd do differently next time.

## Who we are

A team of 3 practicing offensive security together.

## Why this repo exists

- **To build a habit of documentation** — writing up a solve forces you to actually understand it, not just remember the commands that worked
- **To learn from each other** — one of us might solve something the other two would've gotten stuck on; writeups let the whole team benefit from every solve
- **To track our growth over time** — looking back at early writeups vs. recent ones should show how our reasoning has matured
- **To build a portfolio** — a consistent, well-documented history of practice is worth more to future employers than a single flashy solve

## Repo structure

```
offensive-security-practice/
├── README.md              # you are here
├── TEMPLATE.md             # writeup template — copy this for every new challenge
├── tryhackme/
│   └── room-name/
│       ├── README.md       # the writeup
│       └── images/
├── htb/
│   └── box-name/
│       └── README.md
└── ctfs/
    └── event-name/
        └── challenge-name/
            └── README.md
```

One folder per room/box/challenge, so writeups don't collide and it's easy to browse by platform.

## How we write a writeup

Every writeup should cover, at minimum:

1. **What the challenge/room was about** (one or two sentences)
2. **Reconnaissance** — what we scanned/found and why it mattered
3. **The vulnerability or misconfiguration** — explained in plain terms, not just "ran this command"
4. **The exploitation steps** — commands, with reasoning for each
5. **What we learned** — the actual takeaway, phrased so future-us (or a teammate who wasn't there) understands the *pattern*, not just this one instance of it

See `TEMPLATE.md` for the full structure to copy.

## Ground rules

- **Reasoning over results.** A writeup that just pastes commands with no explanation doesn't help anyone learn — including future us.
- **Include dead ends.** What didn't work is often as instructive as what did.
- **Respect each room/platform's disclosure rules.** Some rooms ask you not to post flags or wait before publishing full writeups — check before pushing.
- **One folder per challenge, one writeup per folder.** Keeps things organized as the repo grows.
- **Review each other's writeups.** Open a PR instead of pushing straight to `main` — a second pair of eyes catches both mistakes and things worth explaining better.

## Current writeups

| Platform | Challenge | Topics | Contributor(s) |
|----------|-----------|--------|----------------|
| TryHackMe | Recon Pipeline | FTP RCE, cron abuse, PATH hijacking, sudo misconfig, lateral movement | |

*(Update this table as new writeups get added.)*