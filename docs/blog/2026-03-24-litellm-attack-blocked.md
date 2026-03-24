# How sloppy-joe blocks the LiteLLM supply chain attack

**March 24, 2026**

Today, [TeamPCP compromised LiteLLM](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html) — a Python package with 97 million monthly downloads that routes API calls to 100+ LLM providers. Versions 1.82.7 and 1.82.8 were published to PyPI containing a credential stealer, a Kubernetes lateral movement toolkit, and a persistent systemd backdoor.

The attack harvested SSH keys, cloud credentials (AWS, GCP, Azure), Kubernetes secrets, cryptocurrency wallets, `.env` files, and LLM API keys. Everything was encrypted and exfiltrated to an attacker-controlled domain. The malicious versions were live on PyPI for approximately 3 hours before being yanked.

**If you run `sloppy-joe check` in CI, this attack is blocked before `pip install` ever runs.**

## How the attack worked

TeamPCP stole the LiteLLM maintainer's PyPI publishing credentials through a [prior compromise of Trivy](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/) — the popular container security scanner. LiteLLM's CI ran Trivy, Trivy was backdoored, and the backdoor harvested LiteLLM's `PYPI_PUBLISH_PASSWORD`. The attacker then published two poisoned versions directly to PyPI under the real maintainer's account.

Version 1.82.7 hid the payload in `proxy_server.py`, executing on import. Version 1.82.8 used a `.pth` file — a Python mechanism that executes code on *every interpreter startup*, before any code imports the package.

## Why sloppy-joe catches it

sloppy-joe runs **before** `pip install`. It reads your `requirements.txt` and checks each dependency against multiple signals without downloading any packages.

### Defense 1: Version age gate (blocks on hour zero)

sloppy-joe's default configuration blocks any dependency version published less than 72 hours ago:

```
ERROR litellm [metadata/version-age]
      Version '1.82.8' of 'litellm' was published 0 hours ago (minimum: 72 hours).
      New versions need time for the community and security scanners to review them.
 Fix: Wait until the version is at least 72 hours old, or pin to an older version.
```

The compromised versions were discovered and yanked within 3 hours. A 72-hour gate means they would **never** have been installed in any CI pipeline running sloppy-joe.

This defense requires no knowledge of the attack. No advisory database entry. No package inspection. It works purely on the principle that new versions of packages should have time for the community to review them before they land in production CI.

### Defense 2: Known vulnerability check (blocks after discovery)

Once the community reported the attack, the [OSV database](https://osv.dev) published `PYSEC-2026-2`. sloppy-joe queries OSV for every dependency:

```
ERROR litellm [malicious/known-vulnerability]
      'litellm' has known security vulnerabilities in the OSV database.
      Vulnerability IDs: PYSEC-2026-2
 Fix: Remove 'litellm' or update to a non-vulnerable version.
```

This catches the attack even after the version age window expires — the OSV entry is permanent.

## What about other tools?

| Tool | Catches it? | How | When |
|------|-------------|-----|------|
| **sloppy-joe** | Yes | Version age gate + OSV | Before install (hour 0) |
| **Socket.dev** | Yes | Static analysis of malicious code | After package download |
| **GuardDog** | Probably | Semgrep rules for obfuscation patterns | After package download |
| **pip-audit** | Yes, later | OSV query | After advisory published (hours) |
| **Snyk** | Yes, later | Vulnerability DB | After DB updated (hours) |
| **Phantom Guard** | No | Only detects typosquats | N/A — this is the real package |
| **antislopsquat** | No | Only checks if package exists | N/A — package exists |

The critical difference: sloppy-joe and the version age gate work **before the package is downloaded**. Tools that inspect package contents (Socket, GuardDog) require the package to be on disk — and in this attack, the `.pth` file executes the moment the package is installed, before any scanner can inspect it.

## The version age gate is the strongest defense against maintainer compromise

Typosquatting detection, code analysis, and vulnerability databases are all important. But for the class of attack where a legitimate package's maintainer credentials are stolen and a malicious version is published:

- **Typosquatting detection** doesn't help — it's the real package name
- **Code analysis** requires downloading the package — the `.pth` trick means the malware runs on install
- **Vulnerability databases** need someone to discover and report the attack first

The version age gate is the only defense that works at hour zero, requires no package download, and catches the attack regardless of how the malicious code is delivered.

## Try it

```bash
cargo install sloppy-joe
sloppy-joe check
```

The default `min_version_age_hours` is 72 (3 days). For maximum protection, set it to 168 (7 days) in your [config](https://github.com/brennhill/sloppy-joe/blob/main/CONFIG.md).

## Timeline

- **March 19**: TeamPCP compromises Trivy, harvests CI secrets from projects that run Trivy
- **March 24, ~10:52 UTC**: litellm 1.82.8 published to PyPI with credential stealer
- **March 24, ~13:00 UTC**: Community discovers the attack, PyPI yanks versions
- **March 24**: OSV publishes PYSEC-2026-2
- **sloppy-joe users**: Never affected — version age gate blocked both versions from hour 0
