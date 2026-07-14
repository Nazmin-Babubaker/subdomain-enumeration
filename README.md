# Subdomain Enumeration Tool

A Python tool for discovering subdomains of a target domain using two complementary techniques: **active brute-forcing** against a wordlist, and **passive enumeration** via Certificate Transparency logs. Includes wildcard DNS detection, HTTP fingerprinting for ambiguous wildcard cases, multithreaded scanning, and a liveness check on all passive results.

## Features

- **Active brute-force** — resolves `word.domain.com` for every entry in a wordlist, multithreaded for speed
- **Passive enumeration** — pulls historical subdomains from Cert Spotter's Certificate Transparency API, no requests sent to the target
- **Wildcard DNS detection** — probes random junk subdomains before scanning to detect `*.domain.com` catch-all records and avoid false positives
- **HTTP fingerprinting fallback** — on wildcard-enabled domains, compares `(status_code, content_length)` signatures to catch cases where IP comparison alone can't distinguish real subdomains from wildcard noise
- **Liveness resolution** — passive results are re-resolved before being reported, since Certificate Transparency logs never expire and often include long-dead subdomains
- **Configurable CLI** — choose active-only, passive-only, or both; set thread count and wordlist path

## Installation

```bash
git clone https://github.com/Nazmin-Babubaker/subdomain-enumeration.git
cd subdomain-enumeration
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**requirements.txt**
```
dnspython
requests
```

## Usage

```bash
python3 main.py <domain> [options]
```

| Flag | Description | Default |
|---|---|---|
| `domain` | Target domain (positional, required) | — |
| `-w`, `--wordlist` | Path to wordlist file, used in active mode | `wordlist.txt` |
| `-t`, `--threads` | Number of concurrent threads | `30` |
| `--passive-only` | Run only passive enumeration (Cert Spotter) | off |
| `--active-only` | Run only active brute-force | off |
| `-h`, `--help` | Show help message | — |

`--passive-only` and `--active-only` are mutually exclusive. Omitting both runs active and passive together and merges the results.

### Examples

Run both active and passive enumeration:
```bash
python3 main.py example.com -w wordlist.txt -t 50
```

Passive-only — no requests sent to the target at all:
```bash
python3 main.py example.com --passive-only
```

Active-only brute-force with a larger wordlist:
```bash
python3 main.py example.com --active-only -w wordlists.txt -t 100
```

### Sample output

```
$ python3 main.py example.com -w wordlist.txt -t 50

[*] Checking example.com for wildcard DNS...
[*] No wildcard DNS detected. Skipping HTTP checks.

[*] Loaded 14 words. Starting brute-force (50 threads) against example.com...

[+] www.example.com -> ['93.184.216.34']
[+] api.example.com -> ['93.184.216.40']
[*] Brute-force done: 2 live subdomains found.

[*] Querying certspotter...
[*] Passive sources returned 47 unique candidate subdomains.
[*] Resolving 47 passive candidates to check liveness...
[*] 19 / 47 passive candidates are still live.

[*] === FINAL RESULTS ===
[*] Total unique live subdomains: 20

    api.example.com -> ['93.184.216.40']
    beta.example.com -> ['93.184.216.51']
    ...

[*] Total time: 6.84s
```

## How it works

1. **Wildcard check** — before brute-forcing, the tool resolves several random, near-guaranteed-not-to-exist subdomains. If any resolve, the domain has wildcard DNS, and every brute-force IP result is compared against this pool rather than trusted outright.
2. **Brute-force** — each wordlist entry is resolved concurrently across a thread pool. On wildcard-enabled domains, candidates whose IPs fall entirely inside the wildcard pool trigger a secondary HTTP fingerprint check against the wildcard's own HTTP signature; candidates that don't match are kept.
3. **Passive enumeration** — queries Cert Spotter's Certificate Transparency API for any hostname that has ever had an HTTPS certificate issued under the target domain.
4. **Liveness resolution** — every passive candidate is re-resolved via DNS, since certificate logs include long-decommissioned subdomains.
5. **Merge** — active and passive results are deduplicated into a single dictionary of confirmed-live subdomains.

## Limitations

- Uses standard A-record DNS resolution only; does not check AAAA (IPv6), CNAME chains, or other record types.
- Wildcard filtering compares IP sets and HTTP signatures — a real subdomain that happens to share both with the wildcard catch-all can still be filtered out as a false negative.
- Passive coverage depends entirely on Cert Spotter's index; subdomains that never had a certificate issued won't appear there.
- HTTP fingerprinting uses `(status_code, content_length)` only; it doesn't inspect response body content, so a wildcard whose error page varies in size per request could produce inconsistent fingerprints.

