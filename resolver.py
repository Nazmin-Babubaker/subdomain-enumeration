# step4c.py
import dns.resolver
import requests
import random
import string

def resolve(hostname: str):
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return [str(a) for a in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.exception.Timeout:
        return None

def get_http_signature(hostname: str, timeout: int = 5):
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{hostname}", timeout=timeout, allow_redirects=False)
            return (resp.status_code, len(resp.content))
        except requests.exceptions.RequestException:
            continue
    return None

def random_subdomain_label(length: int = 15) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_wildcard(domain: str, attempts: int = 3):
    
    wildcard_ips = set()
    for _ in range(attempts):
        junk_host = f"{random_subdomain_label()}.{domain}"
        ips = resolve(junk_host)
        if ips:
            wildcard_ips.update(ips)
    return wildcard_ips

def get_wildcard_http_signature(domain: str, attempts: int = 3):
   
    signatures = set()
    for _ in range(attempts):
        junk_host = f"{random_subdomain_label()}.{domain}"
        sig = get_http_signature(junk_host)
        if sig:
            signatures.add(sig)
    return signatures

def load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

def brute_force(domain: str, wordlist_path: str):
    words = load_wordlist(wordlist_path)

    print(f"[*] Checking {domain} for wildcard DNS...")
    wildcard_ips = check_wildcard(domain)

    wildcard_sigs = set()
    if wildcard_ips:
        print(f"[!] Wildcard DNS detected. Pool of IPs: {wildcard_ips}")
        print(f"[*] Fetching HTTP fingerprint of wildcard responses...")
        wildcard_sigs = get_wildcard_http_signature(domain)
        print(f"[!] Wildcard HTTP fingerprint(s): {wildcard_sigs}")
        print(f"[!] Only candidates whose HTTP signature DIFFERS from these will be kept\n")
    else:
        print(f"[*] No wildcard DNS detected. Trusting DNS resolution alone, skipping HTTP checks.\n")

    print(f"[*] Loaded {len(words)} words. Starting brute-force against {domain}...\n")

    found = {}
    filtered_count = 0

    for word in words:
        candidate = f"{word}.{domain}"
        ips = resolve(candidate)

        if ips is None:
            print(f"[-] {candidate}")
            continue

        if not wildcard_ips:
            print(f"[+] {candidate} -> {ips}")
            found[candidate] = {"ips": ips}
            continue

        sig = get_http_signature(candidate)

        if sig and sig in wildcard_sigs:
            print(f"[~] {candidate} -> {ips}  HTTP {sig} (filtered: matches wildcard fingerprint)")
            filtered_count += 1
            continue

        print(f"[+] {candidate} -> {ips}  HTTP {sig}")
        found[candidate] = {"ips": ips, "http_signature": sig}

    print(f"\n[*] Done. Found {len(found)} real subdomains ({filtered_count} filtered as wildcard noise).")
    return found

if __name__ == "__main__":
    results = brute_force("google.com", "wordlist.txt")
    print()
    for sub, data in results.items():
        print(f"    {sub} -> {data}")