import argparse
import dns.resolver
import requests
import random
import string
import threading
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Utility functions ---
def clean_domain(domain):
    domain = re.sub(r'^https?://', '', domain).split('/')[0].rstrip('.')
    if not re.match(r'^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$', domain):
        raise ValueError("Invalid domain")
    return domain.lower()

def load_wordlist(path):
    with open(path, 'r') as f:
        return list({line.strip().lower() for line in f if line.strip()})

def check_wildcard(domain):
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
    test = f"{random_sub}.{domain}"
    try:
        ans = dns.resolver.resolve(test, 'A', lifetime=2)
        return ans[0].to_text()
    except:
        return None

def resolve(subdomain):
    try:
        ans = dns.resolver.resolve(subdomain, 'A', lifetime=2)
        return [r.to_text() for r in ans]
    except dns.resolver.NoAnswer:
        try:
            cname = dns.resolver.resolve(subdomain, 'CNAME', lifetime=2)
            return [f"CNAME:{r.to_text()}" for r in cname]
        except:
            return []
    except:
        return []

# --- Passive source ---
def crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={"User-Agent": "SubEnumerator/1.0"})
        if resp.status_code != 200:
            return set()
        entries = resp.json()
        subs = set()
        for e in entries:
            for name in e.get("name_value", "").split('\n'):
                name = name.strip().lower().lstrip('*.')
                if name.endswith(f".{domain}") and name != domain:
                    subs.add(name)
        return subs
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return set()

# --- Active brute force ---
def brute(domain, wordlist, threads, wildcard_ip):
    found = {}
    lock = threading.Lock()

    def worker(name):
        sub = f"{name}.{domain}"
        ips = resolve(sub)
        if not ips:
            return None
        if wildcard_ip and wildcard_ip in ips:
            return None
        return (sub, ips)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(worker, name): name for name in wordlist}
        for future in as_completed(futures):
            res = future.result()
            if res:
                sub, ips = res
                with lock:
                    found[sub] = ips
                    print(f"[ACTIVE] {sub} -> {', '.join(ips)}")
    return found

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-w", "--wordlist", default="subdomains.txt")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    try:
        domain = clean_domain(args.domain)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    print(f"[*] Target: {domain}")
    wildcard_ip = check_wildcard(domain)
    if wildcard_ip:
        print(f"[!] Wildcard DNS → {wildcard_ip}")

    print("[*] Passive: crt.sh")
    passive = crtsh(domain)
    print(f"[+] {len(passive)} subdomains from crt.sh")

    # Resolve passive results
    resolved_passive = {}
    for sub in passive:
        ips = resolve(sub)
        if ips:
            resolved_passive[sub] = ips
            print(f"[PASSIVE] {sub} → {', '.join(ips)}")

    print("[*] Active brute-force")
    wordlist = load_wordlist(args.wordlist)
    print(f"[*] {len(wordlist)} words loaded")
    active = brute(domain, wordlist, args.threads, wildcard_ip)

    all_results = {**resolved_passive, **active}  # active overwrites passive
    print(f"\n[*] Total unique resolved subdomains: {len(all_results)}")

    if args.output:
        with open(args.output, 'w') as f:
            for sub, ips in sorted(all_results.items()):
                f.write(f"{sub} → {', '.join(ips)}\n")
        print(f"[+] Saved to {args.output}")
    else:
        for sub, ips in sorted(all_results.items()):
            print(f"{sub} → {', '.join(ips)}")

if __name__ == "__main__":
    main()