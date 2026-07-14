
import dns.resolver
import requests
import random
import string
import concurrent.futures
import threading
import argparse
import time

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


def brute_force(domain: str, wordlist_path: str, threads: int = 30):
    words = load_wordlist(wordlist_path)

    print(f"[*] Checking {domain} for wildcard DNS...")
    wildcard_ips = check_wildcard(domain)

    wildcard_sigs = set()
    if wildcard_ips:
        print(f"[!] Wildcard DNS detected. Pool of IPs: {wildcard_ips}")
        wildcard_sigs = get_wildcard_http_signature(domain)
        print(f"[!] Wildcard HTTP fingerprint(s): {wildcard_sigs}\n")
    else:
        print(f"[*] No wildcard DNS detected. Skipping HTTP checks.\n")

    print(f"[*] Loaded {len(words)} words. Starting brute-force ({threads} threads) against {domain}...\n")

    found = {}
    filtered_count = 0
    lock = threading.Lock()  

    def worker(word: str):
        nonlocal filtered_count
        candidate = f"{word}.{domain}"
        ips = resolve(candidate)

        if ips is None:
            return  

        if not wildcard_ips:
            with lock:
                print(f"[+] {candidate} -> {ips}")
                found[candidate] = {"ips": ips}
            return

        sig = get_http_signature(candidate)

        with lock:
            if sig and sig in wildcard_sigs:
                print(f"[~] {candidate} -> {ips}  HTTP {sig} (filtered)")
                filtered_count += 1
            else:
                print(f"[+] {candidate} -> {ips}  HTTP {sig}")
                found[candidate] = {"ips": ips, "http_signature": sig}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(worker, words)

    print(f"\n[*] Done. Found {len(found)} real subdomains ({filtered_count} filtered as wildcard noise).")
    return found



# def crtsh_lookup(domain: str, timeout: int = 15):
#     url = f"https://crt.sh/?q=%25.{domain}&output=json"
#     try:
#         resp = requests.get(url, timeout=timeout)
#         resp.raise_for_status()
#         data = resp.json()
#     except (requests.exceptions.RequestException, ValueError) as e:
#         print(f"[!] crt.sh failed: {e}")
#         return set()

#     subs = set()
#     for entry in data:
#         for name in entry.get("name_value", "").split("\n"):
#             name = name.strip().lower().lstrip("*.")
#             if name.endswith(domain):
#                 subs.add(name)
#     return subs


def certspotter_lookup(domain: str, timeout: int = 15):
    url = f"https://api.certspotter.com/v1/issuances"
    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names"
    }

    try:
        resp = requests.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] Cert Spotter request failed: {e}")
        return set()

    subdomains = set()
    for entry in resp.json():
        for name in entry.get("dns_names", []):
            name = name.strip().lower()
            if name.endswith(domain):
                subdomains.add(name)

    return subdomains

# def hackertarget_lookup(domain: str, timeout: int = 15):
#     url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
#     try:
#         resp = requests.get(url, timeout=timeout)
#         resp.raise_for_status()
#     except requests.exceptions.RequestException as e:
#         print(f"[!] HackerTarget failed: {e}")
#         return set()

#     if "error" in resp.text.lower():
#         print(f"[!] HackerTarget: {resp.text.strip()}")
#         return set()

#     subs = set()
#     for line in resp.text.splitlines():
#         if "," in line:
#             subs.add(line.split(",")[0].strip().lower())
#     return subs



def passive_enum(domain: str):
    all_subs = set()
    print("[*] Querying certspotter...")
    all_subs |= certspotter_lookup(domain)
    print("[*] Querying HackerTarget...")
    # all_subs |= hackertarget_lookup(domain)
    print(f"[*] Passive sources returned {len(all_subs)} unique candidate subdomains.\n")
    return all_subs


def resolve_candidates(candidates: set, threads: int = 30):
    
    print(f"[*] Resolving {len(candidates)} passive candidates to check liveness...\n")

    live = {}
    lock = threading.Lock()

    def worker(hostname):
        ips = resolve(hostname)
        if ips:
            with lock:
                live[hostname] = ips

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(worker, candidates)

    print(f"[*] {len(live)} / {len(candidates)} passive candidates are still live.\n")
    return live


def run_all(domain: str, wordlist_path: str = None, threads: int = 30,
            do_passive: bool = True, do_active: bool = True):

    brute_results = {}
    passive_results = {}

    if do_active:
        if not wordlist_path:
            print("[!] Active mode selected but no wordlist provided. Skipping brute-force.")
        else:
            brute_results = brute_force(domain, wordlist_path, threads)

    if do_passive:
        passive_candidates = passive_enum(domain)
        passive_results = resolve_candidates(passive_candidates, threads)

    merged = {**passive_results, **brute_results}

    print(f"[*] === FINAL RESULTS ===")
    print(f"[*] Total unique live subdomains: {len(merged)}\n")
    for sub in sorted(merged):
        print(f"    {sub} -> {merged[sub]}")

    return merged






def main():
    parser = argparse.ArgumentParser(description="Subdomain enumeration: brute-force + passive")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-w", "--wordlist", default="wordlist.txt", help="Wordlist path (used in active mode)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Thread count")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--passive-only", action="store_true", help="Only run passive enumeration ")
    mode.add_argument("--active-only", action="store_true", help="Only run active brute-force")

    args = parser.parse_args()

    if args.passive_only:
        do_passive, do_active = True, False
    elif args.active_only:
        do_passive, do_active = False, True
    else:
        do_passive, do_active = True, True  

    start = time.time()
    run_all(args.domain, args.wordlist, args.threads, do_passive=do_passive, do_active=do_active)
    print(f"\n[*] Total time: {time.time() - start:.2f}s")



if __name__ == "__main__":
    main()