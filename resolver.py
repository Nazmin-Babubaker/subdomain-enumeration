
import dns.resolver
import requests
import random
import string
import concurrent.futures
import threading
import argparse


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

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration tool — brute-force with wildcard detection"
    )
    parser.add_argument(
        "domain",
        help="Target domain to enumerate (e.g. example.com)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        default="wordlist.txt",
        help="Path to wordlist file (default: wordlist.txt)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=30,
        help="Number of concurrent threads (default: 30)"
    )

    args = parser.parse_args()

    import time
    start = time.time()
    results = brute_force(args.domain, args.wordlist, threads=args.threads)
    elapsed = time.time() - start

    print(f"\n[*] Took {elapsed:.2f} seconds")

if __name__ == "__main__":
    main()