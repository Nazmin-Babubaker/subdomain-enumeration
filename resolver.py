
import dns.resolver
import random
import string

def resolve(hostname: str):
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return str(answers[0])
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.exception.Timeout:
        return None

def load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]
    


def random_subdomain_label(length: int = 15) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def check_wildcard(domain: str):
    junk_label = random_subdomain_label()
    junk_host = f"{junk_label}.{domain}"
    return resolve(junk_host)





def brute_force(domain: str, wordlist_path: str):
    words = load_wordlist(wordlist_path)

    print(f"[*] Checking {domain} for wildcard DNS...")
    wildcard_ip = check_wildcard(domain)
    if wildcard_ip:
        print(f"[!] Wildcard detected: junk subdomains resolve to {wildcard_ip}")
        print(f"[!] Results matching this IP will be filtered out as false positives\n")
    else:
        print(f"[*] No wildcard detected. Proceeding normally.\n")

    print(f"[*] Loaded {len(words)} words. Starting brute-force against {domain}...\n")

    found = {}
    filtered_count = 0

    for word in words:
        candidate = f"{word}.{domain}"
        ip = resolve(candidate)

        if ip is None:
            print(f"[-] {candidate}")
            continue

        if wildcard_ip and ip == wildcard_ip:
            print(f"[~] {candidate} -> {ip}  (filtered: matches wildcard)")
            filtered_count += 1
            continue

        print(f"[+] {candidate} -> {ip}")
        found[candidate] = ip

    print(f"\n[*] Done. Found {len(found)} real subdomains ({filtered_count} filtered as wildcard noise).")
    return found


if __name__ == "__main__":
    results = brute_force("github.io", "wordlist.txt")
    print()
    for sub, ip in results.items():
        print(f"    {sub} -> {ip}")