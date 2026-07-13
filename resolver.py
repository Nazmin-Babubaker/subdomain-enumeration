
import dns.resolver

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


def brute_force(domain: str, wordlist_path: str):
    words = load_wordlist(wordlist_path)
    found = {}

    print(f"[*] Loaded {len(words)} words. Starting brute-force against {domain}...\n")

    for word in words:
        candidate = f"{word}.{domain}"
        ip = resolve(candidate)
        if ip:
            print(f"[+] {candidate} -> {ip}")
            found[candidate] = ip
        else:
            print(f"[-] {candidate}")

    return found


if __name__ == "__main__":
    domain = "rit.ac.in" 
    results = brute_force(domain, "wordlist.txt")

    print(f"\n[*] Done. Found {len(results)} subdomains.")
    for sub, ip in results.items():
        print(f"    {sub} -> {ip}")