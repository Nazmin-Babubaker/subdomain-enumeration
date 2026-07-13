# passive.py
import requests

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

if __name__ == "__main__":
    domain = "google.com"
    print(f"[*] Querying crt.sh for {domain}...")
    results = certspotter_lookup(domain)

    print(f"[*] Found {len(results)} unique subdomains via certspotter\n")
    for sub in sorted(results):
        print(f"    {sub}")