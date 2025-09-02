import argparse, json, time, sys
from typing import Iterable, Set, Dict
import requests
from publicsuffix2 import PublicSuffixList
import dns.resolver, dns.exception

HEADERS = {"User-Agent": "gov-domain-collector/1.0 (+https://example.local)"}
CRT_URL = "https://crt.sh/?q=%25.{suffix}&output=json"

DEFAULT_SUFFIXES = {
    "gob_es": "gob.es",
    "gov_uk": "gov.uk",
    "gob_mx": "gob.mx",
    "gob_cl": "gob.cl",
    "gov_za": "gov.za",
    "gov_in": "gov.in",
    "gov_au": "gov.au",
}

psl = PublicSuffixList()

def fetch_ct_names(suffix: str, retries: int = 4, backoff: float = 1.5) -> Set[str]:
    url = CRT_URL.format(suffix=suffix)
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=60)
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            data = r.json()
            names = set()
            for row in data:
                raw = row.get("name_value", "")
                for h in raw.split("\n"):
                    h = h.strip().lower().lstrip("*.").rstrip(".")
                    if h and h.endswith("." + suffix) or h == suffix:
                        names.add(h)
            return names
        except Exception as e:
            if attempt == retries:
                raise
            sleep = backoff ** attempt
            time.sleep(sleep)
    return set()

def to_registrable(host: str) -> str:
    try:
        host.encode("idna").decode("ascii")
        reg = psl.get_sld(host)
        return reg or ""
    except Exception:
        return ""

def is_delegated(domain: str, timeout: float = 3.0) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        ans = resolver.resolve(domain, "NS")
        return len(ans) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        try:
            ans = resolver.resolve(domain, "SOA")
            return len(ans) > 0
        except Exception:
            return False
    except (dns.resolver.Timeout, dns.exception.DNSException):
        return False

def process_suffix(suffix: str, validate_dns: bool = True) -> Set[str]:
    hosts = fetch_ct_names(suffix)
    registrable = set()
    for h in hosts:
        reg = to_registrable(h)
        if reg and (reg.endswith("." + suffix) or reg == suffix):
            registrable.add(reg)
    if validate_dns:
        valid = set()
        for d in registrable:
            if is_delegated(d):
                valid.add(d)
        return valid
    return registrable

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suffixes", nargs="*")
    ap.add_argument("--no-validate", action="store_true")
    ap.add_argument("--sleep", type=float, default=2.0)
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    suffixes = args.suffixes if args.suffixes else list(DEFAULT_SUFFIXES.values())

    label_map: Dict[str, str] = {}
    for k, v in DEFAULT_SUFFIXES.items():
        label_map[v] = k
    for suf in suffixes:
        label = label_map.get(suf, suf.replace(".", "_"))

        try:
            domains = process_suffix(suf, validate_dns=not args.no_validate)
            outpath = f"{args.outdir.rstrip('/')}/{label}.txt"
            with open(outpath, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    f.write(d + "\n")
            print(f"[OK] {suf}: {len(domains)} domains --> {outpath}")
        except Exception as e:
            print(f"[ERROR] {suf}: {e}", file=sys.stderr)
        time.sleep(max(0.0, args.sleep))

if __name__ == "__main__":
    main()
