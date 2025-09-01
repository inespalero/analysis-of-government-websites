import argparse, socket, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
import requests

GOOD = set(range(200,400)) | {401,403}

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--concurrency", type=int, default=48)
    ap.add_argument("--timeout", type=int, default=6)
    return ap.parse_args()

def canon_host(s: str) -> str:
    s = s.strip()
    if not s: return ""
    if "://" in s:
        h = (urlsplit(s).hostname or "").lower().strip(".")
    else:
        h = s.lower().strip().split("/")[0].strip(".")
    if h.startswith("www."):
        h = h[4:]
    return h

def dns_ok(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False

def try_root(session: requests.Session, host: str, timeout: int):
    def _probe(h: str):
        for scheme in ("https", "http"):
            root = f"{scheme}://{h}/"
            try:
                r = session.head(root, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                r = None
            if r and (r.status_code in GOOD or r.status_code == 405):
                return True, r.url or root, r.status_code
            try:
                g = session.get(root, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                g = None
            if g and g.status_code in GOOD:
                return True, g.url or root, g.status_code
        return False, f"Without valid response in https/http for {h}", None

    if dns_ok(host):
        ok, u, code = _probe(host)
        if ok: return True, u, code

    www = f"www.{host}"
    if dns_ok(www):
        ok, u, code = _probe(www)
        if ok: return True, u, code

    return False, "DNS does not resolve host nor www.", None

def build_session(timeout: int) -> requests.Session:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    retry = Retry(
        total=1, connect=1, read=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("HEAD","GET"),
        backoff_factor=0.3,
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    s = requests.Session()
    s.headers.update({
        "User-Agent": "TFM-check/1.0 (+research; contact: you@example.com)",
        "Accept": "*/*",
    })
    adapter = HTTPAdapter(max_retries=retry, pool_connections=64, pool_maxsize=64)
    s.mount("https://", adapter); s.mount("http://", adapter)
    return s

def check_file(path: str, concurrency: int, timeout: int):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = [ln.strip() for ln in f if ln.strip()]
    hosts, seen = [], set()
    for ln in raw:
        h = canon_host(ln)
        if h and h not in seen:
            seen.add(h); hosts.append(h)

    session = build_session(timeout)
    results = []

    def worker(h):
        ok, url_or_reason, code = try_root(session, h, timeout)
        return (h, ok, url_or_reason, code)

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = {ex.submit(worker, h): h for h in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())

    alive = [f"{url_or_reason.rstrip('/')}/" if ok else None for h, ok, url_or_reason, code in results if ok]
    dead  = [h for h, ok, url_or_reason, code in results if not ok]

    alive_path = f"{path}_alive.txt"
    dead_path  = f"{path}_dead.txt"
    with open(alive_path, "w", encoding="utf-8") as fa:
        for u in sorted(set(alive)):
            fa.write(u + "\n")
    with open(dead_path, "w", encoding="utf-8") as fd:
        for h in sorted(set(dead)):
            fd.write(h + "\n")

    ok_count = len(set(alive))
    ko_count = len(set(dead))
    print(f"[{path}] OK: {ok_count} | FAIL: {ko_count} -> {alive_path} / {dead_path}")

def main():
    args = parse_args()
    for p in args.files:
        try:
            check_file(p, args.concurrency, args.timeout)
        except FileNotFoundError:
            print(f"[ERROR] Cannot find {p}", file=sys.stderr)

if __name__ == "__main__":
    main()
