from __future__ import annotations
import argparse, csv, socket, subprocess, sys, textwrap, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR   = Path(__file__).resolve().parent.parent
TLS_DIR    = BASE_DIR / "tls_data"; TLS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_CSV = TLS_DIR / "summary_tls.csv"


SCAN_OPTS = [
    "--certinfo",
    "--tlsv1_2",
    "--tlsv1_3",
    "--quiet",
]

def port_open(host: str, port: int = 443, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False

def slug(host: str) -> str:
    return host.replace(".", "_").replace(":", "_")

def run_cmd(cmd: list[str], timeout: int) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stderr.strip()

def host_from_line(s: str) -> str:
    s = s.strip()
    if not s:
        return ""
    if "://" in s:
        try:
            h = (urlsplit(s).hostname or "").lower()
        except Exception:
            h = s.split("://",1)[-1].split("/")[0]
    else:
        h = s.split("/")[0]
    h = h.strip().strip(".").lower()
    if h.startswith("www."):
        h = h[4:]

    return h.split(":")[0]

def scan_domain(domain: str, timeout: int, http_headers: bool) -> tuple[str,str|None,str]:
    if not port_open(domain, 443, timeout=5):
        return "NOP", None, "port 443 closed"

    outfile = TLS_DIR / f"{slug(domain)}.json"

    base = ["sslyze", *SCAN_OPTS]
    if http_headers:
        base.append("--http_headers")
    base += ["--json_out", str(outfile)]

    attempts: list[list[str]] = [
        base + [domain]
    ]
    if not domain.startswith("www."):
        attempts += [
            base + ["--sni", f"www.{domain}", domain],
            base + [f"www.{domain}"],
        ]

    for cmd in attempts:
        rc, err = run_cmd(cmd, timeout)
        if rc == 0 and outfile.exists() and outfile.stat().st_size > 0:
            return "OK", outfile.name, ""
        outfile.unlink(missing_ok=True)

    return "ERR", None, "sslyze failed"

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-i","--input", required=True)
    p.add_argument("-w","--workers", type=int, default=4)
    p.add_argument("-t","--timeout", type=int, default=120)
    p.add_argument("--no-http", action="store_true")
    return p.parse_args()

def main() -> None:
    args = parse_args()

    lines = Path(args.input).read_text().splitlines()
    domains, seen = [], set()
    for line in lines:
        h = host_from_line(line)
        if h and h not in seen:
            seen.add(h)
            domains.append(h)

    total    = len(domains)
    print(f"TLS scan ({total} domains) with {args.workers} workers(s)\n")

    ok = err = nop = 0
    rows: list[tuple[str,str,str,str]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(scan_domain,d,args.timeout,not args.no_http): d for d in domains}
        for fut in as_completed(futs):
            dom = futs[fut]
            try:
                status, jfile, reason = fut.result()
            except Exception as ex:
                status, jfile, reason = "ERR", None, f"exception: {ex}"

            pad = dom.ljust(35)
            if status == "OK":
                ok  += 1;  print(f"[ OK ] {pad} → {jfile}")
            elif status == "NOP":
                nop += 1;  print(f"[NOP ] {pad} → {reason}")
            else:
                err += 1;  print(f"[ERR ] {pad} → {reason}")

            rows.append((dom,status,jfile or "",reason))

    with SUMMARY_CSV.open("w",newline="",encoding="utf-8") as fh:
        csv.writer(fh).writerows([["domain","status","json_file","reason"], *rows])

    print(f"\n END TLS-scan: {ok} OK, {err} ERR, {nop} NOP")
    print(f"Summary CSV : {SUMMARY_CSV.relative_to(Path.cwd())}")
    print(f"JSON : {TLS_DIR.relative_to(Path.cwd())}")

if __name__ == "__main__":
    t0=time.time()
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nCanceled.")
    finally:
        print(f"\nTotal duration: {time.time()-t0:,.1f}s")
