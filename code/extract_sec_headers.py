from __future__ import annotations
import argparse, sqlite3, json, pathlib, re, urllib.parse as up
import pandas as pd

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
    "x-frame-options",
    "x-content-type-options",
]

def parse_raw_headers(raw: str | None) -> dict[str, str]:
    if not isinstance(raw, str) or not raw.strip():
        return {}

    raw = raw.strip()

    try:
        h = json.loads(raw)
        if isinstance(h, list):
            return {k.lower(): v for k, v in h}
        if isinstance(h, dict):
            return {k.lower(): v for k, v in h.items()}
    except Exception:
        pass

    out: dict[str, str] = {}
    for line in re.split(r"\r?\n", raw):
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def header_present(hdr_dict: dict[str, str], name: str) -> int:
    if name in hdr_dict:
        return 1
    if name == "permissions-policy" and "feature-policy" in hdr_dict:
        return 1
    return 0


def fqdn_from_url(url: str) -> str:
    try:
        return (up.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", required=True)
    ap.add_argument("--db",       required=True)
    ap.add_argument("--out",      required=True)
    args = ap.parse_args()

    rq = pd.read_csv(args.requests)

    main_docs = (
        rq[rq["resource_type"].str.lower().isin(["main_frame", "document"])]
        [["url"]].drop_duplicates()
    )
    main_docs["fqdn"] = main_docs["url"].apply(fqdn_from_url)

    conn = sqlite3.connect(args.db)
    resp = pd.read_sql_query("SELECT url, headers FROM http_responses", conn)
    conn.close()

    merged = main_docs.merge(resp, on="url", how="left")
    merged["_hdr_dict"] = merged["headers"].apply(parse_raw_headers)

    for h in SEC_HEADERS:
        merged[h] = merged["_hdr_dict"].apply(lambda d, x=h: header_present(d, x))

    cols = SEC_HEADERS
    sec = (
        merged.groupby("fqdn")[cols].max().reset_index()
        .rename(columns={"fqdn": "domain"})
    )
    sec["total_sec_headers"] = sec[cols].sum(axis=1)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sec.to_csv(out, index=False)
    print(f"OK sec_headers.csv created ({len(sec)} domains) --> {out}")


if __name__ == "__main__":
    main()
