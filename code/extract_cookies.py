import sqlite3, pandas as pd, tldextract, argparse, pathlib, sys
from urllib.parse import urlsplit

ext = tldextract.TLDExtract(include_psl_private_domains=True)

def parse_expiry(x):
    try:
        if pd.isna(x): return pd.NaT
        if isinstance(x, (int, float)) or (isinstance(x, str) and x.isdigit()):
            return pd.to_datetime(int(float(x)), unit="s", utc=True, errors="coerce")
        return pd.to_datetime(str(x), utc=True, errors="coerce")
    except Exception:
        return pd.NaT

def regdom_or_host(u):
    try:
        h = urlsplit(u).hostname or u
    except Exception:
        h = u
    rd = ext(h).registered_domain or ""
    return rd or h.lower().lstrip(".")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sqlite", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    DB = pathlib.Path(args.sqlite).expanduser()
    if not DB.exists():
        sys.exit(f"ERROR SQLite not found: {DB}")

    with sqlite3.connect(DB) as con:
        df = pd.read_sql_query("""
            SELECT visit_id, host, name, value, path,
                   is_session, is_secure, is_http_only,
                   same_site, expiry
            FROM javascript_cookies
        """, con)

        sites = pd.read_sql_query("""
            SELECT visit_id, site_url FROM site_visits
        """, con).set_index("visit_id")["site_url"].to_dict()

    df["first_party"] = df["visit_id"].map(sites)
    df["first_party"] = df["first_party"].fillna("")

    df["expiry"] = df["expiry"].apply(parse_expiry)

    for col in ("cookie_domain", "fp_domain"):
        df[col] = ""

    df["cookie_domain"] = df["host"].apply(lambda h: regdom_or_host(h))
    df["fp_domain"]     = df["first_party"].apply(lambda u: regdom_or_host(u) if u else "")

    df["is_third_party"] = (df["cookie_domain"] != df["fp_domain"]).astype(int)

    df.to_csv(args.out, index=False)
    print(f"OK CSV cookies --> {args.out}  ({len(df):,} rows)")

if __name__ == "__main__":
    main()
