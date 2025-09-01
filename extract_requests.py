import sqlite3
import pandas as pd
import argparse, sys, pathlib, tldextract, textwrap

ext = tldextract.TLDExtract(include_psl_private_domains=True)

def detect_tp_column(cursor) -> str | None:
    cols = {row[1] for row in cursor.execute("PRAGMA table_info(http_requests)")}
    for cand in (
        "is_third_party_to_top_window",
        "is_third_party_window",
        "is_third_party_channel",
    ):
        if cand in cols:
            return cand
    return None

def regdom_or_host_from_url(u):
    try:
        h = urlsplit(u).hostname or u
    except Exception:
        h = u
    rd = ext(h).registered_domain or ""
    return rd or h.lower().lstrip(".")

def main() -> None:
    pa = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pa.add_argument("--sqlite", required=True)
    pa.add_argument("--out", required=True)
    args = pa.parse_args()

    db_path = pathlib.Path(args.sqlite).expanduser()
    if not db_path.exists():
        sys.exit(f"ERROR SQLite not found: {db_path}")

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    tp_col = detect_tp_column(cur)
    if not tp_col:
        sys.exit("ERROR Could not find column")

    req = pd.read_sql_query(
        f"""
        SELECT id AS request_id,
               visit_id,
               url,
               referrer,
               resource_type,
               {tp_col} AS is_third_party
        FROM   http_requests
        """,
        con,
    )

    resp = pd.read_sql_query(
        """
        SELECT request_id,
               response_status AS status
        FROM   http_responses
        """,
        con,
    )

    visits = pd.read_sql_query(
        "SELECT visit_id, site_url FROM site_visits", con
    ).set_index("visit_id")["site_url"]

    con.close()

    df = req.merge(resp, on="request_id", how="left")
    df["first_party"] = df["visit_id"].map(visits).fillna("")

    df["req_domain"] = df["url"].apply(regdom_or_host_from_url)
    df["fp_domain"]  = df["first_party"].apply(regdom_or_host_from_url)

    df["is_third_party_dom"] = (df["req_domain"] != df["fp_domain"]).astype(int)

    cols_final = [
        "visit_id",
        "first_party",
        "fp_domain",
        "url",
        "req_domain",
        "resource_type",
        "status",
        "referrer",
        "is_third_party",
        "is_third_party_dom",
    ]
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False, columns=cols_final)
    print(f"OK CSV requests --> {out_path}  ({len(df):,} rows)")


if __name__ == "__main__":
    main()
