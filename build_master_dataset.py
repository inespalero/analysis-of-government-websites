from __future__ import annotations
import argparse, pathlib, warnings
import pandas as pd, numpy as np
warnings.filterwarnings("ignore", category=pd.errors.PerformanceWarning)
import urllib.parse as up

def pct(a: pd.Series, b: pd.Series) -> pd.Series:
    return (a / b.replace(0, np.nan)).round(3).fillna(0)

def read_domains(txt: str) -> set[str]:
    return {l.strip().lower() for l in pathlib.Path(txt).read_text().splitlines() if l.strip()}

def top_list(series: pd.Series, n: int = 5) -> str:
    return ";".join(series.value_counts().head(n).index)

def norm_host(s: str) -> str:
    s = str(s or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            s = up.urlsplit(s).hostname or s
        except Exception:
            s = s.split("://", 1)[-1]
    s = s.split("/")[0]
    if s.startswith("www."):
        s = s[4:]
    return s

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookies",   required=True)
    ap.add_argument("--requests",  required=True)
    ap.add_argument("--headers",   required=True)
    ap.add_argument("--tls_flat",  required=True)
    ap.add_argument("--fp_flat",   required=True)
    ap.add_argument("--official",  required=True)
    ap.add_argument("--out",       required=True)
    args = ap.parse_args()

    official = {norm_host(l) for l in pathlib.Path(args.official).read_text().splitlines() if l.strip()}

    ck = pd.read_csv(args.cookies)

    ck["first_party"] = ck["first_party"].fillna("")
    ck["fp_fqdn"] = ck["first_party"].str.extract(r"://([^/]+)")[0].str.lower().fillna("")
    ck["fp_fqdn"] = ck["fp_fqdn"].apply(norm_host)

    ck["expiry"] = pd.to_datetime(ck["expiry"], errors="coerce", utc=True)
    ck["is_third_party"] = ck["is_third_party"].fillna(0)

    now = pd.Timestamp.utcnow()
    ck["expiry_days"] = (ck["expiry"] - now).dt.days
    ck["expiry_days_clip"] = ck["expiry_days"].clip(lower=0)

    g = ck.groupby("fp_fqdn", group_keys=False)
    cookies = pd.DataFrame({
        "cookies_total"   : g.size(),
        "cookies_3p"      : g["is_third_party"].sum(),
        "cookie_3p_domains": g.apply(lambda x: x.loc[x["is_third_party"]==1,"cookie_domain"].nunique()),
        "cookie_3p_top"    : g.apply(lambda x: top_list(x.loc[x["is_third_party"]==1,"cookie_domain"])),
        "tracker_cookies"  : g.apply(lambda x: x["owner"].notna().sum()),

        "cookies_secure"  : g["is_secure"].sum(),
        "cookies_httponly": g["is_http_only"].sum(),
        "cookies_session" : g["is_session"].sum(),

        "ss_none"   : g.apply(lambda x: (x["same_site"].str.lower()=="none").sum()),
        "ss_lax"    : g.apply(lambda x: (x["same_site"].str.lower()=="lax").sum()),
        "ss_strict" : g.apply(lambda x: (x["same_site"].str.lower()=="strict").sum()),

        "expiry_median_days": g["expiry_days_clip"].median().round(1).fillna(0),
        "expiry_max_days"   : g["expiry_days_clip"].max().fillna(0).astype(int),
        "expiry_min_days"   : g["expiry_days"].min().fillna(0).astype(int),
    }).reset_index().rename(columns={"fp_fqdn":"domain"})

    cookies["cookies_3p_ratio"]       = pct(cookies["cookies_3p"], cookies["cookies_total"])
    cookies["tracker_cookie_ratio"]   = pct(cookies["tracker_cookies"], cookies["cookies_total"])
    cookies["cookies_secure_ratio"]   = pct(cookies["cookies_secure"], cookies["cookies_total"])
    cookies["cookies_httponly_ratio"] = pct(cookies["cookies_httponly"], cookies["cookies_total"])
    cookies["cookies_session_ratio"]  = pct(cookies["cookies_session"], cookies["cookies_total"])
    cookies["ss_none_ratio"]          = pct(cookies["ss_none"], cookies["cookies_total"])
    cookies["ss_lax_ratio"]           = pct(cookies["ss_lax"], cookies["cookies_total"])
    cookies["ss_strict_ratio"]        = pct(cookies["ss_strict"], cookies["cookies_total"])

    rq = pd.read_csv(args.requests)

    rq["first_party"] = rq["first_party"].fillna("")
    rq["fp_fqdn"] = rq["first_party"].str.extract(r"://([^/]+)")[0].str.lower().fillna("")
    rq["fp_fqdn"] = rq["fp_fqdn"].apply(norm_host)

    rq["is_third_party_dom"] = rq["is_third_party_dom"].fillna(0)
    g = rq.groupby("fp_fqdn", group_keys=False)

    pivot = rq.pivot_table(index="fp_fqdn",
                           columns="resource_type",
                           values="url",
                           aggfunc="count",
                           fill_value=0)
    pivot.columns = [f"resources_{c.lower()}" for c in pivot.columns]

    requests = pd.DataFrame({
        "req_total"        : g.size(),
        "req_3p"           : g["is_third_party_dom"].sum(),
        "distinct_3p_req_domains": g.apply(
            lambda x: x.loc[x["is_third_party_dom"]==1,"req_domain"].nunique()),
        "req_3p_top"       : g.apply(lambda x: top_list(
            x.loc[x["is_third_party_dom"]==1,"req_domain"])),
        "tracker_hits"     : g.apply(lambda x: x["owner"].notna().sum()),
    }).reset_index().rename(columns={"fp_fqdn":"domain"})

    requests["req_3p_ratio"]      = pct(requests["req_3p"], requests["req_total"])
    requests["tracker_hit_ratio"] = pct(requests["tracker_hits"], requests["req_total"])

    requests = requests.merge(pivot.reset_index().rename(columns={"fp_fqdn":"domain"}), how="left")

    sec_headers = pd.read_csv(args.headers)
    sec_headers["domain"] = sec_headers["domain"].apply(norm_host)

    tls = pd.read_csv(args.tls_flat)
    tls["domain"] = tls["domain"].apply(norm_host)
    tls = (tls.sort_values(["tls_cipher_suites_total","tls_hsts"], ascending=[False, False])
          .drop_duplicates("domain", keep="first"))
    tls["tls_cipher_fs_ratio"] = pct(tls["tls_cipher_suites_fs"], tls["tls_cipher_suites_total"])
    tls["tls_cipher_weak_ratio"] = pct(tls["tls_cipher_suites_weak"], tls["tls_cipher_suites_total"])

    fp = pd.read_csv(args.fp_flat).drop(columns=["status","http_status","load_time"], errors="ignore")
    fp["domain"] = fp["domain"].apply(norm_host)

    all_domains = pd.Series(sorted(official), name="domain").to_frame()
    df = (all_domains.set_index("domain")
                    .join(cookies.set_index("domain"))
                    .join(requests.set_index("domain"))
                    .join(sec_headers.set_index("domain"))
                    .join(tls.set_index("domain"))
                    .join(fp.set_index("domain"))
                    .reset_index())

    num_cols = df.select_dtypes(include=["number", "boolean"]).columns
    str_cols = df.select_dtypes(include=["object"]).columns
    df[num_cols] = df[num_cols].fillna(0)
    df[str_cols] = df[str_cols].fillna("")

    blocks = [
        ["domain"],

        ["cookies_total","cookies_3p","cookies_3p_ratio",
         "cookie_3p_domains","cookie_3p_top",
         "tracker_cookies","tracker_cookie_ratio",
         "cookies_secure","cookies_secure_ratio",
         "cookies_httponly","cookies_httponly_ratio",
         "cookies_session","cookies_session_ratio",
         "ss_none","ss_lax","ss_strict",
         "ss_none_ratio","ss_lax_ratio","ss_strict_ratio",
         "expiry_min_days","expiry_median_days","expiry_max_days"],

        ["req_total","req_3p","req_3p_ratio",
         "distinct_3p_req_domains","req_3p_top",
         "tracker_hits","tracker_hit_ratio"],

        sorted([c for c in df.columns if c.startswith("resources_")]),

        ["strict-transport-security","content-security-policy",
         "permissions-policy","referrer-policy",
         "x-frame-options","x-content-type-options","total_sec_headers"],

        ["tls_error","tls_version_max","tls_key_alg","tls_key_size","tls_curve",
         "tls_cert_issuer","tls_days_until_expiry",
         "tls_cipher_suites_total","tls_cipher_suites_list","tls_cipher_suites_fs","tls_cipher_fs_ratio",
         "tls_cipher_suites_weak","tls_cipher_weak_ratio","tls_cipher_weak_list",
         "tls_hsts"],

        ["fp_detected","fp_methods_total","fp_canvas","fp_audioCtx","fp_rtc","fp_storage"],
    ]
    ordered = [col for blk in blocks for col in blk if col in df.columns]
    df = df[ordered]

    out = pathlib.Path(args.out)
    out.parent.mkdir(exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Saved  master_dataset: {out}  ({len(df)} domains, {len(df.columns)} columns)")

if __name__ == "__main__":
    main()
