import json, re, argparse, pandas as pd, numpy as np
from pathlib import Path
from typing import Optional

TLD_GENERIC = re.compile(r"\.(com|net|io|ai|app|cloud|co|org|info)$", re.I)

def load_ndjson(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]

def norm_domain(s):
    if not isinstance(s, str):
        return s
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    s = s[4:] if s.startswith("www.") else s
    return s

def first_cookie_policy_details(docs: list[dict]) -> dict[str, dict]:
    out = {}
    for d in docs:
        if d["doc_type"] == "COOKIE_POLICY":
            dom = norm_domain(d["domain"])
            if dom not in out:
                out[dom] = d["details"] or {}
    return out

def ok_cookie_ownership(det: dict, tech: pd.Series) -> Optional[bool]:
    own = det.get("ownership")
    if own != "FIRST":
        return None
    return tech["cookies_3p_ratio"] == 0

def ok_cookie_session_only(det: dict, tech: pd.Series) -> Optional[bool]:
    dur = det.get("duration") or {}
    if not (dur.get("session") and not dur.get("persistent")):
        return None
    return (tech["expiry_max_days"] or 0) <= 1

def ok_consent_prior(consent_mech: str | None, tech: pd.Series) -> Optional[bool]:
    if consent_mech not in {"banner", "cmp"}:
        return None
    return (tech["cookies_3p_ratio"] or 0) <= 0.05

def ok_no_tracking_claim(det: dict, tech: pd.Series) -> Optional[bool]:
    if det.get("third_parties"):
        return None
    return (tech["tracker_hit_ratio"] or 0) == 0

def possible_transfer_violation(scope_norm: str | None, tech: pd.Series) -> Optional[bool]:
    if scope_norm not in {"NONE", "INTRA_EU"}:
        return None
    v = tech.get("req_3p_top")
    if v is None or (isinstance(v, float) and np.isnan(v)):
        s = ""
    else:
        s = str(v)
    top = [t.strip() for t in s.split(";") if t.strip()]
    violates = any(TLD_GENERIC.search(d) for d in top)
    return violates

def main(policies_jsonl, domains_csv, tech_csv, out_csv):

    docs  = load_ndjson(policies_jsonl)
    cpol  = first_cookie_policy_details(docs)
    df_pol= pd.read_csv(domains_csv)
    df_pol["domain"] = df_pol["domain"].apply(norm_domain)
    df_tech = pd.read_csv(tech_csv)
    df_tech["domain"] = df_tech["domain"].apply(norm_domain)

    def norm_scope(x: str|float):
        if not isinstance(x, str):
            return pd.NA
        x = x.upper()
        if "INTERNAC" in x:
            return "INTERNATIONAL"
        if "INTRA" in x or "UE" in x or "EEE" in x:
            return "INTRA_EU"
        if "NONE" in x or "NINGUNA" in x:
            return "NONE"
        return pd.NA
    df_pol["transfer_scope_norm"] = df_pol["transfer_scope"].apply(norm_scope)

    df = (df_pol
          .merge(df_tech, on="domain", how="left", suffixes=("", "_tech"))
          .set_index("domain"))

    results = {
        "ok_cookie_ownership": [],
        "ok_cookie_session_only": [],
        "ok_consent_prior": [],
        "ok_no_tracking_claim": [],
        "possible_transfer_violation": [],
    }

    for dom, row in df.iterrows():
        det = cpol.get(dom, {})

        results["ok_cookie_ownership"]      .append( ok_cookie_ownership(det, row) )
        results["ok_cookie_session_only"]   .append( ok_cookie_session_only(det, row) )
        results["ok_consent_prior"]         .append( ok_consent_prior(row.get("consent_mechanism"), row) )
        results["ok_no_tracking_claim"]     .append( ok_no_tracking_claim(det, row) )
        results["possible_transfer_violation"].append( possible_transfer_violation(row.get("transfer_scope_norm"), row) )

    for k,v in results.items():
        df[k] = v

    bool_cols = list(results.keys())
    df["matches"]     = df[bool_cols].apply(lambda r:(r==True ).sum(), axis=1)
    df["violations"]  = df[bool_cols].apply(lambda r:(r==False).sum(), axis=1)
    df["unevaluable"] = df[bool_cols].isna().sum(axis=1)

    denom = df["matches"] + df["violations"]
    denom = denom.replace(0, np.nan)
    df["compliance_score"] = df["matches"] / denom.replace(0, np.nan)

    ESSENTIAL = [
     "transfer_scope_norm", "cookie_ownership_mixed", "consent_mechanism",
     "automated_decisions",
     "cookies_total", "cookies_3p_ratio", "cookies_session_ratio",
     "tracker_hit_ratio", "req_3p_ratio",
     "ok_cookie_ownership", "ok_cookie_session_only",
     "ok_consent_prior", "ok_no_tracking_claim",
     "possible_transfer_violation",
     "matches", "violations", "unevaluable", "compliance_score",
    ]

    report = df[ESSENTIAL]
    report.to_csv(out_csv, index_label="domain")

    print("OK compliance report: ", out_csv)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--policies")
    ap.add_argument("--domains")
    ap.add_argument("--tech")
    ap.add_argument("--out")
    args = ap.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    main(args.policies, args.domains, args.tech, args.out)
