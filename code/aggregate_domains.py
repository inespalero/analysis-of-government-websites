import json, argparse, pandas as pd, pathlib, re, numpy as np

def load_docs(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]

def rights_count(details):
    r = details.get("rights", {}) if isinstance(details, dict) else {}
    return sum(1 for v in r.values() if v is True)

def load_ndjson(path: str) -> pd.DataFrame:
    with open(path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]

    df = pd.json_normalize(records, sep=".")
    return df

def norm_domain(s):
    if not isinstance(s, str):
        return s
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    s = s[4:] if s.startswith("www.") else s
    return s

RIGHT_COLS = [
    "details.rights.access",
    "details.rights.rectification",
    "details.rights.erasure",
    "details.rights.opposition",
    "details.rights.portability",
    "details.rights.restriction",
    "details.rights.no_individual_decision",
]

SCOPE_RANK = {"NONE": 0, "INTRA_EU": 1, "INTERNATIONAL": 2}

def norm_scope(raw):
    if not isinstance(raw, str):
        return None
    raw = raw.upper()
    if re.search(r"INTERNAC", raw):
        return "INTERNATIONAL"
    if re.search(r"INTRA|UE|EEE", raw):
        return "INTRA_EU"
    if re.search(r"NONE|NINGUNA", raw):
        return "NONE"
    return None

def main(src, dst):
    df = load_ndjson(src).drop_duplicates(subset=["domain", "doc_type", "sha1"])
    df["domain"] = df["domain"].apply(norm_domain)

    def S(col, default=pd.NA):
        if col in df.columns:
            return df[col]
        n = len(df.index)
        if callable(default):
            vals = [default() for _ in range(n)]
        else:
            vals = [default] * n
        return pd.Series(vals, index=df.index)

    df["has_privacy"]  = df["doc_type"].eq("PRIVACY_POLICY")
    df["has_cookies"]  = df["doc_type"].eq("COOKIE_POLICY")
    df["has_legal"]    = df["doc_type"].eq("LEGAL_NOTICE")
    df["has_data_prot"]= df["doc_type"].eq("DATA_PROTECTION")

    df["privacy_controller_present"] = (
        (df["doc_type"]=="PRIVACY_POLICY") & S("details.controller", "").astype(str).str.len().gt(0)
    )
    df["dpo_contact_present"] = S("details.dpo_contact", "").astype(str).str.len().gt(0)

    for c in RIGHT_COLS:
        if c not in df.columns:
            df[c] = pd.NA
    df["rights_count"] = df[RIGHT_COLS].fillna(False).astype("boolean").sum(axis=1)
    df["rights_count_rel"] = df["rights_count"].where(
        df["doc_type"].isin(["PRIVACY_POLICY", "DATA_PROTECTION"])
    )
    df["legal_bases_count"] = (
        S("details.legal_bases", list)
        .apply(lambda x: len(x) if isinstance(x, list) else 0)
        .where(df["doc_type"].eq("PRIVACY_POLICY"), 0)
    )

    df["scope_norm"] = S("details.transfer_scope", None).apply(norm_scope)
    df["transfer_rank"] = (
        df["scope_norm"]
        .map(SCOPE_RANK)
        .where(df["doc_type"].isin(["PRIVACY_POLICY", "DATA_PROTECTION"]))
    )
    df["consent_mechanism_doc"] = df.apply(
        lambda r: r["details.consent_mechanism"] if r["doc_type"]=="COOKIE_POLICY" else None,
        axis=1
    )

    df["rights_general_statement"] = S("details.rights_general_statement", False).fillna(False).astype("boolean")
    df["automated_decisions_present"] = S("details.automated_decisions", False).fillna(False).astype("boolean")
    df["retention_present"] = S("details.retention", "").astype(str).str.len().gt(0)

    df["recipients_count"] = (
        S("details.recipients", list)
        .apply(lambda x: len(x) if isinstance(x, list) else 0)
        .where(df["doc_type"].isin(["PRIVACY_POLICY", "DATA_PROTECTION"]), 0)
    )

    df["complaint_authority_present"] = S("details.complaint_authority", False).fillna(False).astype("boolean")

    df["cookie_third_party_count"] = (
        S("details.third_parties", list)
        .apply(lambda x: len(x) if isinstance(x, list) else 0)
        .where(df["doc_type"].eq("COOKIE_POLICY"), 0)
    )
    df["cookie_mgmt_instructions"] = S("details.mgmt_instructions", False).fillna(False).astype("boolean")

    df["cookie_ownership_mixed_doc"] = np.where(
        df["doc_type"].eq("COOKIE_POLICY"),
        S("details.ownership", None).eq("MIXED"),
        False
    )

    df["legal_ip_notice_present"]   = S("details.ip_notice", False).fillna(False).astype("boolean")
    df["legal_liability_present"]   = S("details.liability_clause", False).fillna(False).astype("boolean")

    agg_dom = (
        df.groupby("domain")
          .agg(
              docs                      = ("url", "count"),
              has_privacy               = ("has_privacy", "max"),
              has_cookies               = ("has_cookies", "max"),
              has_legal                 = ("has_legal", "max"),
              has_data_prot             = ("has_data_prot", "max"),
              privacy_controller_present= ("privacy_controller_present", "max"),
              dpo_contact_present       = ("dpo_contact_present", "max"),
              rights_sum                = ("rights_count_rel", "sum"),
              rights_avg_per_doc        = ("rights_count_rel", "mean"),
              rights_general_statement  = ("rights_general_statement", "max"),
              legal_bases_sum           = ("legal_bases_count", "sum"),
              automated_decisions       = ("automated_decisions_present", "max"),
              retention_present         = ("retention_present", "max"),
              recipients_sum            = ("recipients_count", "sum"),
              complaint_authority       = ("complaint_authority_present", "max"),
              cookie_third_party_sum    = ("cookie_third_party_count", "sum"),
              cookie_mgmt_instructions  = ("cookie_mgmt_instructions", "max"),
              cookie_ownership_mixed    = ("cookie_ownership_mixed_doc", "max"),
              legal_ip_notice           = ("legal_ip_notice_present", "max"),
              legal_liability           = ("legal_liability_present", "max"),
              max_transfer_scope_rank   = ("transfer_rank", "max"),
          )
          .reset_index()
    )

    rank_to_scope = {v: k for k, v in SCOPE_RANK.items()}
    agg_dom["transfer_scope"] = agg_dom["max_transfer_scope_rank"].map(rank_to_scope)

    consent = (
        df.loc[df["consent_mechanism_doc"].notna(), ["domain","consent_mechanism_doc"]]
          .drop_duplicates("domain")
          .set_index("domain")["consent_mechanism_doc"]
    )
    agg_dom["consent_mechanism"] = agg_dom["domain"].map(consent)

    agg_dom.replace({"": pd.NA, "null": pd.NA}, inplace=True)
    agg_dom.to_csv(dst, index=False)
    print("Saved", dst)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="documents.jsonl")
    ap.add_argument("--dst", default="domain_metrics.csv")
    main(**vars(ap.parse_args()))
