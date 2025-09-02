from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd

import re

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
    "x-frame-options",
    "x-content-type-options",
]

VIOLATION_COLS = {
    "cookie_session_only": "ok_cookie_session_only",
    "no_tracking_claim": "ok_no_tracking_claim",
}

ROBUST_METRICS = ["cookies_total", "tracker_hit_ratio", "total_sec_headers"]

def load_data(data_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    try:
        domains = pd.read_csv(data_dir / "domains_agg.csv")
        master = pd.read_csv(data_dir / "master_dataset.csv")
        compliance = pd.read_csv(data_dir / "compliance_report.csv")
    except FileNotFoundError as e:
        raise SystemExit(f"[ERROR] Couldn't find file: {e.filename}. "
                         "Verify --data-dir or project's structure.") from None
    return domains, master, compliance


def norm_domain(s: str) -> str:
    if not isinstance(s, str):
        return s
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    s = s[4:] if s.startswith("www.") else s
    return s

def build_domain_metrics(
    domains: pd.DataFrame, master: pd.DataFrame, compliance: pd.DataFrame) -> pd.DataFrame:

    domains["domain"]    = domains["domain"].apply(norm_domain)
    master["domain"]     = master["domain"].apply(norm_domain)
    compliance["domain"] = compliance["domain"].apply(norm_domain)

    d_cols = [
        "domain",
        "has_privacy",
        "has_cookies",
        "has_legal",
        "has_data_prot",
        "privacy_controller_present",
        "dpo_contact_present",
        "rights_sum",
        "legal_bases_sum",
        "retention_present",
        "recipients_sum",
        "transfer_scope",
        "consent_mechanism",
    ]

    m_cols = [
        "domain",
        "cookies_total",
        "cookies_3p_ratio",
        "cookies_session_ratio",
        "tracker_hit_ratio",
        "req_3p_ratio",
        "req_3p_top",
        "total_sec_headers",
        *SECURITY_HEADERS,
        "tls_version_max",
        "tls_days_until_expiry",
        "tls_cipher_fs_ratio",
        "tls_cipher_weak_ratio",
    ]

    comp_cols = [col for col in compliance.columns if col.startswith("ok_")]

    c_cols = [
        "domain",
        "compliance_score",
        "matches",
        "violations",
        "possible_transfer_violation",
        *comp_cols,
    ]

    df = (
        domains[d_cols]
        .merge(master[m_cols], on="domain", how="left")
        .merge(compliance[c_cols], on="domain", how="left")
    )

    df["rights_pct"] = df["rights_sum"] / 7.0
    df["security_score"] = df[SECURITY_HEADERS].sum(axis=1)
    df["security_score_pct"] = df["security_score"] / len(SECURITY_HEADERS)

    return df


def summarise_dataset(df: pd.DataFrame) -> Dict[str, float]:

    summary = {

        "pct_privacy_policy": df["has_privacy"].mean(),
        "pct_cookie_policy": df["has_cookies"].mean(),
        "pct_legal_notice": df["has_legal"].mean(),
        "pct_data_protect_clause": df["has_data_prot"].mean(),
        "pct_controller_present": df["privacy_controller_present"].mean(),
        "pct_dpo_contact": df["dpo_contact_present"].mean(),
        "rights_pct_mean": df["rights_pct"].mean(),
        "rights_pct_std": df["rights_pct"].std(ddof=0),
        "pct_has_legal_basis": (df["legal_bases_sum"] > 0).mean(),
        "pct_has_retention": df["retention_present"].mean(),
        "pct_has_recipients": (df["recipients_sum"] > 0).mean(),

        "cookies_total_mean": df["cookies_total"].mean(),
        "cookies_3p_ratio_mean": df["cookies_3p_ratio"].mean(),
        "cookies_session_ratio_mean": df["cookies_session_ratio"].mean(),
        "tracker_hit_ratio_mean": df["tracker_hit_ratio"].mean(),
        "req_3p_ratio_mean": df["req_3p_ratio"].mean(),

        "total_sec_headers_mean": df["total_sec_headers"].mean(),
        "security_score_mean": df["security_score"].mean(),
        **{f"pct_{h}": df[h].mean() for h in SECURITY_HEADERS},
        "tls_days_until_expiry_median": df["tls_days_until_expiry"].median(),
        "tls_cipher_fs_ratio_mean": df["tls_cipher_fs_ratio"].mean(),
        "tls_cipher_weak_ratio_mean": df["tls_cipher_weak_ratio"].mean(),

        "compliance_score_mean": df["compliance_score"].mean(),
        "possible_transfer_violation_pct": df["possible_transfer_violation"].mean(),
    }


    for col in [c for c in df.columns if c.startswith("ok_")]:
        label = VIOLATION_COLS.get(col, col.replace("ok_", ""))
        summary[f"violation_{label}_count"] = (df[col] == False).sum()

    for metric in ROBUST_METRICS:
        summary[f"{metric}_median"] = df[metric].median()
        summary[f"{metric}_iqr"] = df[metric].quantile(0.75) - df[metric].quantile(0.25)
        cv = df[metric].std(ddof=0) / (df[metric].mean() or 1)
        summary[f"{metric}_cv"] = cv
        summary[f"{metric}_high_cv"] = cv > 1


    return summary


def summarise_consent(df: pd.DataFrame) -> pd.Series:
    df["consent_mechanism"] = df["consent_mechanism"].fillna("unknown")
    return df["consent_mechanism"].value_counts(normalize=True, dropna=False)


def _json_serial(obj):
    if isinstance(obj, (np.integer, np.floating)):
        return obj.item()
    if isinstance(obj, (pd.Timestamp,)):
        return obj.isoformat()
    return str(obj)


def main():
    parser = argparse.ArgumentParser()
    default_data_dir = Path(__file__).resolve().parents[1] / "datasets"
    default_out_dir = Path(__file__).resolve().parents[1] / "output"

    parser.add_argument("--data-dir", type=Path, default=default_data_dir)
    parser.add_argument("--out-dir", type=Path, default=default_out_dir)

    args = parser.parse_args()

    args.out_dir.mkdir(exist_ok=True, parents=True)

    domains, master, compliance = load_data(args.data_dir)
    df_metrics = build_domain_metrics(domains, master, compliance)


    df_metrics.to_csv(args.out_dir / "domain_metrics.csv", index=False)


    summary = summarise_dataset(df_metrics)
    consent_dist = summarise_consent(df_metrics)

    with open(args.out_dir / "aggregated_metrics.json", "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "consent_distribution": consent_dist.to_dict()}, fh,
                  indent=2, ensure_ascii=False, default=_json_serial)


    pd.options.display.float_format = "{:.2%}".format

    print("\n===== Summary =====")
    for k, v in summary.items():
        if k.startswith("pct_") or k.endswith("_ratio_mean"):
            print(f"{k:40s}: {float(v):.2%}")
        elif k.startswith("violation_"):
            print(f"{k:40s}: {int(v)}")
        else:
            print(f"{k:40s}: {float(v):.2f}")

    print("\n===== Consent mechanisms' distribution =====")
    for k, v in consent_dist.items():
        print(f"{k or 'None'}: {v:.2%}")


if __name__ == "__main__":
    main()
