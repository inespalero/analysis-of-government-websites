import pandas as pd, argparse, pathlib, sys

DOMAIN_COLS = ["cookie_domain", "req_domain", "domain", "host"]

def find_domain_col(df):
    for c in DOMAIN_COLS:
        if c in df.columns:
            return c
    sys.exit(f"ERROR Could not find any column {DOMAIN_COLS}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input",   required=True)
    ap.add_argument("--mapping", required=True)
    ap.add_argument("--out",     required=True)
    args = ap.parse_args()

    df  = pd.read_csv(args.input)
    map = pd.read_csv(args.mapping)

    dom_col = find_domain_col(df)
    df["__dom"]  = df[dom_col].str.lower().fillna("")
    map["__dom"] = map["domain"].str.lower()

    out = df.merge(
        map[["__dom", "owner", "categ", "default", "prevalence", "fingerprinting"]],
        on="__dom",
        how="left"
    ).drop(columns="__dom")

    out.to_csv(args.out, index=False)
    hits = out["owner"].notna().sum()
    print(f"OK enriched → {args.out}   ({hits:,} coincidences)")

if __name__ == "__main__":
    main()
