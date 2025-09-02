import pandas as pd, ast, argparse, pathlib

ap = argparse.ArgumentParser()
ap.add_argument("--summary", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()

df = pd.read_csv(args.summary)

rename = {"canvas":"fp_canvas",
          "audioCtx":"fp_audioCtx",
          "rtc":"fp_rtc",
          "storage":"fp_storage"}
df = df.rename(columns=rename)

for col in rename.values():
    df[col] = df[col].astype(bool).astype(int)

df["fp_methods_total"] = df[list(rename.values())].sum(axis=1)
df["fp_detected"]      = (df["fp_methods_total"] > 0).astype(int)

keep = ["domain","fp_detected","fp_methods_total",
        "fp_canvas","fp_audioCtx","fp_rtc","fp_storage",
        "status","http_status"]
df[keep].to_csv(args.out, index=False)
print(f"OK {args.out} generated ({len(df)} domains)")
