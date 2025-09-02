import json, csv, pathlib, argparse, re, datetime as dt

def flatten(path: pathlib.Path) -> dict:
    domain = path.stem.replace("_", ".")
    try:
        data = json.loads(path.read_text())
        res = data["server_scan_results"][0]
        scan = res.get("scan_result", {})

        tls_version = res.get("connectivity_result", {}).get("highest_tls_version_supported", "")

        cert_info = scan.get("certificate_info", {})
        cert_result = cert_info.get("result")
        if not cert_result:
            raise ValueError("No certificate result")

        deployments = cert_result.get("certificate_deployments")
        if not deployments:
            raise ValueError("No certificate deployments")

        leaf = deployments[0]["received_certificate_chain"][0]
        issuer = deployments[0]["received_certificate_chain"][-1].get("issuer", {}).get("rfc4514_string", "")
        pub_key = leaf.get("public_key", {})
        key_alg = pub_key.get("algorithm", "")
        key_size = pub_key.get("key_size", 0)
        curve = pub_key.get("ec_curve_name", "")
        not_after = dt.datetime.fromisoformat(leaf["not_valid_after"].replace("Z", "+00:00"))
        days_left = (not_after - dt.datetime.now(dt.timezone.utc)).days

        suites = []
        suites_fs = []
        for ver in ["tls_1_3_cipher_suites", "tls_1_2_cipher_suites"]:
            cs_block = scan.get(ver, {})
            accepted = cs_block.get("result", {}).get("accepted_cipher_suites", [])
            for c in accepted:
                name = c["cipher_suite"]["name"]
                suites.append(name)
                if "ECDHE" in name or "DHE" in name:
                    suites_fs.append(name)

        WEAK_PAT = re.compile(r"RC4|3DES|DES|NULL|EXPORT|MD5|PSK|ADH|ANON", re.I)
        IS_FS   = ("ECDHE", "DHE")
        TLS13_OK = ("TLS_AES_", "TLS_CHACHA20_")

        weak = [
            s for s in suites
            if (
                WEAK_PAT.search(s)
                or (
                    not any(k in s for k in IS_FS)
                    and not s.startswith(TLS13_OK)
                )
            )
        ]

        headers = scan.get("http_headers", {}).get("result", {})
        hsts = headers.get("strict_transport_security_header")
        hsts_flag = 1 if hsts else 0

        return {
            "domain": domain,
            "tls_error": "",
            "tls_version_max": tls_version,
            "tls_key_alg": key_alg,
            "tls_key_size": key_size,
            "tls_curve": curve,
            "tls_cert_issuer": issuer,
            "tls_days_until_expiry": days_left,
            "tls_cipher_suites_total": len(suites),
            "tls_cipher_suites_fs": len(suites_fs),
            "tls_cipher_suites_list": ";".join(suites),
            "tls_cipher_suites_weak": len(weak),
            "tls_cipher_weak_list": ";".join(weak),
            "tls_hsts": hsts_flag,
        }

    except Exception as e:
        return {
            "domain": domain,
            "tls_error": f"certinfo_error ({e})",
            "tls_version_max": "",
            "tls_key_alg": "",
            "tls_key_size": 0,
            "tls_curve": "",
            "tls_cert_issuer": "",
            "tls_days_until_expiry": 0,
            "tls_cipher_suites_total": 0,
            "tls_cipher_suites_fs": 0,
            "tls_cipher_suites_list": "",
            "tls_cipher_suites_weak": 0,
            "tls_cipher_weak_list": "",
            "tls_hsts": 0,
        }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = [flatten(p) for p in pathlib.Path(args.indir).glob("*.json")]
    cols = [
        "domain", "tls_error", "tls_version_max", "tls_key_alg", "tls_key_size",
        "tls_curve", "tls_cert_issuer", "tls_days_until_expiry",
        "tls_cipher_suites_total", "tls_cipher_suites_fs",
        "tls_cipher_suites_list", "tls_cipher_suites_weak", "tls_cipher_weak_list", "tls_hsts"
    ]

    pathlib.Path(args.out).parent.mkdir(exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        writer.writerows(rows)

    print(f"OK flat TLS --> {args.out} ({len(rows)} domains)")

if __name__ == "__main__":
    main()
