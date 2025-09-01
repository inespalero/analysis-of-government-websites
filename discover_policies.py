from __future__ import annotations

import argparse, re, sys, json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup
from langdetect import detect, LangDetectException
from pydantic import BaseModel

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

LANG_ALIASES = {"es": ("es","es-es","es-mx","es-cl","español"),
  "en": ("en","en-gb","en-au","en-za","en-in","english"),
  "hi": ("hi","hi-in","hindi"),
  "ml": ("ml","ml-in","malayalam","മലയാളം"),}


KEYWORDS_BY_LANG: Dict[str, Dict[str, List[str]]] = {
    "es": {
        "PRIVACY_POLICY":  [r"privacidad"],
        "COOKIE_POLICY":   [r"cookie"],
        "LEGAL_NOTICE":    [r"aviso[-_ ]?legal", r"nota[-_ ]?legal", r"condiciones(?:[-_ ]+de)?[-_ ]+uso", r"t[eé]rminos"],
        "DATA_PROTECTION": [r"protecci[oó]n(?:[-_ ]+de)?[-_ ]+datos", r"lopd", r"rgpd"],
    },
    "en": {
        "PRIVACY_POLICY":  [r"\bprivacy"],
        "COOKIE_POLICY":   [r"\bcookie"],
        "LEGAL_NOTICE":    [r"legal[-_ ]?notice", r"\bterms\s*(?:&|and)?\s*conditions\b", r"\bterms\s+of\s+(?:use|service|access|conditions)\b", r"legals"],
        "DATA_PROTECTION": [r"data[-_ ]?protection", r"gdpr", r"\bpersonal\s+information\s+protection\b", r"\binformation\s+privacy\b"],
    },
    "hi": {
        "PRIVACY_POLICY":  [r"गोपनीयता"],
        "COOKIE_POLICY":   [r"कुकी"],
        "LEGAL_NOTICE":    [r"(नियम|शर्तें)"],
    },
    "ml": {
        "PRIVACY_POLICY":  [r"സ്വകാര്യത"],
        "COOKIE_POLICY":   [r"കുക്കി"],
    },
}

DOC_PRIORITY = ("PRIVACY_POLICY", "COOKIE_POLICY", "DATA_PROTECTION", "LEGAL_NOTICE")

ACTION_EXCLUDE_RX = re.compile(
    r"\b(acept(o|ar|a)|de\s+acuerdo|ok|entendido|continuar|cerrar|permitir|allow|accept|agree|yes|got\s*it|understood)\b",
    re.I | re.U
)

KEYWORD_URL_RX = re.compile(
    r"(privacy|privacidad|protecci[oó]n[-\s_]*de[-\s_]*datos|cookies?|legal|t[eé]rminos|terms|condiciones)",
    re.I | re.U
)

class LinkRecord(BaseModel):
    domain: str
    url: str
    doc_type: str
    anchor_text: str | None = None
    lang: str | None = None

def build_accept_language(lang_grp: str) -> str:
    if lang_grp == "es":
        return "es-ES,es;q=0.9,en;q=0.8"
    if lang_grp == "hi":
        return "hi-IN,hi;q=0.9,en;q=0.8"
    if lang_grp == "ml":
        return "ml-IN,ml;q=0.9,en;q=0.8"
    return "en-GB,en;q=0.9,es;q=0.7"

def fetch(url: str, lang_grp: str = "en", timeout: int = 20) -> Tuple[Optional[str], Optional[str], str]:
    headers = {
        "User-Agent": UA,
        "Accept-Language": build_accept_language(lang_grp),
    }
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if r.ok and "text/html" in r.headers.get("Content-Type", "").lower():
            return r.text, r.url, r.headers.get("Content-Type", "")
    except requests.RequestException:
        pass
    return None, None, ""

def normalize_url(u: str) -> str:
    try:
        p = urlparse(u)
        q = parse_qs(p.query, keep_blank_values=False)
        q_clean = {k: v for k, v in q.items() if not k.lower().startswith(("utm_", "fbclid", "gclid"))}
        new_query = urlencode([(k, vv) for k, vs in q_clean.items() for vv in vs])
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))
    except Exception:
        return u.split("#", 1)[0]

def detect_language_from_html(soup: BeautifulSoup, fallback_text: str = "") -> str:
    declared = ""
    if soup and soup.html:
        declared = (soup.html.get("lang") or soup.html.get("xml:lang") or "").strip().lower()
    if not declared:
        meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-language"})
        if meta:
            declared = (meta.get("content") or "").split(",")[0].strip().lower()

    for grp, aliases in LANG_ALIASES.items():
        if declared and any(declared.startswith(a) for a in aliases):
            return grp

    text = fallback_text or (soup.get_text(" ", strip=True)[:2000] if soup else "")
    try:
        guess = detect(text) if text else ""
    except LangDetectException:
        guess = ""
    for grp, aliases in LANG_ALIASES.items():
        if guess and any(guess.startswith(a.split("-")[0]) for a in aliases):
            return grp
    return "en"

def patterns_for_lang(lang_grp: str) -> Dict[str, List[re.Pattern]]:
    pats = {}
    for doc_type, lst in KEYWORDS_BY_LANG.get(lang_grp, {}).items():
        pats[doc_type] = [re.compile(p, re.I | re.U) for p in lst]
    return pats

def classify_src(src: str, lang_grp: str) -> Optional[str]:
    pats = patterns_for_lang(lang_grp)
    hits = set()
    for dt in pats:
        if any(rx.search(src) for rx in pats[dt]):
            hits.add(dt)
    if not hits:
        pats_en = patterns_for_lang("en")
        for dt in pats_en:
            if any(rx.search(src) for rx in pats_en[dt]):
                hits.add(dt)
    for dt in DOC_PRIORITY:
        if dt in hits:
            return dt
    return None

def fetch_render(url: str, lang_grp: str = "en", timeout: int = 30) -> Tuple[Optional[str], Optional[str]]:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except Exception:
        return None, None

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        page = browser.new_page(extra_http_headers={"Accept-Language": build_accept_language(lang_grp)})
        try:
            page.goto(url, wait_until="load", timeout=timeout * 1000)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1200)
            html = page.content()
            final = page.url
        except Exception:
            html, final = None, None
        browser.close()
        return html, final


def extract_links_and_candidates(base_url: str, html: str, lang_grp: str, save_html_dir: Optional[Path], domain: str, debug: bool=False) -> List[LinkRecord]:
    soup = BeautifulSoup(html, "lxml")
    text_for_lang = soup.get_text(" ", strip=True)[:4000] if soup else ""
    lang = detect_language_from_html(soup, text_for_lang) or lang_grp

    seen_urls = set()
    records: List[LinkRecord] = []

    def maybe_add(abs_url: str, anchor_text: str, lang_guess: str, src: str):
        if not abs_url.lower().startswith(("http://", "https://")):
            return
        abs_url_norm = normalize_url(abs_url)
        if abs_url_norm in seen_urls:
            return
        doc_type = classify_src(src, lang_guess)
        if not doc_type:
            return
        seen_urls.add(abs_url_norm)
        rec = LinkRecord(domain=domain, url=abs_url_norm, doc_type=doc_type,
                         anchor_text=anchor_text or None, lang=lang_guess)
        records.append(rec)

        if save_html_dir:
            body, final_url, ctype = fetch(abs_url_norm, lang_guess)
            if body:
                dest = save_html_dir / domain / doc_type
                dest.mkdir(parents=True, exist_ok=True)
                fname = (urlparse(final_url or abs_url_norm).path.strip("/") or "index").replace("/", "_") + ".html"
                (dest / fname).write_text(body, encoding="utf-8")

    parsed_base = urlparse(base_url)
    base_root = f"{parsed_base.scheme}://{parsed_base.netloc}/"

    for el in soup.select("a, [role=link], button, [role=button]"):
        href = el.get("href") or el.get("data-href") or ""
        if not href:
            onclick = (el.get("onclick") or "").strip()
            m = re.search(r"location\.href\s*=\s*['\"](.*?)['\"]", onclick, re.I)
            if m:
                href = m.group(1)

        href = (href or "").strip()
        if not href:
            continue

        anchor = " ".join(el.stripped_strings).strip()
        aria = (el.get("aria-label") or "").strip()
        title = (el.get("title") or "").strip()
        label  = (anchor or aria or title or "").strip()

        if label and ACTION_EXCLUDE_RX.search(label):
            continue

        low = href.lower()
        if (not href or
            low in {"#", "/", "#0", "#!", "#?","javascript:;", "javascript:void(0)", "javascript:void(0);"} or
            low.startswith("javascript:")):
            continue

        if low.startswith(("mailto:", "tel:", "callto:")):
            continue

        abs_url = urljoin(base_url, href)
        abs_url_norm = normalize_url(abs_url)

        if abs_url_norm.rstrip("/") == base_root.rstrip("/"):
            if not (href.startswith("#") and KEYWORD_URL_RX.search(href)):
                continue

        src = " ".join([
            abs_url_norm.lower(),
            (anchor or "").lower(),
            aria.lower(),
            title.lower(),
        ])

        maybe_add(abs_url_norm, label, lang, src)

    if debug:
        print(f"- {len(records)} detected links ({domain}, lang={lang})")
    return records

def _start_urls_from_input(domain_or_url: str) -> List[str]:
    dom = domain_or_url.strip()
    if dom.startswith(("http://", "https://")):
        return [dom]
    return [f"https://{dom}/", f"http://{dom}/"]

def discover_for_domain(domain_or_url: str, save_html_dir: Path | None = None, use_render: bool = False, debug=False) -> List[LinkRecord]:
    html, base = None, None
    for start in _start_urls_from_input(domain_or_url):
        html, base, _ = fetch(start, "en")
        if html and base:
            break
    if not html or not base:
        if debug:
            print(f"[discover] could not access {domain_or_url}", file=sys.stderr)
        return []

    recs = extract_links_and_candidates(base, html, "en", save_html_dir, domain_or_url, debug)

    if use_render and len(recs) < 2:
        if debug:
            print("render JS (SPA heuristics)")
        html2, base2 = fetch_render(base, "en")
        if html2 and base2:
            more = extract_links_and_candidates(base2, html2, "en", save_html_dir, domain_or_url, debug)
            seen = {(r.url, r.doc_type) for r in recs}
            for r in more:
                if (r.url, r.doc_type) not in seen:
                    recs.append(r); seen.add((r.url, r.doc_type))

    return recs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--save-html")
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--debug", action="store_true")
    ns = ap.parse_args()

    out_path = Path(ns.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_dir = Path(ns.save_html) if ns.save_html else None

    total = 0
    with out_path.open("w", encoding="utf-8") as fout, open(ns.domains, encoding="utf-8") as fdom:
        for i, line in enumerate(fdom, 1):
            dom = line.strip();
            if not dom or dom.startswith("#"):
                continue
            if ns.debug:
                print(f"[{i}] {dom}")
            try:
                records = discover_for_domain(dom, save_dir, ns.render, ns.debug)
            except Exception as e:
                if ns.debug:
                    print(f"ERROR discover {dom}: {e}", file=sys.stderr)
                records = []

            for rec in records:
                fout.write(json.dumps(rec.model_dump(), ensure_ascii=False) + "\n")
                total += 1

    print(f"OK {total} links --> {out_path}")

if __name__ == "__main__":
    main()
