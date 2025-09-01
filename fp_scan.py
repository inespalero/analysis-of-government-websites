import asyncio, json, argparse, random
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from tqdm.asyncio import tqdm
from playwright.async_api import async_playwright

JS_SNIPPET = """
// === Pre-Page-Load instrumentation ===
window.__FP_FLAGS = {canvas:false,audioCtx:false,rtc:false,storage:false};

// Canvas
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(){
    window.__FP_FLAGS.canvas = true;
    return origToDataURL.apply(this, arguments);
};

// Audio
['OscillatorNode','AudioContext','OfflineAudioContext'].forEach(cls=>{
  const proto = window[cls]?.prototype;
  if (proto && proto.start){
      const orig = proto.start;
      proto.start = function(){
          window.__FP_FLAGS.audioCtx = true;
          return orig.apply(this, arguments);
      };
  }
});

// WebRTC
const origRTCPeer = window.RTCPeerConnection;
if (origRTCPeer){
  window.RTCPeerConnection = function(...args){
      window.__FP_FLAGS.rtc = true;
      return new origRTCPeer(...args);
  }
}

// Storage (localStorage / sessionStorage)
['localStorage','sessionStorage'].forEach(store=>{
  const origSet = Storage.prototype.setItem;
  Storage.prototype.setItem = function(k,v){
      window.__FP_FLAGS.storage = true;
      return origSet.call(this,k,v);
  };
});
"""

def _to_url_and_host(target: str):
    s = target.strip()
    url = s if s.startswith(("http://","https://")) else f"https://{s}"
    host = (urlparse(url).hostname or "").lower()
    return url, host

async def scan_domain(page, target, timeout):
    url, main_host = _to_url_and_host(target)

    third_party = set()
    page.on("request", lambda r: third_party.add(urlparse(r.url).hostname or ""))

    await page.add_init_script(JS_SNIPPET)

    try:
        resp = await page.goto(url, timeout=timeout*1000)
        status = resp.status if resp else 0
    except Exception as e:
        return {"domain": main_host or target, "status": f"ERROR {e}"}

    cookies = await page.context.cookies()
    fp_flags = await page.evaluate("window.__FP_FLAGS")

    tps = sorted({h for h in third_party if h and h != main_host})

    def cookie_host(c):
        d = (c.get("domain","") or "").lstrip(".").lower()
        return d

    tp_cookies = [c for c in cookies if (cookie_host(c) and cookie_host(c) != main_host)]


    return {
        "domain": main_host,
        "status": "OK",
        "http_status": status,
        "third_party_domains": tps,
        "third_party_cookies": tp_cookies,
        **fp_flags
    }

async def main_async(args):
    domains = [d.strip() for d in Path(args.input).read_text().splitlines() if d.strip()]
    out_dir = Path(args.output); out_dir.mkdir(parents=True, exist_ok=True)

    sem = asyncio.Semaphore(args.workers)
    results = []

    async with async_playwright() as p:
        browser = await p.firefox.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)

        async def worker(domain):
            async with sem:
                page = await context.new_page()
                res = await scan_domain(page, domain, args.timeout)
                await page.close()
                if res["status"] == "OK":
                    safe_name = res["domain"].replace(".", "_")
                    jpath = out_dir / f"{safe_name}.json"
                    jpath.write_text(json.dumps(res, indent=2, ensure_ascii=False))
                results.append(res)

        await tqdm.gather(*(worker(d) for d in domains))

    df = pd.DataFrame(results)
    df.to_csv(out_dir / "summary_fp.csv", index=False)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-i","--input", required=True)
    ap.add_argument("-o","--output")
    ap.add_argument("-w","--workers", type=int, default=4)
    ap.add_argument("-t","--timeout", type=int, default=40)
    args = ap.parse_args()
    asyncio.run(main_async(args))
    print(f"OK FP-scan finished --> {args.output}/summary_fp.csv")
