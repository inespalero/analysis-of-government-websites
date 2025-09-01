import random, os, argparse
from pathlib import Path
from datetime import datetime
from openwpm.command_sequence import CommandSequence
from openwpm.commands.browser_commands import GetCommand
from openwpm.config import BrowserParams, ManagerParams
from openwpm.storage.sql_provider import SQLiteStorageProvider
from openwpm.task_manager import TaskManager

ap = argparse.ArgumentParser()
ap.add_argument("--input",  required=True)
ap.add_argument("--outdir", required=True)
ap.add_argument("--append", action="store_true")
args = ap.parse_args()

ROOT = Path.home() / "tfm_project"
URLS = Path(args.input).expanduser()
DDIR = Path(args.outdir).expanduser()
DB   = DDIR / "openwpm.sqlite"
LOG  = DDIR / "openwpm.log"
DDIR.mkdir(parents=True, exist_ok=True)
if DB.exists() and not args.append:
    DB.unlink()

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
VIEWPORT_POOL = ["1920x1080", "1366x768", "1440x900"]

def load_sites(path: Path) -> list[str]:
    sites = []
    for l in path.read_text(encoding="utf-8").splitlines():
        l = l.strip()
        if not l: continue
        if not l.startswith(("http://", "https://")):
            l = "https://" + l
        if not l.endswith("/"): l += "/"
        sites.append(l)
    return sites

sites = load_sites(URLS)
if not sites:
    raise SystemExit(f"Could not find URLs in {URLS}")

NUM_BROWSERS = 1
mp = ManagerParams(num_browsers=NUM_BROWSERS)
mp.data_directory = DDIR
mp.log_path       = LOG
mp.memory_watchdog  = True
mp.process_watchdog = True
mp.no_instrument_cache_reset = False

bp = BrowserParams(display_mode="headless")
bp.user_agent              = random.choice(UA_POOL)
bp.viewport                = random.choice(VIEWPORT_POOL)
bp.http_instrument         = True
bp.cookie_instrument       = True
bp.navigation_instrument   = True
bp.js_instrument           = True
bp.js_instrument_settings  = {"collection_fingerprinting": True}
#bp.callstack_instrument    = True
bp.dns_instrument          = True
bp.save_content            = False
bp.maximum_profile_size    = 75 * (2**20)
browsers = [bp]

def banner(msg): print(f"\n=== {msg} ===")

with TaskManager(mp, browsers, SQLiteStorageProvider(DB), None) as m:
    for rank, url in enumerate(sites):

        def cb(ok: bool, tgt=url):
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"[{ts}] {tgt}  →  {'OK' if ok else 'FAIL'}")

        cs = CommandSequence(url, site_rank=rank, callback=cb)
        cs.append_command(GetCommand(url=url, sleep=4), timeout=90)
        m.execute_command_sequence(cs)


banner(f"END · SQLite en {DB}")
