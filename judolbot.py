#!/usr/bin/env python3
"""judolbot: kumpulkan, verifikasi, dan bangun blocklist domain judi online.

Perintah:
  python judolbot.py run         # collect -> verify -> build (dipakai GitHub Actions)
  python judolbot.py collect     # kumpulkan kandidat domain
  python judolbot.py verify      # cek DNS + isi halaman, prune domain mati
  python judolbot.py build       # tulis ulang file di lists/
  python judolbot.py add-issue   # ambil domain dari isi GitHub Issue (env ISSUE_BODY)
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import sys
import time
from html import unescape
from pathlib import Path
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
import tldextract
import urllib3

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent
DATA, LISTS = ROOT / "data", ROOT / "lists"
DB_PATH = DATA / "db.json"
CFG = json.loads((ROOT / "config.json").read_text("utf-8"))

NOW = dt.datetime.now(dt.timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")
UA = "Mozilla/5.0 (compatible; judolbot/1.0; +https://github.com/GregOliv)"
HEADERS = {"User-Agent": UA, "Accept-Language": "id,en;q=0.8"}

EXT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def term_re(t: str) -> re.Pattern:
    return re.compile(r"\b" + r"\s+".join(map(re.escape, t.lower().split())) + r"\b")


STRONG = [term_re(t) for t in CFG["strong_terms"]]
WEAK = [term_re(t) for t in CFG["weak_terms"]]
NAME_RE = re.compile("|".join(map(re.escape, CFG["name_terms"])))
REDIRECT_RE = re.compile(
    r"""(?:location(?:\.href)?\s*=\s*|location\.(?:replace|assign)\(\s*|window\.open\(\s*|"""
    r"""http-equiv=["']refresh["'][^>]*url=)["']?(https?://[^"'\s<>)]+)""",
    re.I,
)

RES = dns.resolver.Resolver(configure=False)
RES.nameservers = ["8.8.8.8", "1.1.1.1"]  # resolver publik: tidak ikut memblokir judol
RES.lifetime = 5


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- utilitas
def norm(name: str) -> str:
    name = name.strip().lower().rstrip(".")
    name = re.sub(r"^\*\.", "", name)
    return name if name.isascii() else name.encode("idna").decode()


def reg_domain(name: str) -> str | None:
    """Kembalikan domain terdaftar (eTLD+1). Hosting bersama seperti x.blogspot.com dijaga utuh."""
    try:
        name = norm(name)
    except Exception:
        return None
    if not DOMAIN_RE.match(name):
        return None
    e = EXT(name)
    d = getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain
    return d or None


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def covered(domain: str, blocked: set[str]) -> bool:
    """True jika domain atau salah satu domain induknya ada di himpunan."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in blocked for i in range(len(parts) - 1))


def protected(domain: str) -> bool:
    return any(domain.endswith(s) for s in CFG["protected_suffixes"])


def name_hit(domain: str) -> bool:
    return bool(NAME_RE.search(domain))


def load_db() -> dict:
    return json.loads(DB_PATH.read_text("utf-8")) if DB_PATH.exists() else {}


def save_db(db: dict) -> None:
    rows = [
        f"{json.dumps(k)}:{json.dumps(v, ensure_ascii=False, separators=(',', ':'), sort_keys=True)}"
        for k, v in sorted(db.items())
    ]
    DB_PATH.write_text("{\n" + ",\n".join(rows) + "\n}\n", "utf-8")


def fetch_text(url: str, timeout: int = 60) -> str:
    r = requests.get(url, timeout=timeout, headers=HEADERS)
    r.raise_for_status()
    return r.text


def parse_list(text: str) -> set[str]:
    """Baca daftar format domain polos, hosts, atau adblock."""
    out = set()
    pat = re.compile(r"^(?:0\.0\.0\.0\s+|127\.0\.0\.1\s+)?(?:\|\|)?([a-z0-9._*-]+)\^?(?:\$.*)?$")
    for line in text.lower().splitlines():
        line = line.strip()
        if not line or line[0] in "!#[":
            continue
        m = pat.match(line)
        if m:
            name = m.group(1).lstrip("*.")
            if DOMAIN_RE.match(name):
                out.add(name)
    return out


def load_upstream() -> set[str]:
    known: set[str] = set()
    for url in CFG["upstream_lists"]:
        try:
            got = parse_list(fetch_text(url))
            log(f"  upstream {len(got):>7} domain <- {url}")
            known |= got
        except Exception as e:  # sumber boleh gagal tanpa menghentikan proses
            log(f"  ! gagal ambil {url}: {e}")
    return known


# ---------------------------------------------------------------- collect
def cmd_collect() -> None:
    log("== COLLECT ==")
    db = load_db()
    wl = set(read_lines(DATA / "whitelist.txt"))
    known = load_upstream()
    added = 0
    limit = CFG["max_new_candidates"]

    def add(name: str, src: str, force: bool = False) -> None:
        nonlocal added
        d = reg_domain(name)
        if not d or covered(d, wl) or covered(d, known):
            return
        if d in db:
            if force and db[d]["status"] in ("dead", "reject"):
                db[d] = {"status": "candidate", "source": src, "first_seen": TODAY}
                added += 1
            return
        if added >= limit:
            return
        db[d] = {"status": "candidate", "source": src, "first_seen": TODAY}
        added += 1

    # 1) laporan manual / issue
    cand_file = DATA / "candidates.txt"
    if cand_file.exists():
        for line in cand_file.read_text("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            dom, _, src = line.partition("\t")
            add(dom, src or "manual", force=True)
        cand_file.write_text("# domain<TAB>sumber  (diisi otomatis dari GitHub Issues; boleh isi manual)\n", "utf-8")
    log(f"  manual/issue: total kandidat baru {added}")

    # 2) daftar kandidat tambahan (harus lolos verifikasi)
    for url in CFG["candidate_lists"]:
        try:
            for d in parse_list(fetch_text(url)):
                add(d, "list:" + urlparse(url).netloc)
        except Exception as e:
            log(f"  ! gagal ambil {url}: {e}")

    # 3) CertStream (mendengarkan sertifikat TLS baru beberapa menit)
    cs = CFG["certstream"]
    if cs["enabled"]:
        collect_certstream(cs, add)

    # 4) crt.sh (pencarian kata kunci spesifik)
    cr = CFG["crtsh"]
    if cr["enabled"]:
        collect_crtsh(cr, add)

    # hapus entri kedaluwarsa
    expire(db)
    save_db(db)
    log(f"  kandidat baru total: {added}")


def collect_certstream(cfg: dict, add) -> None:
    try:
        import websocket
    except ImportError:
        log("  ! websocket-client belum terpasang, CertStream dilewati")
        return
    end = time.time() + cfg["seconds"]
    seen: set[str] = set()
    n = 0
    try:
        ws = websocket.create_connection(cfg["url"], timeout=15)
        ws.settimeout(15)
        while time.time() < end:
            try:
                msg = ws.recv()
            except websocket.WebSocketTimeoutException:
                continue
            if not NAME_RE.search(msg):  # saring murah sebelum parse JSON
                continue
            try:
                names = json.loads(msg)["data"]["leaf_cert"]["all_domains"]
            except Exception:
                continue
            for name in names:
                d = reg_domain(name)
                if d and d not in seen and name_hit(d):
                    seen.add(d)
                    add(d, "certstream")
                    n += 1
        ws.close()
    except Exception as e:
        log(f"  ! CertStream gagal: {e}")
    log(f"  certstream: {n} domain cocok kata kunci")


def collect_crtsh(cfg: dict, add) -> None:
    cutoff = NOW - dt.timedelta(days=cfg["lookback_days"])
    for kw in cfg["keywords"]:
        rows = []
        for attempt in range(2):
            try:
                r = requests.get(
                    "https://crt.sh/",
                    params={"q": f"%{kw}%", "output": "json", "exclude": "expired", "deduplicate": "Y"},
                    timeout=90,
                    headers=HEADERS,
                )
                r.raise_for_status()
                rows = r.json()
                break
            except Exception as e:
                log(f"  ! crt.sh '{kw}' percobaan {attempt + 1} gagal: {e}")
                time.sleep(5)
        n = 0
        for row in rows[:20000]:
            try:
                nb = dt.datetime.fromisoformat(row["not_before"][:19]).replace(tzinfo=dt.timezone.utc)
            except Exception:
                continue
            if nb < cutoff:
                continue
            for name in row.get("name_value", "").split("\n"):
                d = reg_domain(name)
                if d and name_hit(d):
                    add(d, "crt.sh")
                    n += 1
        log(f"  crt.sh '{kw}': {n} hit")
        time.sleep(cfg["sleep"])


def expire(db: dict) -> None:
    days = CFG["expire_days"]

    def before(n: int) -> str:
        return (NOW - dt.timedelta(days=n)).strftime("%Y-%m-%d")

    for d, v in list(db.items()):
        st = v["status"]
        ref = v.get("last_checked") or v.get("first_seen", TODAY)
        if st in days and ref < before(days[st]):
            del db[d]


# ---------------------------------------------------------------- verify
def dns_status(domain: str) -> str:
    for rtype in ("A", "AAAA"):
        try:
            RES.resolve(domain, rtype)
            return "alive"
        except dns.resolver.NXDOMAIN:
            return "nxdomain"
        except dns.resolver.NoAnswer:
            continue
        except Exception:
            return "error"
    return "nodata"


def is_public(host: str) -> bool:
    """Tolak IP privat/loopback/link-local supaya runner tidak dipakai menyerang jaringan internal."""
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(host, None)}
        return bool(ips) and all(ipaddress.ip_address(i).is_global for i in ips)
    except (OSError, ValueError):
        return False


def fetch_page(domain: str):
    """Ambil halaman depan. Kembalikan (url_akhir, html, status) atau None."""
    max_hops = CFG["verify"]["max_redirects"]
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            for _ in range(max_hops + 1):
                host = urlparse(url).hostname
                if not host or not is_public(host):
                    return None
                r = requests.get(url, headers=HEADERS, timeout=(5, 8), allow_redirects=False,
                                 stream=True, verify=False)
                loc = r.headers.get("location")
                if r.status_code in (301, 302, 303, 307, 308) and loc:
                    url = urljoin(url, loc)
                    r.close()
                    continue
                body = r.raw.read(CFG["verify"]["max_bytes"], decode_content=True)
                status = r.status_code
                enc = r.encoding or "utf-8"
                r.close()
                return url, body.decode(enc, errors="ignore"), status
        except requests.RequestException:
            continue
        except Exception:
            continue
    return None


def score_page(domain: str, html: str):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", unescape(m.group(1))).strip() if m else ""
    metas = []
    for tag in re.findall(r"<meta\b[^>]*>", html, re.I):
        if re.search(r'(name|property)=["\'](description|keywords|og:title|og:description)["\']', tag, re.I):
            c = re.search(r'content=["\']([^"\']*)', tag, re.I)
            if c:
                metas.append(unescape(c.group(1)))
    body = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", html, flags=re.I | re.S)
    body = unescape(re.sub(r"<[^>]+>", " ", body))
    head = f"{title} {' '.join(metas)}".lower()
    hay = f"{head} {body.lower()}"

    score, strong, hits = 0, 0, []
    for rx in STRONG:
        if rx.search(hay):
            strong += 1
            score += 3 + (2 if rx.search(head) else 0)
            hits.append(rx.pattern.replace("\\s+", " ").replace("\\b", ""))
    for rx in WEAK:
        if rx.search(hay):
            score += 1
    if name_hit(domain):
        score += 2
    return score, title[:120], hits[:6], strong


def redirect_targets(domain: str, final_url: str, html: str) -> list[str]:
    found = []
    cands = [final_url] + REDIRECT_RE.findall(html)
    for u in cands:
        host = urlparse(u).hostname
        d = reg_domain(host) if host else None
        if d and d != domain and d not in found:
            found.append(d)
    return found[:3]


def check(domain: str) -> dict:
    st = dns_status(domain)
    res = {"dns": st}
    if st == "error":
        res["decision"] = "retry"
        return res
    if st in ("nxdomain", "nodata"):
        res["decision"] = "dead"
        return res
    page = fetch_page(domain)
    if not page:
        if name_hit(domain):
            res.update(decision="review", note="domain hidup tapi halaman tak terjangkau", score=0)
        else:
            res["decision"] = "dead"
        return res
    final_url, html, status = page
    score, title, hits, strong = score_page(domain, html)
    th = CFG["thresholds"]
    res.update(score=score, title=title, hits=hits, strong=strong)
    res["redirects"] = redirect_targets(domain, final_url, html)
    if strong >= th["min_strong_auto"] and score >= th["auto"]:
        res["decision"] = "auto"
    elif strong >= 1 and score >= th["review"]:
        res["decision"] = "review"
    elif name_hit(domain) and status in (403, 429, 503):
        res.update(decision="review", note=f"dilindungi anti-bot (HTTP {status})")
    else:
        res["decision"] = "reject"
    return res


def cmd_verify() -> None:
    log("== VERIFY ==")
    db = load_db()
    wl = set(read_lines(DATA / "whitelist.txt"))
    vc = CFG["verify"]

    cand = sorted((d for d, v in db.items() if v["status"] == "candidate"),
                  key=lambda d: db[d].get("first_seen", ""))[: vc["max_new_per_run"]]
    recheck = sorted((d for d, v in db.items() if v["status"] == "auto"),
                     key=lambda d: db[d].get("last_checked", ""))[: vc["recheck_per_run"]]
    targets = cand + recheck
    log(f"  cek {len(cand)} kandidat baru + {len(recheck)} entri lama (workers={vc['workers']})")

    new_redirects: list[str] = []
    done = 0
    deadline = time.time() + vc["time_budget_seconds"]
    with cf.ThreadPoolExecutor(max_workers=vc["workers"]) as ex:
        futs = {ex.submit(check, d): d for d in targets}
        for f in cf.as_completed(futs):
            d = futs[f]
            try:
                res = f.result()
            except Exception as e:
                log(f"  ! {d}: {e}")
                continue
            was_auto = db[d]["status"] == "auto"
            if covered(d, wl):
                res["decision"] = "reject"
            elif res["decision"] == "auto" and protected(d):
                res["decision"] = "review"
                res["note"] = "domain institusi (kemungkinan situs resmi diretas)"
            apply_result(db, d, res, was_auto)
            if res["decision"] in ("auto", "review"):
                new_redirects += res.get("redirects", [])
            done += 1
            if time.time() > deadline:
                log("  ! batas waktu tercapai, sisa antrean ditunda ke run berikutnya")
                for x in futs:
                    x.cancel()
                break

    for r in dict.fromkeys(new_redirects):  # domain tujuan redirect jadi kandidat baru
        if r not in db and not covered(r, wl):
            db[r] = {"status": "candidate", "source": "redirect", "first_seen": TODAY}
    expire(db)
    save_db(db)
    log(f"  selesai: {done} domain diperiksa")


def apply_result(db: dict, d: str, res: dict, was_auto: bool) -> None:
    v = db[d]
    dec = res["decision"]
    v["last_checked"] = TODAY
    if dec == "retry":
        v["retries"] = v.get("retries", 0) + 1
        if v["retries"] >= 3 and v["status"] == "candidate":
            v["status"] = "dead"
        return
    v.pop("retries", None)
    if was_auto:
        if dec in ("auto", "review"):
            v["dead_count"] = 0
            v["last_alive"] = TODAY
            if "score" in res:
                v["score"] = res["score"]
        else:
            v["dead_count"] = v.get("dead_count", 0) + 1
            if v["dead_count"] >= CFG["verify"]["prune_after"]:
                v["status"] = "dead"  # keluar dari daftar (prune)
        return
    v["status"] = dec
    for k in ("score", "title", "hits", "note"):
        if k in res:
            v[k] = res[k]
    if dec == "auto":
        v["dead_count"] = 0
        v["last_alive"] = TODAY


# ---------------------------------------------------------------- build
def write_list(path: Path, title: str, desc: str, domains: list[str], adblock: bool) -> bool:
    body = [f"||{d}^" if adblock else d for d in domains]
    marker = "||" if adblock else ""
    if path.exists():
        old = [l for l in path.read_text("utf-8").splitlines() if l and not l.startswith(("!", "#"))]
        if old == body:
            return False
    repo = os.environ.get("GITHUB_REPOSITORY", "GregOliv/judol-blocklist")
    c = "!" if adblock else "#"
    header = [
        f"{c} Title: {title}",
        f"{c} Description: {desc}",
        f"{c} Homepage: https://github.com/{repo}",
        f"{c} Version: {NOW.strftime('%Y.%m.%d.%H%M')}",
        f"{c} Last modified: {NOW.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"{c} Expires: 1 day",
        f"{c} Entries: {len(body)}",
    ]
    path.write_text("\n".join(header + body) + "\n", "utf-8")
    return True


def cmd_build() -> None:
    log("== BUILD ==")
    LISTS.mkdir(exist_ok=True)
    db = load_db()
    wl = set(read_lines(DATA / "whitelist.txt"))
    approved = sorted({d for d in (reg_domain(x) for x in read_lines(DATA / "approved.txt")) if d and not covered(d, wl)})

    auto_items = [(d, v) for d, v in db.items() if v["status"] == "auto" and not covered(d, wl)]
    auto_items.sort(key=lambda x: -x[1].get("score", 0))
    if len(auto_items) > CFG["max_entries"]:
        log(f"  ! {len(auto_items)} entri > batas {CFG['max_entries']}, skor terendah dipangkas")
        auto_items = auto_items[: CFG["max_entries"]]
    auto = sorted(d for d, _ in auto_items if d not in approved)

    a = write_list(LISTS / "judol-auto.txt", "Judol Blocklist (Auto) by goliverr",
                   "Domain judi online hasil deteksi otomatis, diverifikasi lewat DNS dan isi halaman.",
                   auto, True)
    b = write_list(LISTS / "judol-reviewed.txt", "Judol Blocklist (Reviewed) by goliverr",
                   "Domain judi online yang sudah dicek manual.", approved, True)
    write_list(LISTS / "judol-auto.domains.txt", "Judol Blocklist (Auto) domains only",
               "Versi domain polos untuk Pi-hole dan sejenisnya.", auto, False)

    # antrean tinjauan manual + catatan sumber
    review = sorted(((d, v) for d, v in db.items() if v["status"] == "review" and d not in approved),
                    key=lambda x: -x[1].get("score", 0))
    with (DATA / "review-queue.tsv").open("w", encoding="utf-8") as f:
        f.write("domain\tscore\ttitle\tcatatan\tsumber\tpertama_terlihat\n")
        for d, v in review:
            f.write(f"{d}\t{v.get('score', '')}\t{v.get('title', '')}\t{v.get('note', ' '.join(v.get('hits', [])))}"
                    f"\t{v.get('source', '')}\t{v.get('first_seen', '')}\n")
    with (DATA / "sources.tsv").open("w", encoding="utf-8") as f:
        f.write("domain\tsumber\tpertama_terlihat\tskor\ttitle\n")
        for d, v in auto_items:
            f.write(f"{d}\t{v.get('source', '')}\t{v.get('first_seen', '')}\t{v.get('score', '')}\t{v.get('title', '')}\n")

    counts: dict[str, int] = {}
    for v in db.values():
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    log(f"  auto={len(auto)} reviewed={len(approved)} (berubah: auto={a}, reviewed={b})")
    log(f"  db: {counts}")


# ---------------------------------------------------------------- issue
def cmd_add_issue() -> None:
    body = os.environ.get("ISSUE_BODY", "")
    num = re.sub(r"\D", "", os.environ.get("ISSUE_NUMBER", "")) or "0"
    m = re.search(r"###\s*Domain\s*\n(.*?)(?:\n###|\Z)", body, re.S | re.I)
    chunk = m.group(1) if m else ""
    found: list[str] = []
    for tok in re.split(r"[\s,;]+", chunk):
        tok = re.sub(r"^\w+://", "", tok.strip()).split("/")[0].split(":")[0]
        d = reg_domain(tok) if tok else None
        if d and d not in found:
            found.append(d)
        if len(found) >= 20:
            break
    with (DATA / "candidates.txt").open("a", encoding="utf-8") as f:
        for d in found:
            f.write(f"{d}\tissue#{num}\n")
    log(f"{len(found)} domain dari issue #{num}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"count={len(found)}\n")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["run", "collect", "verify", "build", "add-issue"])
    cmd = p.parse_args().cmd
    if cmd == "run":
        cmd_collect()
        cmd_verify()
        cmd_build()
    else:
        {"collect": cmd_collect, "verify": cmd_verify, "build": cmd_build, "add-issue": cmd_add_issue}[cmd]()


if __name__ == "__main__":
    sys.exit(main())
