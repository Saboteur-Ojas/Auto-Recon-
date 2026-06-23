from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Optional, List, Tuple, Dict, Set

from ..config import Config
from ..core.utils import (
    console, log, ok, warn, err, has_tool, run_cmd, run_capture, count_lines,
    read_lines, write_sorted_unique, touch, make_progress, stage_header
)
from ..patterns import SECRET_PATTERNS, _COMBINED_RE


# Stage 5a — JS Analysis
# ============================================================================
SECRET_PATTERNS: Dict[str, str] = {
    "AWS_Access_Key_ID":   r'AKIA[0-9A-Z]{16}',
    "AWS_Secret_Key":      r'aws[\-_\s]*(secret|access)[\-_\s]*key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z/+]{40}',
    "GCP_API_Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "OpenAI_API_Key":      r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
    "Anthropic_API_Key":   r'sk-ant-[a-zA-Z0-9\-_]{90,}',
    "HuggingFace_Token":   r'hf_[a-zA-Z0-9]{34,}',
    "GitHub_PAT":          r'ghp_[0-9a-zA-Z]{36}',
    "GitHub_OAuth":        r'gho_[0-9a-zA-Z]{36}',
    "GitHub_Actions":      r'ghs_[0-9a-zA-Z]{36}',
    "GitLab_PAT":          r'glpat-[0-9a-zA-Z\-_]{20}',
    "npm_Token":           r'npm_[A-Za-z0-9]{36}',
    "Docker_Hub_Token":    r'dckr_pat_[A-Za-z0-9\-_]{27}',
    "Slack_Bot_Token":     r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
    "Slack_Webhook":       r'hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+',
    "Discord_Token":       r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}',
    "Twilio_SID":          r'AC[a-zA-Z0-9]{32}',
    "SendGrid_Key":        r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    "Stripe_Secret":       r'sk_(live|test)_[0-9a-zA-Z]{24,}',
    "Stripe_Pub":          r'pk_(live|test)_[0-9a-zA-Z]{24,}',
    "JWT":                 r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Firebase_URL":        r'https://[a-z0-9-]+\.firebaseio\.com',
    "RSA_Private_Key":     r'-----BEGIN RSA PRIVATE KEY-----',
    "EC_Private_Key":      r'-----BEGIN EC PRIVATE KEY-----',
    "OpenSSH_Private_Key": r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Bearer_Token":        r'bearer\s+[a-zA-Z0-9\-_\.=]{20,}',
    "Generic_API_Key":     r'(api[\-_]?key|apikey)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-_]{20,}',
    "Generic_Secret":      r'(client[\-_]?secret|app[\-_]?secret)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-_!@#$%^&*]{16,}',
    "Generic_Password":    r'(password|passwd|db[\-_]?pass)["\']?\s*[:=]\s*["\']?[^\s"\']{8,}',
    "Connection_String":   r'(mongodb(\+srv)?|mysql|postgres|redis|amqp)://[^\s"\'<>]+',
    "AWS_Session_Token":   r'aws[\-_\s]*session[\-_\s]*token["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{100,}',
    "Azure_Client_Secret": r'azure[\-_\s]*(client|tenant)[\-_\s]*(secret|id)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-]{20,}',
    "Shopify_Token":       r'shp(ss|at|ca)_[a-fA-F0-9]{32}',
    "PayPal_OAuth":        r'access_token\$production\$[a-zA-Z0-9]{16}\$[a-zA-Z0-9]{32}',
    "Vercel_Token":        r'vercel(.{0,10})?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{24,}',
    "Notion_Token":        r'secret_[a-zA-Z0-9]{43}',
    "Linear_Key":          r'lin_api_[a-zA-Z0-9]{40}',
}
_COMBINED_RE = re.compile(
    "|".join(f"(?P<p{i}>{v})" for i, v in enumerate(SECRET_PATTERNS.values())),
    re.IGNORECASE
)

def download_js_file(args: Tuple) -> Tuple[str, Optional[str], Optional[str]]:
    url, dir_js = args
    fname = hashlib.md5(url.encode()).hexdigest()
    outfile = Path(dir_js) / "raw" / f"{fname}.js"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                          "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"})
        with urllib.request.urlopen(req, timeout=12) as r:
            content = r.read()
        outfile.write_bytes(content)
        map_url = None
        m = re.search(rb'sourceMappingURL=([^\s*]+)', content)
        if m:
            mu = m.group(1).decode(errors="ignore").strip()
            if mu.startswith("//"):
                mu = "https:" + mu
            elif not mu.startswith("http"):
                mu = "/".join(url.split("/")[:-1]) + "/" + mu
            map_url = mu
        return fname, url, map_url
    except Exception:
        return fname, None, None

def download_js_files(c: Config) -> None:
    js_urls = read_lines(c.dir_urls / "js_urls.txt")
    if not js_urls:
        return
    log(f"  Downloading {len(js_urls)} JS files ({c.js_parallel} parallel)...")
    url_map: List[str] = []
    failed: List[str]  = []
    with make_progress() as prog:
        t = prog.add_task("[cyan]Downloading JS...", total=len(js_urls))
        with concurrent.futures.ThreadPoolExecutor(max_workers=c.js_parallel) as ex:
            futs = {ex.submit(download_js_file, (url, c.dir_js)): url
                    for url in js_urls}
            for fut in concurrent.futures.as_completed(futs):
                fname, url_result, map_url = fut.result()
                if url_result:
                    url_map.append(f"{fname}.js|{url_result}")
                    if map_url:
                        try:
                            req = urllib.request.Request(
                                map_url, headers={"User-Agent": "recon/3.0"})
                            with urllib.request.urlopen(req, timeout=12) as r:
                                content = r.read()
                            mapfile = c.dir_js / "maps" / f"{fname}.map"
                            mapfile.write_bytes(content)
                            url_map.append(f"{fname}.map|{map_url}")
                        except Exception:
                            pass
                else:
                    failed.append(futs[fut])
                prog.advance(t)
    (c.dir_js / "url_map.txt").write_text("\n".join(url_map) + "\n")
    (c.dir_js / "failed_downloads.txt").write_text("\n".join(failed) + "\n")
    ok(f"  JS download done: {len(url_map)} files")

def extract_secrets(c: Config) -> None:
    log(f"  Scanning for secrets ({len(SECRET_PATTERNS)} patterns)...")
    out_path = c.dir_js / "secrets.txt"
    url_map: Dict[str, str] = {}
    for line in read_lines(c.dir_js / "url_map.txt"):
        parts = line.split("|", 1)
        if len(parts) == 2:
            url_map[parts[0]] = parts[1]
    findings: List[str] = []
    for sdir in [c.dir_js / "raw", c.dir_js / "maps"]:
        if not sdir.exists():
            continue
        for js_file in sdir.iterdir():
            if not js_file.is_file():
                continue
            try:
                content = js_file.read_text(errors="ignore")
            except Exception:
                continue
            for lineno, line in enumerate(content.splitlines(), 1):
                for m in _COMBINED_RE.finditer(line):
                    source_url = url_map.get(
                        js_file.name.rsplit(".", 1)[0] + "." + js_file.suffix.lstrip("."),
                        str(js_file))
                    findings.append(f"[SECRET] {source_url}:{lineno} => {m.group()}")
    write_sorted_unique(out_path, findings)
    ok(f"  Secrets found: {len(findings)}")

def extract_endpoints(c: Config) -> None:
    """Extract API endpoints from JS files, Katana output, and Wayback URLs."""
    log("  Extracting API endpoints from JS + Katana + Wayback...")
    out     = c.dir_js / "endpoints.txt"
    out_abs = c.dir_js / "endpoints_absolute.txt"
    out_rel = c.dir_js / "endpoints_relative.txt"
    IGNORE_EXTS = re.compile(
        r'^/(img|images|fonts|icons|static|assets|css|js|svg|png|jpg|jpeg|gif|woff|ttf|eot|ico)',
        re.IGNORECASE)
    ONLY_DIGITS = re.compile(r'^/[0-9]+$')
    rel_re  = re.compile(r'["\'](\\/[a-zA-Z0-9_\-/.\{\}?=&%#@]{3,200})["\']')
    abs_re  = re.compile(r'["\']( https?://[a-zA-Z0-9_\-.]+ (?:/[a-zA-Z0-9_\-/.\{\}?=&%#@]*)?)["\']',
                         re.VERBOSE)
    fetch_re = re.compile(
        r'(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*[`"\']([^`"\']{5,200})[`"\']')
    api_path_re = re.compile(
        r'(?:["\'`])(/(?:api|v\d+|graphql|rest|service|endpoint|rpc|internal)'
        r'[a-zA-Z0-9_\-/.\{\}?=&%#@]{2,200})(?:["\'`])', re.IGNORECASE)
    abs_eps, rel_eps = set(), set()

    # --- from JS files ---
    raw_dir = c.dir_js / "raw"
    if raw_dir.exists():
        for jf in raw_dir.iterdir():
            if not jf.is_file():
                continue
            try:
                content = jf.read_text(errors="ignore")
            except Exception:
                continue
            for ep in rel_re.findall(content) + fetch_re.findall(content):
                ep = ep.replace("\\/", "/")
                if ep.startswith("http"):
                    abs_eps.add(ep)
                elif ep.startswith("/"):
                    if not IGNORE_EXTS.match(ep) and not ONLY_DIGITS.match(ep):
                        rel_eps.add(ep)
            for ep in abs_re.findall(content):
                abs_eps.add(ep.strip())
            for ep in api_path_re.findall(content):
                if not IGNORE_EXTS.match(ep) and not ONLY_DIGITS.match(ep):
                    rel_eps.add(ep)

    # --- from Katana output ---
    for url in read_lines(c.dir_urls / "katana.txt"):
        if url.startswith("http"):
            abs_eps.add(url)

    # --- from raw Wayback URLs: no httpx verification here ---
    for url in read_lines(c.dir_urls / "waybackurls.txt"):
        if url.startswith("http"):
            abs_eps.add(url)

    write_sorted_unique(out_abs, list(abs_eps))
    write_sorted_unique(out_rel, list(rel_eps))
    all_eps = sorted(abs_eps | rel_eps)
    write_sorted_unique(out, all_eps)
    ok(f"  Endpoints: {len(all_eps)} total ({len(abs_eps)} absolute, {len(rel_eps)} relative)")

def extract_source_maps(c: Config) -> None:
    maps_dir = c.dir_js / "maps"
    out = c.dir_js / "sourcemap_sources.txt"
    touch(out)
    if not maps_dir.exists():
        return
    map_files = list(maps_dir.glob("*.map"))
    if not map_files:
        return
    log(f"  Parsing {len(map_files)} source maps...")
    sources: List[str] = []
    for mf in map_files:
        try:
            data = json.loads(mf.read_text(errors="ignore"))
            sources.extend(data.get("sources") or [])
        except Exception:
            pass
    write_sorted_unique(out, sources)
    ok(f"  Source map files listed: {count_lines(out)}")

def stage_js_analysis(c: Config) -> None:
    stage_header("Stage 5a — JS Analysis")
    for f in ["url_map.txt", "secrets.txt", "endpoints.txt",
              "endpoints_absolute.txt", "endpoints_relative.txt",
              "sourcemap_sources.txt", "failed_downloads.txt"]:
        touch(c.dir_js / f)
    if count_lines(c.dir_urls / "js_urls.txt") == 0:
        warn("No JS URLs — skipping JS download/analysis")
    else:
        download_js_files(c)
        extract_secrets(c)
    # extract_endpoints always runs — it also pulls from Katana + Wayback
    extract_endpoints(c)
    extract_source_maps(c)
    ok(f"JS/endpoint analysis done. Results: {c.dir_js}/")

