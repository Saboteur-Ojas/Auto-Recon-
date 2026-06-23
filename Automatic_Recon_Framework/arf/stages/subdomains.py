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
from ..patterns import DEFAULT_PERM_WORDS


# Stage 1 — Subdomain enumeration
# ============================================================================
def fetch_crtsh(domain: str, out: Path) -> int:
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "recon/3.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.replace("*.", "").strip().lower()
                if name:
                    subs.add(name)
        write_sorted_unique(out, list(subs))
        return len(subs)
    except Exception:
        touch(out)
        return 0

def stage_subdomain_enum(c: Config) -> None:
    sentinel = c.dir_subs / "all_subdomains.txt"
    if c.should_skip("subdomain enum", sentinel):
        return
    stage_header("Stage 1 — Subdomain Enumeration")

    for f in ["subfinder.txt", "assetfinder.txt", "crtsh.txt",
              "asn_ptr_hosts.txt", "shuffledns.txt", "ffuf.txt",
              "altdns_candidates.txt"]:
        touch(c.dir_subs / f)

    def run_subfinder():
        cmd = ["subfinder", "-d", c.domain, "-silent", "-all",
               "-o", str(c.dir_subs / "subfinder.txt")]
        run_cmd(cmd)
        return count_lines(c.dir_subs / "subfinder.txt")

    def run_assetfinder():
        run_cmd(["assetfinder", "--subs-only", c.domain],
                stdout_file=c.dir_subs / "assetfinder.txt")
        return count_lines(c.dir_subs / "assetfinder.txt")

    def run_crtsh():
        return fetch_crtsh(c.domain, c.dir_subs / "crtsh.txt")

    def run_asn():
        if not has_tool("asnmap") or not has_tool("mapcidr"):
            return 0
        run_cmd(["asnmap", "-d", c.domain, "-silent",
                 "-o", str(c.dir_subs / "asn_cidrs.txt")])
        cidrs = c.dir_subs / "asn_cidrs.txt"
        if not cidrs.exists() or count_lines(cidrs) == 0:
            return 0
        ips_raw = run_capture(["mapcidr", "-l", str(cidrs), "-silent"])
        total_ips = len([l for l in ips_raw.splitlines() if l.strip()])
        if total_ips == 0 or total_ips > c.cidr_scan_limit:
            return 0
        (c.dir_subs / "asn_ips.txt").write_text(ips_raw)
        rf = ["-r", c.resolvers] if c.resolvers and Path(c.resolvers).is_file() else []
        cmd = (["dnsx", "-l", str(c.dir_subs / "asn_ips.txt"), "-ptr",
                "-resp-only"] + rf +
               ["-t", str(c.dnsx_threads), "-silent"])
        raw = run_capture(cmd)
        matches = [l for l in raw.splitlines()
                   if l.strip() and c.domain in l.lower()]
        write_sorted_unique(c.dir_subs / "asn_ptr_hosts.txt", matches)
        return len(matches)

    def run_shuffledns():
        if not Path(c.dns_wordlist).is_file():
            return 0
        rf = ["-r", c.resolvers] if c.resolvers and Path(c.resolvers).is_file() else []
        cmd = (["shuffledns", "-d", c.domain, "-w", c.dns_wordlist, "-mode", "bruteforce"]
               + rf + ["-silent", "-o", str(c.dir_subs / "shuffledns.txt")])
        run_cmd(cmd)
        return count_lines(c.dir_subs / "shuffledns.txt")

    jobs = [
        ("subfinder",    run_subfinder),
        ("assetfinder",  run_assetfinder),
        ("crt.sh",       run_crtsh),
        ("shuffledns",   run_shuffledns),
    ]
    if not c.skip_asn:
        jobs.append(("ASN/PTR", run_asn))

    results: Dict[str, int] = {}
    lock = Lock()

    with make_progress() as prog:
        task_ids = {name: prog.add_task(f"[green]{name}", total=None)
                    for name, _ in jobs}

        def run_job(name: str, fn):
            count = 0
            try:
                count = fn()
            finally:
                with lock:
                    results[name] = count
                    prog.update(task_ids[name],
                                description=f"[green]✔ {name:<18}[/green] "
                                            f"[dim]{count} results[/dim]",
                                completed=True, total=1)
            return count

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futs = {ex.submit(run_job, name, fn): name for name, fn in jobs}
            concurrent.futures.wait(futs)

    log("Merging subdomains...")
    all_subs: List[str] = []
    for f in ["subfinder.txt", "assetfinder.txt", "crtsh.txt",
              "asn_ptr_hosts.txt", "shuffledns.txt"]:
        all_subs.extend(read_lines(c.dir_subs / f))
    all_subs = [s.lower() for s in all_subs if s.strip()]
    write_sorted_unique(c.dir_subs / "all_subdomains.txt", all_subs)
    ok(f"Unique subdomains: {count_lines(c.dir_subs / 'all_subdomains.txt')}")

    stage_altdns(c)

    ok(f"Subdomains after permutation step: "
       f"{count_lines(c.dir_subs / 'all_subdomains.txt')}")

# ============================================================================
# Stage 1b — altdns permutations
# ============================================================================
DEFAULT_PERM_WORDS = (
    "dev staging stage stg test qa uat beta demo preprod pre prod "
    "internal intranet vpn admin api app mail smtp ftp old new backup bak sandbox "
    "secure portal gateway cdn static assets mobile www web git gitlab jenkins ci cd "
    "jira confluence db database redis elastic kibana grafana monitor status docs "
    "support shop payments billing auth sso login"
).split()

def stage_altdns(c: Config) -> None:
    log("Stage 1b: Subdomain permutations")
    input_file = c.dir_subs / "all_subdomains.txt"
    out_file   = c.dir_subs / "altdns_candidates.txt"
    touch(out_file)
    if not input_file.exists() or count_lines(input_file) == 0:
        return
    if has_tool("altdns"):
        wl = c.perm_wordlist if c.perm_wordlist and Path(c.perm_wordlist).is_file() else ""
        if not wl:
            wl = str(c.dir_subs / "perm_words.txt")
            Path(wl).write_text("\n".join(DEFAULT_PERM_WORDS))
        run_cmd(["altdns", "-i", str(input_file), "-o", str(out_file), "-w", wl])
    else:
        subs = read_lines(input_file)
        words = (read_lines(Path(c.perm_wordlist))
                 if c.perm_wordlist and Path(c.perm_wordlist).is_file()
                 else DEFAULT_PERM_WORDS)
        candidates: List[str] = []
        for sub in subs:
            parts = sub.split(".", 1)
            label = parts[0]
            rest  = parts[1] if len(parts) > 1 else ""
            for w in words:
                candidates.append(f"{w}.{sub}")
                candidates.append(f"{w}-{sub}")
                if rest:
                    candidates.append(f"{label}-{w}.{rest}")
        write_sorted_unique(out_file, candidates)
    count = count_lines(out_file)
    ok(f"  {count} permutation candidates generated")
    merged = list(set(read_lines(input_file) + read_lines(out_file)))
    write_sorted_unique(input_file, merged)

