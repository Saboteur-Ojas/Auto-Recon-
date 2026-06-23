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
from rich.markup import escape


# Stage 5b — FFUF vhost (with rich progress bar showing completion %)
# ============================================================================
def stage_ffuf_vhost(c: Config) -> None:
    touch(c.dir_ffuf / "all_vhosts.txt")
    if not c.run_vhost:
        log("Skipping vhost discovery (use --vhost to enable)"); return
    if c.skip_ffuf:
        log("Skipping vhost bruteforce (--no-ffuf)"); return
    stage_header("Stage 5b — VHost Bruteforce (ffuf)")
    if not has_tool("ffuf"):
        warn("  ffuf not installed — skipping"); return
    if count_lines(c.dir_http / "live_hosts.txt") == 0:
        warn("  No live hosts"); return
    wl = c.ffuf_vhost_wordlist
    if not Path(wl).is_file():
        warn(f"  Vhost wordlist not found: {wl}"); return

    hosts = read_lines(c.dir_http / "live_hosts.txt")[:c.ffuf_max_hosts]
    total_hosts = len(hosts)
    log(f"  Vhost bruteforce — {total_hosts} hosts, {c.ffuf_threads} threads")

    # Count wordlist lines once for accurate per-host progress estimate
    wl_lines = count_lines(Path(wl))
    total_probes = total_hosts * wl_lines if wl_lines > 0 else total_hosts

    all_vhosts: List[str] = []

    if getattr(c, "bg_ffuf", False):
        for idx, host in enumerate(hosts):
            safe = re.sub(r'https?://', '', host)
            safe = re.sub(r'[^a-zA-Z0-9._-]', '_', safe)
            vhost_json = c.dir_ffuf / "vhosts" / f"{safe}.json"
            vhost_txt  = c.dir_ffuf / "vhosts" / f"{safe}.txt"
            touch(vhost_txt)
            try:
                req = urllib.request.Request(
                    host, headers={"Host": f"nonexistent99999.{c.domain}",
                                   "User-Agent": "recon/3.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    baseline = len(r.read())
            except Exception:
                baseline = 0
            run_cmd(["ffuf", "-w", wl, "-u", host,
                     "-H", f"Host: FUZZ.{c.domain}",
                     "-mc", "200,204,301,302,307,401,403,405",
                     "-fs", str(baseline),
                     "-t", str(c.ffuf_threads),
                     "-timeout", "8", "-s", "-noninteractive",
                     "-of", "json", "-o", str(vhost_json)])
            vhost_count = 0
            if vhost_json.exists():
                try:
                    data = json.loads(vhost_json.read_text())
                    vhosts = [
                        f"{r['status']} {r['input']['FUZZ']}.{c.domain}"
                        for r in data.get("results", [])
                    ]
                    vhost_count = len(vhosts)
                    write_sorted_unique(vhost_txt, vhosts)
                    all_vhosts.extend(vhosts)
                except Exception:
                    pass
            pct = int(((idx + 1) / total_hosts) * 100)
            log(f"  [ffuf bg] {idx+1}/{total_hosts} ({pct}%) — {host} — {vhost_count} vhosts")
    else:
        # Foreground: one progress bar tracking hosts completed + total probe estimate
        with make_progress() as prog:
            # Host-level progress (exact)
            host_task = prog.add_task(
                f"[green]ffuf vhost [0/{total_hosts} hosts]",
                total=total_hosts)
            # Probe-level progress (estimated: hosts_done * wl_lines)
            probe_task = prog.add_task(
                f"[cyan]  probes [0/{total_probes}]",
                total=total_probes)

            for idx, host in enumerate(hosts):
                safe = re.sub(r'https?://', '', host)
                safe = re.sub(r'[^a-zA-Z0-9._-]', '_', safe)
                vhost_json = c.dir_ffuf / "vhosts" / f"{safe}.json"
                vhost_txt  = c.dir_ffuf / "vhosts" / f"{safe}.txt"
                touch(vhost_txt)
                try:
                    req = urllib.request.Request(
                        host, headers={"Host": f"nonexistent99999.{c.domain}",
                                       "User-Agent": "recon/3.0"})
                    with urllib.request.urlopen(req, timeout=5) as r:
                        baseline = len(r.read())
                except Exception:
                    baseline = 0

                prog.update(host_task,
                            description=f"[green]ffuf vhost [{idx+1}/{total_hosts} hosts] "
                                        f"— {escape(host[:40])}")

                run_cmd(["ffuf", "-w", wl, "-u", host,
                         "-H", f"Host: FUZZ.{c.domain}",
                         "-mc", "200,204,301,302,307,401,403,405",
                         "-fs", str(baseline),
                         "-t", str(c.ffuf_threads),
                         "-timeout", "8", "-s", "-noninteractive",
                         "-of", "json", "-o", str(vhost_json)])

                vhost_count = 0
                if vhost_json.exists():
                    try:
                        data = json.loads(vhost_json.read_text())
                        vhosts = [
                            f"{r['status']} {r['input']['FUZZ']}.{c.domain}"
                            for r in data.get("results", [])
                        ]
                        vhost_count = len(vhosts)
                        write_sorted_unique(vhost_txt, vhosts)
                        all_vhosts.extend(vhosts)
                    except Exception:
                        pass

                # Advance both tasks
                prog.advance(host_task)
                probes_done = (idx + 1) * wl_lines if wl_lines > 0 else (idx + 1)
                prog.update(probe_task,
                            completed=probes_done,
                            description=f"[cyan]  probes [{probes_done}/{total_probes}] "
                                        f"— {vhost_count} vhosts this host")

    write_sorted_unique(c.dir_ffuf / "all_vhosts.txt", all_vhosts)
    ok(f"Vhost bruteforce done: {len(all_vhosts)} unique vhosts")

