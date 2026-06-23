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


# Stage 3 — HTTPX with status-code classification
# ============================================================================
def stage_httpx(c: Config) -> None:
    sentinel = c.dir_http / "live_hosts.txt"
    if c.should_skip("httpx probing", sentinel):
        return
    stage_header("Stage 3 — HTTP Probing (httpx)")
    for f in ["httpx_full.json", "httpx_readable.txt", "live_hosts.txt",
              "live_200.txt", "live_redirects.txt", "live_403.txt"]:
        touch(c.dir_http / f)
    if count_lines(c.dir_dns / "resolved_hosts.txt") == 0:
        warn("No resolved hosts"); return
    cmd = ["httpx", "-l", str(c.dir_dns / "resolved_hosts.txt"),
           "-silent", "-threads", str(c.httpx_threads),
           "-status-code", "-title", "-tech-detect",
           "-follow-redirects", "-random-agent", "-timeout", "8",
           "-mc", "200,301,302,403",
           "-json", "-o", str(c.dir_http / "httpx_full.json")]
    with make_progress() as prog:
        t = prog.add_task("[green]httpx probing...", total=None)
        run_cmd(cmd)
        prog.update(t, description="[green]✔ httpx done", completed=True, total=1)

    # Parse JSON → classify into separate files
    urls_200, urls_redirects, urls_403, readable = [], [], [], []
    json_file = c.dir_http / "httpx_full.json"
    if json_file.exists():
        for line in read_lines(json_file):
            try:
                d = json.loads(line)
                url = d.get("url", "")
                if not url:
                    continue
                status = d.get("status_code", 0)
                title  = (d.get("title") or "-").replace("\t", " ")
                tech_list = d.get("technologies") or d.get("tech") or []
                tech = ",".join(tech_list)
                readable.append(f"{url}\t[{status}]\t[{title}]\t[{tech}]")
                if status == 200:
                    urls_200.append(url)
                elif status in (301, 302):
                    urls_redirects.append(url)
                elif status == 403:
                    urls_403.append(url)
            except Exception:
                pass

    write_sorted_unique(c.dir_http / "live_200.txt", urls_200)
    write_sorted_unique(c.dir_http / "live_redirects.txt", urls_redirects)
    write_sorted_unique(c.dir_http / "live_403.txt", urls_403)
    # live_hosts.txt = union of 200 + 301/302 + 403 (backward compat)
    all_live = urls_200 + urls_redirects + urls_403
    write_sorted_unique(sentinel, all_live)
    write_sorted_unique(c.dir_http / "httpx_readable.txt", readable)
    ok(f"Live hosts: {count_lines(sentinel)} "
       f"(200={len(urls_200)}, redirects={len(urls_redirects)}, 403={len(urls_403)})")



# Stage 3b — Port scan (naabu) — opt-in with --ports
# ============================================================================
def stage_port_scan(c: Config) -> None:
    if c.skip_ports:
        log("Skipping port scan (use --ports to enable)"); return
    stage_header("Stage 3b — Port Scanning (naabu)")
    open_ports = c.dir_ports / "open_ports.txt"
    web_ports  = c.dir_ports / "web_ports.txt"
    touch(open_ports); touch(web_ports)
    if not has_tool("naabu"):
        warn("  naabu not installed — skipping"); return
    if count_lines(c.dir_dns / "resolved_hosts.txt") == 0:
        warn("  No resolved hosts"); return
    cmd = ["naabu", "-l", str(c.dir_dns / "resolved_hosts.txt"),
           "-top-ports", c.naabu_top_ports, "-silent",
           "-o", str(open_ports)]
    with make_progress() as prog:
        t = prog.add_task("[green]naabu scanning...", total=None)
        run_cmd(cmd)
        prog.update(t, description=f"[green]✔ naabu done ({count_lines(open_ports)} open)",
                    completed=True, total=1)
    ok(f"  Open ports: {count_lines(open_ports)}")
    web_port_patt = re.compile(
        r':(80|443|8080|8443|8000|8008|8888|3000|3001|4000|4443|'
        r'5000|5001|9000|9090|9200|9443|10000)$')
    web_targets = [l for l in read_lines(open_ports) if web_port_patt.search(l)]
    write_sorted_unique(web_ports, web_targets)
    if not web_targets:
        return
    log(f"  Probing {len(web_targets)} non-standard web port targets with httpx...")
    ports_json = c.dir_ports / "httpx_ports.json"
    run_cmd(["httpx", "-l", str(web_ports),
             "-silent", "-threads", str(c.httpx_threads),
             "-status-code", "-title", "-tech-detect",
             "-follow-redirects", "-random-agent", "-timeout", "8",
             "-mc", "200,301,302,403",
             "-json", "-o", str(ports_json)])
    if not ports_json.exists():
        return
    extra_200, extra_redirects, extra_403, extra_readable = [], [], [], []
    for line in read_lines(ports_json):
        try:
            d = json.loads(line)
            url = d.get("url", "")
            if not url:
                continue
            status = d.get("status_code", 0)
            title  = (d.get("title") or "-").replace("\t", " ")
            tech_list = d.get("technologies") or d.get("tech") or []
            tech = ",".join(tech_list)
            extra_readable.append(f"{url}\t[{status}]\t[{title}]\t[{tech}]")
            if status == 200:
                extra_200.append(url)
            elif status in (301, 302):
                extra_redirects.append(url)
            elif status == 403:
                extra_403.append(url)
        except Exception:
            pass
    for fname, extra in [("live_200.txt", extra_200),
                         ("live_redirects.txt", extra_redirects),
                         ("live_403.txt", extra_403)]:
        existing = read_lines(c.dir_http / fname)
        write_sorted_unique(c.dir_http / fname, existing + extra)
    existing = read_lines(c.dir_http / "live_hosts.txt")
    write_sorted_unique(c.dir_http / "live_hosts.txt",
                        existing + extra_200 + extra_redirects + extra_403)
    existing_rd = read_lines(c.dir_http / "httpx_readable.txt")
    write_sorted_unique(c.dir_http / "httpx_readable.txt", existing_rd + extra_readable)
    ok(f"  Extra web-port hosts merged. live_hosts: "
       f"{count_lines(c.dir_http / 'live_hosts.txt')}")

