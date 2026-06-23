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


# Stage 4 — URL collection: Katana (200/301/302 only) + Waybackurls
#            GAU removed entirely.
# ============================================================================
def stage_url_collection(c: Config) -> None:
    sentinel = c.dir_urls / "all_urls.txt"
    if c.should_skip("URL collection", sentinel):
        return
    stage_header("Stage 4 — URL Collection (Katana + Waybackurls)")
    for f in ["katana.txt", "waybackurls.txt",
              "all_urls.txt", "js_urls.txt"]:
        touch(c.dir_urls / f)

    # Katana only on 200 + redirects (301/302)
    katana_input = c.dir_http / "live_200.txt"
    katana_redir = c.dir_http / "live_redirects.txt"

    # Build a merged katana target list (200 + 301/302)
    katana_targets_file = c.dir_urls / "katana_targets.txt"
    katana_targets = (read_lines(katana_input) + read_lines(katana_redir))
    write_sorted_unique(katana_targets_file, katana_targets)

    if count_lines(katana_targets_file) == 0:
        warn("No 200/301/302 hosts — skipping Katana"); 
    
    def run_katana():
        if count_lines(katana_targets_file) == 0:
            return 0
        run_cmd(["katana", "-list", str(katana_targets_file),
                 "-silent", "-hl", "-d", "3", "-c", "20",
                 "-timeout", "15", "-o", str(c.dir_urls / "katana.txt")])
        return count_lines(c.dir_urls / "katana.txt")

    def run_waybackurls():
        # waybackurls expects bare domain names
        domains_file = c.dir_urls / "live_domains_bare.txt"
        bare = []
        for u in read_lines(c.dir_http / "live_hosts.txt"):
            host = re.sub(r'^https?://', '', u).split("/")[0].split(":")[0]
            if host:
                bare.append(host)
        write_sorted_unique(domains_file, bare)
        run_cmd(["waybackurls"],
                stdin_file=domains_file,
                stdout_file=c.dir_urls / "waybackurls.txt")
        return count_lines(c.dir_urls / "waybackurls.txt")

    jobs = [
        ("katana",       run_katana),
        ("waybackurls",  run_waybackurls),
    ]
    lock = Lock()
    with make_progress() as prog:
        task_ids = {name: prog.add_task(f"[green]{name}", total=None)
                    for name, _ in jobs}

        def run_job(name: str, fn):
            count = fn()
            with lock:
                prog.update(task_ids[name],
                            description=f"[green]✔ {name:<14}[/green] "
                                        f"[dim]{count} URLs[/dim]",
                            completed=True, total=1)
            return count

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futs = {ex.submit(run_job, n, fn): n for n, fn in jobs}
            concurrent.futures.wait(futs)

    # Merge Katana + Waybackurls for all_urls
    log("Merging URLs...")
    all_urls: List[str] = []
    for f in ["katana.txt", "waybackurls.txt"]:
        all_urls.extend(read_lines(c.dir_urls / f))
    write_sorted_unique(sentinel, all_urls)
    js_patt = re.compile(r'\.js(\?|$)', re.IGNORECASE)
    js_urls = [u for u in read_lines(sentinel) if js_patt.search(u)]
    write_sorted_unique(c.dir_urls / "js_urls.txt", js_urls)
    ok(f"Total URLs: {count_lines(sentinel)}  |  JS: {count_lines(c.dir_urls / 'js_urls.txt')}")

    # Intentionally no httpx verification on raw Wayback URLs.
    # Wayback output is kept raw and analyzed offline for JS, endpoints, backups, and secrets.

