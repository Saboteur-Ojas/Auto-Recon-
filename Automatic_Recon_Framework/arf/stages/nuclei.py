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


# Stage 5e — Nuclei
#   Runs AFTER Katana, JS analysis, API extraction, and Arjun.
#   Feeds on: live_200.txt + verified API endpoints + Arjun results.
#   All targets deduplicated before scanning.
# ============================================================================
def stage_nuclei(c: Config) -> None:
    touch(c.dir_nuclei / "nuclei_results.txt")
    stage_header(f"Stage 5e — Nuclei  (severity: {c.nuclei_severity})")

    # Build deduplicated target list
    nuclei_targets: set = set()

    # 1. Verified 200 hosts
    nuclei_targets.update(read_lines(c.dir_http / "live_200.txt"))

    # 2. Verified API endpoints (absolute)
    for url in read_lines(c.dir_js / "endpoints_absolute.txt"):
        nuclei_targets.add(url)

    # 3. Arjun discovered param URLs
    for line in read_lines(c.dir_params / "discovered_params.txt"):
        # arjun output may contain "URL param=value" style — extract URL part
        url = line.split()[0] if line.strip() else ""
        if url.startswith("http"):
            nuclei_targets.add(url)

    if not nuclei_targets:
        warn("No targets for Nuclei — skipping"); return

    nuclei_target_file = c.dir_nuclei / "nuclei_targets.txt"
    write_sorted_unique(nuclei_target_file, list(nuclei_targets))
    log(f"  Nuclei target count (deduplicated): {count_lines(nuclei_target_file)}")

    cmd = ["nuclei", "-l", str(nuclei_target_file),
           "-severity", c.nuclei_severity,
           "-rate-limit", str(c.nuclei_rate_limit),
           "-bs", "25", "-concurrency", "50",
           "-silent", "-o", str(c.dir_nuclei / "nuclei_results.txt")]
    with make_progress() as prog:
        t = prog.add_task("[green]nuclei scanning...", total=None)
        run_cmd(cmd)
        n = count_lines(c.dir_nuclei / "nuclei_results.txt")
        prog.update(t, description=f"[green]✔ nuclei done — {n} findings",
                    completed=True, total=1)
    ok(f"Nuclei findings: {count_lines(c.dir_nuclei / 'nuclei_results.txt')}")

