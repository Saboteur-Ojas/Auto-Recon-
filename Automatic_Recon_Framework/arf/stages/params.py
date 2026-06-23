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


# Stage 5d — Parameter fuzzing (arjun) — only on verified 200 + API endpoints
# ============================================================================
def stage_param_fuzzing(c: Config) -> None:
    touch(c.dir_params / "discovered_params.txt")
    if c.skip_params:
        log("Skipping parameter fuzzing (--no-params)"); return
    stage_header("Stage 5d — Parameter Fuzzing (arjun)")
    if not has_tool("arjun"):
        warn("  arjun not installed"); return

    # Seed targets: live_200.txt + raw Wayback URLs + absolute API endpoints.
    # No httpx verification is performed on Wayback URLs.
    candidates: List[str] = []
    candidates.extend(read_lines(c.dir_http / "live_200.txt"))
    candidates.extend(read_lines(c.dir_urls / "waybackurls.txt"))
    candidates.extend(read_lines(c.dir_js / "endpoints_absolute.txt"))

    # Keep only dynamic-looking URLs (query params or dynamic extensions)
    dyn_re = re.compile(
        r'\?[a-z0-9_]+=|\.(php|asp|aspx|jsp|jspx|cfm|do|action)(\?|$)',
        re.IGNORECASE)
    # Also include /api/ paths regardless of extension
    api_re = re.compile(r'/(?:api|v\d+|graphql|rest|rpc|service)/', re.IGNORECASE)

    seen_bases: set = set()
    dynamic: List[str] = []
    for url in candidates:
        if dyn_re.search(url) or api_re.search(url):
            base = url.split("?")[0]
            if base not in seen_bases:
                seen_bases.add(base)
                dynamic.append(base)

    dynamic = dynamic[:c.max_param_targets]
    if not dynamic:
        warn("  No eligible endpoints for Arjun (no verified 200/API targets)"); return

    targets_file = c.dir_params / "targets.txt"
    write_sorted_unique(targets_file, dynamic)
    log(f"  Fuzzing {len(dynamic)} endpoints with Arjun ({c.arjun_threads} threads)")
    with make_progress() as prog:
        t = prog.add_task("[green]arjun fuzzing...", total=None)
        run_cmd(["arjun", "-i", str(targets_file), "-m", "GET",
                 "-t", str(c.arjun_threads),
                 "-oT", str(c.dir_params / "discovered_params.txt")])
        prog.update(t, description="[green]✔ arjun done", completed=True, total=1)
    ok(f"Discovered params: {count_lines(c.dir_params / 'discovered_params.txt')}")

