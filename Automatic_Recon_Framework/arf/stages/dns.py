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


# Stage 2 — DNSX resolution
# ============================================================================
def stage_dnsx(c: Config) -> None:
    sentinel = c.dir_dns / "resolved_hosts.txt"
    if c.should_skip("dnsx resolution", sentinel):
        return
    stage_header("Stage 2 — DNS Resolution (dnsx)")
    touch(c.dir_dns / "resolved.txt")
    touch(sentinel)
    if count_lines(c.dir_subs / "all_subdomains.txt") == 0:
        warn("No subdomains to resolve"); return
    rf = ["-r", c.resolvers] if c.resolvers and Path(c.resolvers).is_file() else []
    cmd = (["dnsx", "-l", str(c.dir_subs / "all_subdomains.txt")]
           + rf + ["-t", str(c.dnsx_threads), "-retry", "1",
                   "-silent", "-a", "-resp", "-o", str(c.dir_dns / "resolved.txt")])
    with make_progress() as prog:
        t = prog.add_task("[green]dnsx resolving...", total=None)
        run_cmd(cmd)
        prog.update(t, description="[green]✔ dnsx done", completed=True, total=1)
    hosts = []
    for line in read_lines(c.dir_dns / "resolved.txt"):
        hosts.append(line.split()[0])
    write_sorted_unique(sentinel, hosts)
    ok(f"Resolved hosts: {count_lines(sentinel)}")

