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
from ..patterns import BACKUP_EXT_RE, URL_SECRET_RE


# Stage 5c — Wayback analysis (backup files / secrets in URLs)
# ============================================================================
BACKUP_EXT_RE = re.compile(
    r'\.(zip|rar|7z|tar\.gz|tgz|tar|gz|bak|bkp|backup|old|orig|save|swp|'
    r'sql|sql\.gz|db|sqlite3?|config|conf|ini|env|pem|key|crt|p12|pfx|'
    r'log|csv|xls|xlsx|doc|docx|htpasswd|htaccess|git)(\?.*)?$',
    re.IGNORECASE)
URL_SECRET_RE = re.compile(
    r'(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|token|'
    r'passwd|password|session[_-]?id|aws[_-]?(access|secret)[_-]?key)=[^&\s"\']{4,}')

def stage_wayback_analysis(c: Config) -> None:
    stage_header("Stage 5c — Wayback Analysis")
    for f in ["backup_files.txt", "backup_files_live.txt", "url_secrets.txt", "wayback_url_secrets.txt"]:
        touch(c.dir_wayback / f)
    wb_file = c.dir_urls / "waybackurls.txt"
    if count_lines(wb_file) == 0:
        warn("No waybackurls output — skipping"); return
    urls = read_lines(wb_file)
    backups = [u for u in urls if BACKUP_EXT_RE.search(u)]
    write_sorted_unique(c.dir_wayback / "backup_files.txt", backups)
    ok(f"  Backup files: {len(backups)}")
    secrets_in_urls = [u for u in urls if URL_SECRET_RE.search(u)]
    write_sorted_unique(c.dir_wayback / "wayback_url_secrets.txt", secrets_in_urls)
    write_sorted_unique(c.dir_wayback / "url_secrets.txt", secrets_in_urls)  # backward-compatible name
    ok(f"  Secrets in Wayback URLs: {len(secrets_in_urls)}")
    log("  Skipping httpx checks on Wayback-derived backup URLs as requested")



