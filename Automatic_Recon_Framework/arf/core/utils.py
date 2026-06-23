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

try:
    from rich.console import Console
    from rich.progress import (
        SpinnerColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn, ProgressColumn, Progress
    )
    from rich.text import Text
    from rich.markup import escape
except ImportError:
    print("[!] 'rich' is required. Install: pip install rich")
    sys.exit(1)

console = Console(highlight=False)

_tool_cache: Dict[str, Optional[str]] = {}

def ts() -> str:
    return time.strftime("%H:%M:%S")

def log(msg: str)  -> None:
    console.print(f"[bold blue][*][/bold blue] [[dim]{ts()}[/dim]] {msg}")

def ok(msg: str)   -> None:
    console.print(f"[bold green][+][/bold green] [[dim]{ts()}[/dim]] {msg}")

def warn(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] [[dim]{ts()}[/dim]] {msg}")

def err(msg: str)  -> None:
    console.print(f"[bold red][x][/bold red] [[dim]{ts()}[/dim]] {msg}")



def find_tool(name: str) -> Optional[str]:
    if name not in _tool_cache:
        _tool_cache[name] = shutil.which(name)
    return _tool_cache[name]

def has_tool(name: str) -> bool:
    return find_tool(name) is not None

def run_cmd(cmd: List[str], *,
            stdin_file: Optional[Path] = None,
            stdout_file: Optional[Path] = None,
            timeout: Optional[int] = None) -> int:
    stdin_fh  = open(stdin_file)  if stdin_file  and stdin_file.exists()  else subprocess.DEVNULL
    stdout_fh = open(stdout_file, "w") if stdout_file else subprocess.DEVNULL
    try:
        r = subprocess.run(cmd, stdin=stdin_fh, stdout=stdout_fh,
                           stderr=subprocess.DEVNULL, timeout=timeout)
        return r.returncode
    except Exception:
        return 1
    finally:
        for fh in (stdin_fh, stdout_fh):
            if hasattr(fh, "close"):
                fh.close()

def run_capture(cmd: List[str], *,
                stdin_file: Optional[Path] = None,
                timeout: Optional[int] = None) -> str:
    stdin_fh = open(stdin_file) if stdin_file and stdin_file.exists() else subprocess.DEVNULL
    try:
        r = subprocess.run(cmd, stdin=stdin_fh, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""
    finally:
        if hasattr(stdin_fh, "close"):
            stdin_fh.close()

def count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.open("r", errors="ignore") if line.strip())
    except Exception:
        return 0

def read_lines(path: Path) -> List[str]:
    try:
        return [l.rstrip() for l in path.open("r", errors="ignore") if l.strip()]
    except Exception:
        return []

def write_sorted_unique(path: Path, lines: List[str]) -> None:
    unique = sorted({l for l in lines if l.strip()})
    path.write_text("\n".join(unique) + ("\n" if unique else ""))

def touch(path: Path) -> None:
    path.touch(exist_ok=True)

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn("line", style="bold green"),
        TextColumn("[bold green]{task.description}"),
        HackerBarColumn(bar_width=30),
        TaskProgressColumn(style="bold green"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

def stage_header(title: str) -> None:
    console.print()
    console.rule(f"[bold green]{title}[/bold green]", style="dim green")

BANNER = """\
  ███████╗██╗   ██╗██╗     ██╗         ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔════╝██║   ██║██║     ██║         ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  █████╗  ██║   ██║██║     ██║         ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══╝  ██║   ██║██║     ██║         ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║     ╚██████╔╝███████╗███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\
"""

def print_banner() -> None:
    console.print(BANNER, style="bold green")
    console.print("      [ Fast Recon: Subdomain | DNS | HTTP | URL | JS | Vhost | Nuclei ]",
                  style="bold cyan")
    console.print("                             :: By Ojasva Srivastava ::", style="bold red")
    console.print("      " + "-" * 69, style="bold green")
    console.print()