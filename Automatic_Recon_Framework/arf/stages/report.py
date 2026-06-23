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
from rich.table import Table
from rich import box


# Summary report
# ============================================================================
def print_summary(c: Config) -> None:
    console.print()
    console.rule("[bold green]Recon Summary[/bold green]", style="dim green")

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold green",
              title=f"[bold]{c.domain}[/bold]", title_style="bold yellow",
              min_width=60)
    t.add_column("Category",  style="bold", min_width=34)
    t.add_column("Count", justify="right", style="green")

    def row(label: str, path: Path, indent: int = 0) -> None:
        prefix = "  " * indent
        t.add_row(prefix + label, str(count_lines(path)))

    row("Subdomains (total)",    c.dir_subs / "all_subdomains.txt")
    row("  via crt.sh",          c.dir_subs / "crtsh.txt", 1)
    row("  via ASN/PTR",         c.dir_subs / "asn_ptr_hosts.txt", 1)
    row("Resolved hosts",        c.dir_dns  / "resolved_hosts.txt")
    row("Live hosts (total)",    c.dir_http / "live_hosts.txt")
    row("  HTTP 200",            c.dir_http / "live_200.txt", 1)
    row("  HTTP 301/302",        c.dir_http / "live_redirects.txt", 1)
    row("  HTTP 403",            c.dir_http / "live_403.txt", 1)
    row("Open ports (naabu)",    c.dir_ports / "open_ports.txt")
    row("Total URLs",            c.dir_urls / "all_urls.txt")
    row("  Katana",              c.dir_urls / "katana.txt", 1)
    row("  Waybackurls (raw)",   c.dir_urls / "waybackurls.txt", 1)
    row("JS files downloaded",   c.dir_js   / "url_map.txt")
    row("Secrets in JS",         c.dir_js   / "secrets.txt")
    row("Endpoints (total)",     c.dir_js   / "endpoints.txt")
    row("  absolute",            c.dir_js   / "endpoints_absolute.txt", 1)
    row("  relative",            c.dir_js   / "endpoints_relative.txt", 1)
    row("Source map sources",    c.dir_js   / "sourcemap_sources.txt")
    row("Vhosts discovered",     c.dir_ffuf / "all_vhosts.txt")
    row("Backup files found",    c.dir_wayback / "backup_files.txt")
    row("Secrets in Wayback URLs", c.dir_wayback / "wayback_url_secrets.txt")
    row("Hidden params",         c.dir_params / "discovered_params.txt")
    row("Nuclei targets",        c.dir_nuclei / "nuclei_targets.txt")
    row("Nuclei findings",       c.dir_nuclei / "nuclei_results.txt")
    console.print(t)

    console.print()
    console.rule("[bold green]Live Subdomains (httpx)[/bold green]", style="dim green")
    ht = Table(box=box.SIMPLE, show_header=True, header_style="bold",
               min_width=80, expand=True)
    ht.add_column("URL",    style="cyan",  min_width=40)
    ht.add_column("Status", style="green", min_width=8)
    ht.add_column("Title",  min_width=20)
    ht.add_column("Tech",   style="dim")
    rd = c.dir_http / "httpx_readable.txt"
    if rd.exists() and count_lines(rd) > 0:
        for line in read_lines(rd)[:50]:
            parts = line.split("\t")
            if len(parts) >= 4:
                ht.add_row(*parts[:4])
    else:
        ht.add_row("(no live hosts found)", "", "", "")
    console.print(ht)

    console.print()
    console.rule("[bold red]Nuclei Findings[/bold red]", style="dim red")
    nf = c.dir_nuclei / "nuclei_results.txt"
    if nf.exists() and count_lines(nf) > 0:
        for line in read_lines(nf):
            console.print(f"  {escape(line)}")
    else:
        console.print("  [dim](no findings)[/dim]")

    report_lines = [
        f"RECON SUMMARY: {c.domain}",
        f"Results: {c.outdir}", "",
    ]
    for line in read_lines(c.dir_http / "httpx_readable.txt"):
        report_lines.append(line)
    for line in (read_lines(nf) if nf.exists() else []):
        report_lines.append(line)
    c.report_file.write_text("\n".join(report_lines))
    ok(f"Report saved: {c.report_file}")

# ============================================================================
# Main
# ============================================================================
def main() -> None:
    print_banner()
    c = parse_args()
    prompt_domain(c)
    select_wordlist(c)
    select_resolvers(c)
    if c.ctf_mode:
        warn("CTF mode: ports ON · altdns always ON · params OFF · ffuf OFF")
        c.skip_ports  = False
        c.skip_altdns = False
        c.skip_params = True
        c.skip_ffuf   = True

    c.setup_paths()
    c.setup_dirs()
    check_deps()

    # Start background ffuf-subs thread if not skipped
    ffuf_subs_thread = None
    if not c.skip_ffuf:
        import threading
        ffuf_subs_thread = threading.Thread(target=run_ffuf_subs, args=(c,))
        ffuf_subs_thread.start()
        log("Started subdomain bruteforce (ffuf) in the background...")

    # ── Sequential pipeline ──────────────────────────────────────────────────
    stage_subdomain_enum(c)

    if ffuf_subs_thread is not None:
        log("Waiting for ffuf subdomain bruteforce to finish before DNS resolution...")
        ffuf_subs_thread.join()
        ffuf_subs_thread = None
        ffuf_json = c.dir_subs / "ffuf.json"
        ffuf_txt  = c.dir_subs / "ffuf.txt"
        if ffuf_json.exists():
            found = []
            try:
                import json as _json
                data = _json.loads(ffuf_json.read_text())
                for r in data.get("results", []):
                    host = r.get("host") or r.get("input", {}).get("FUZZ", "")
                    if host:
                        found.append(f"{host}.{c.domain}" if not host.endswith(c.domain) else host)
            except Exception:
                pass
            write_sorted_unique(ffuf_txt, found)
        if ffuf_txt.exists() and count_lines(ffuf_txt) > 0:
            existing = read_lines(c.dir_subs / "all_subdomains.txt")
            merged   = list(set(existing) | set(read_lines(ffuf_txt)))
            write_sorted_unique(c.dir_subs / "all_subdomains.txt", merged)
            ok(f"ffuf added {count_lines(ffuf_txt)} subdomain candidates → merged into all_subdomains.txt")

    stage_dnsx(c)
    stage_httpx(c)
    stage_port_scan(c)

    # Stage 4: URL collection (Katana on 200/301/302 + raw Waybackurls; no httpx on Wayback URLs)
    stage_url_collection(c)

    # Stage 5a: JS analysis + endpoint extraction (JS + Katana + Wayback)
    stage_js_analysis(c)

    # Stage 5b: FFUF vhost (only when --vhost is specified)
    stage_ffuf_vhost(c)

    # Stage 5c: Wayback backup/secret analysis
    stage_wayback_analysis(c)

    # Stage 5d: Arjun — live 200 + raw Wayback dynamic URLs + API endpoints
    stage_param_fuzzing(c)

    # Stage 5e: Nuclei — after all above; feeds live_200 + APIs + Arjun results
    stage_nuclei(c)

    print_summary(c)


if __name__ == "__main__":
    main()
