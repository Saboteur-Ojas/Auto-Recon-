from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .config import Config, WL_OPTIONS
from .core.utils import (
    console, log, ok, warn, err, find_tool, has_tool, run_cmd,
    make_progress, stage_header
)

def parse_args() -> Config:
    p = argparse.ArgumentParser(
        description="Full Recon — Bug Hunting & CTF Edition v3.0",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-d", "--domain", default="")
    p.add_argument("domain_positional", nargs="?", default="")
    p.add_argument("-o", "--outbase", type=Path,
                   default=Path.home() / "Desktop" / "recon-results")
    p.add_argument("-w", "--wordlist", default="", dest="dns_wordlist")
    p.add_argument("-p", "--perm-wordlist", default="")
    p.add_argument("-r", "--resolvers", default="")
    p.add_argument("-c", "--custom-templates", default="./nuclei-templates-custom")
    p.add_argument("-s", "--severity", default="critical,high,medium", dest="nuclei_severity")
    p.add_argument("--rl",  type=int, default=30,  dest="nuclei_rate_limit")
    p.add_argument("--altdns",      action="store_true")
    p.add_argument("--no-ffuf",     action="store_true")
    p.add_argument("--no-asn",      action="store_true")
    p.add_argument("--no-params",   action="store_true")
    p.add_argument("--ports",       action="store_true")
    p.add_argument("--ctf",         action="store_true")
    p.add_argument("--resume",      action="store_true")
    p.add_argument("--ffuf-bg",     action="store_true")
    p.add_argument("--vhost",      action="store_true", help="Enable FFUF vhost discovery")
    p.add_argument("--ffuf-vhost",  default="",  dest="ffuf_vhost_wordlist")
    p.add_argument("--ffuf-hosts",  type=int, default=20, dest="ffuf_max_hosts")
    p.add_argument("--httpx-t",     type=int, default=20, dest="httpx_threads")
    p.add_argument("--dnsx-t",      type=int, default=100, dest="dnsx_threads")
    p.add_argument("--ffuf-t",      type=int, default=10,  dest="ffuf_threads")
    p.add_argument("--js-p",        type=int, default=20,  dest="js_parallel")
    p.add_argument("--naabu-t",     default="1000", dest="naabu_top_ports")
    a = p.parse_args()

    raw_domain = a.domain or a.domain_positional or ""
    parsed_domain = re.sub(r'^https?://', '', raw_domain.lower()).split("/")[0]

    c = Config(
        domain=parsed_domain,
        outbase=a.outbase.resolve(),
        dns_wordlist=a.dns_wordlist,
        perm_wordlist=a.perm_wordlist,
        resolvers=a.resolvers,
        custom_templates=a.custom_templates,
        nuclei_severity=a.nuclei_severity,
        nuclei_rate_limit=a.nuclei_rate_limit,
        httpx_threads=a.httpx_threads,
        dnsx_threads=a.dnsx_threads,
        ffuf_threads=a.ffuf_threads,
        js_parallel=a.js_parallel,
        naabu_top_ports=a.naabu_top_ports,
        ffuf_max_hosts=a.ffuf_max_hosts,
        skip_ffuf=a.no_ffuf,
        skip_altdns=False,
        run_vhost=a.vhost,
        skip_asn=a.no_asn,
        skip_params=a.no_params,
        skip_ports=not a.ports,
        resume=a.resume,
        ctf_mode=a.ctf,
        bg_ffuf=a.ffuf_bg,
    )
    if a.ffuf_vhost_wordlist:
        c.ffuf_vhost_wordlist = a.ffuf_vhost_wordlist
    return c

def prompt_domain(c: Config) -> None:
    if c.domain:
        return
    if not sys.stdin.isatty():
        err("No -d <domain> supplied and not interactive. Aborting.")
        sys.exit(1)
    console.print("[bold cyan][?][/bold cyan] No target domain specified.")
    while True:
        try:
            raw = input("    Enter target domain (e.g. example.com): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print()
            sys.exit(1)
        raw = re.sub(r'^https?://', '', raw).split("/")[0]
        if raw:
            c.domain = raw
            ok(f"Target: {c.domain}")
            break
        warn("Domain cannot be empty.")

def select_wordlist(c: Config) -> None:
    if c.dns_wordlist:
        log(f"Using wordlist: {c.dns_wordlist}")
        return
    if not sys.stdin.isatty():
        c.dns_wordlist = WL_OPTIONS["1"]
        warn(f"Non-interactive — defaulting wordlist: {c.dns_wordlist}")
        return
    console.print("\n[bold cyan]Select subdomain bruteforce wordlist:[/bold cyan]")
    for k, v in WL_OPTIONS.items():
        suffix = "  [fastest]" if k == "1" else ""
        console.print(f"  {k}) {v}{suffix}")
    console.print("  5) Custom path\n")
    try:
        choice = input("Enter choice [1-5]: ").strip()
    except (KeyboardInterrupt, EOFError):
        console.print()
        sys.exit(1)
    if choice in WL_OPTIONS:
        c.dns_wordlist = WL_OPTIONS[choice]
    elif choice == "5":
        try:
            c.dns_wordlist = input("Path: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            sys.exit(1)
    else:
        warn("Invalid — defaulting to option 1")
        c.dns_wordlist = WL_OPTIONS["1"]
    if not Path(c.dns_wordlist).is_file():
        warn(f"Wordlist not found: {c.dns_wordlist} (bruteforce stages skipped)")
    else:
        ok(f"Wordlist: {c.dns_wordlist}")

def select_resolvers(c: Config) -> None:
    if c.resolvers and Path(c.resolvers).is_file():
        ok(f"Resolver list: {c.resolvers}")
        return
    if c.resolvers and not Path(c.resolvers).is_file():
        warn(f"Resolver list not found: {c.resolvers} — shuffledns wildcard mode will use system resolvers")
        c.resolvers = ""
        return
    if not sys.stdin.isatty():
        warn("Non-interactive — no resolver list supplied.")
        return
    console.print("\n[bold cyan]Resolver list for shuffledns:[/bold cyan]")
    console.print("  1) /opt/resolvers/resolvers.txt")
    console.print("  2) /usr/share/seclists/Miscellaneous/dns-resolvers.txt")
    console.print("  3) Custom path")
    console.print("  4) Skip\n")
    RESOLVER_OPTIONS = {
        "1": "/opt/resolvers/resolvers.txt",
        "2": "/usr/share/seclists/Miscellaneous/dns-resolvers.txt",
    }
    try:
        choice = input("Enter choice [1-4]: ").strip()
    except (KeyboardInterrupt, EOFError):
        console.print()
        sys.exit(1)
    if choice in RESOLVER_OPTIONS:
        path = RESOLVER_OPTIONS[choice]
        if Path(path).is_file():
            c.resolvers = path
            ok(f"Resolver list: {c.resolvers}")
        else:
            warn(f"Not found: {path} — skipping resolver list")
    elif choice == "3":
        try:
            path = input("Path to resolver list: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print()
            sys.exit(1)
        if Path(path).is_file():
            c.resolvers = path
            ok(f"Resolver list: {c.resolvers}")
        else:
            warn(f"Not found: {path} — skipping resolver list")
    else:
        warn("Skipping resolver list")

# GAU removed — no longer in REQUIRED or OPTIONAL
REQUIRED = ["subfinder", "assetfinder", "shuffledns", "dnsx", "httpx",
            "katana", "waybackurls", "nuclei", "curl", "jq"]
OPTIONAL = ["asnmap", "mapcidr", "altdns", "arjun", "ffuf", "parallel", "naabu"]

# GAU removed — no longer in REQUIRED or OPTIONAL
REQUIRED = ["subfinder", "assetfinder", "shuffledns", "dnsx", "httpx",
            "katana", "waybackurls", "nuclei", "curl", "jq"]
OPTIONAL = ["asnmap", "mapcidr", "altdns", "arjun", "ffuf", "parallel", "naabu"]

def check_deps() -> None:
    stage_header("Checking dependencies")
    missing = []
    with make_progress() as prog:
        t = prog.add_task("Required tools", total=len(REQUIRED))
        for tool in REQUIRED:
            loc = find_tool(tool)
            if loc:
                prog.console.print(f"  [green]✔[/green] {tool:<20} [dim]{loc}[/dim]")
            else:
                prog.console.print(f"  [red]✘[/red] {tool}")
                missing.append(tool)
            prog.advance(t)
    if missing:
        err(f"Missing required tools: {', '.join(missing)}")
        sys.exit(1)
    ok("All required tools found.")
    for tool in OPTIONAL:
        if not has_tool(tool):
            warn(f"Optional: {tool} not found (stage will fallback or skip)")
