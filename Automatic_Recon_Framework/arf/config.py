from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Set

from .core.utils import ok, warn, touch, count_lines

@dataclass
class Config:
    domain: str = ""
    outbase: Path = field(default_factory=lambda: Path.home() / "Desktop" / "recon-results")
    dns_wordlist: str = ""
    perm_wordlist: str = ""
    resolvers: str = ""
    custom_templates: str = "./nuclei-templates-custom"
    nuclei_severity: str = "critical,high,medium"
    nuclei_rate_limit: int = 30
    httpx_threads: int = 20
    dnsx_threads: int = 100
    ffuf_threads: int = 10
    js_parallel: int = 20
    arjun_threads: int = 10
    naabu_top_ports: str = "1000"
    max_param_targets: int = 100
    cidr_scan_limit: int = 65536
    ffuf_vhost_wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    ffuf_max_hosts: int = 20
    skip_ffuf: bool = False
    skip_altdns: bool = False
    run_vhost: bool = False
    skip_asn: bool = False
    skip_params: bool = False
    skip_ports: bool = True
    resume: bool = False
    ctf_mode: bool = False
    bg_ffuf: bool = False
    # paths (populated by setup_paths)
    outdir:      Path = field(default_factory=Path)
    dir_subs:    Path = field(default_factory=Path)
    dir_dns:     Path = field(default_factory=Path)
    dir_http:    Path = field(default_factory=Path)
    dir_urls:    Path = field(default_factory=Path)
    dir_js:      Path = field(default_factory=Path)
    dir_ffuf:    Path = field(default_factory=Path)
    dir_wayback: Path = field(default_factory=Path)
    dir_nuclei:  Path = field(default_factory=Path)
    dir_params:  Path = field(default_factory=Path)
    dir_ports:   Path = field(default_factory=Path)
    report_file: Path = field(default_factory=Path)

    def setup_paths(self) -> None:
        self.outdir      = self.outbase / self.domain
        self.dir_subs    = self.outdir / "subdomains"
        self.dir_dns     = self.outdir / "dns"
        self.dir_http    = self.outdir / "http"
        self.dir_urls    = self.outdir / "urls"
        self.dir_js      = self.outdir / "js"
        self.dir_ffuf    = self.outdir / "ffuf"
        self.dir_wayback = self.outdir / "wayback"
        self.dir_nuclei  = self.outdir / "nuclei"
        self.dir_params  = self.outdir / "params"
        self.dir_ports   = self.outdir / "ports"
        self.report_file = self.outdir / f"{self.domain}_recon_summary.txt"

    def setup_dirs(self) -> None:
        for d in [
            self.dir_subs, self.dir_dns, self.dir_http, self.dir_urls,
            self.dir_js / "raw", self.dir_js / "maps",
            self.dir_wayback, self.dir_nuclei, self.dir_params,
            self.dir_ffuf / "vhosts", self.dir_ports,
        ]:
            d.mkdir(parents=True, exist_ok=True)
        # Pre-create important result files so interrupted scans still leave a clean structure.
        result_files = [
            self.dir_ports / "open_ports.txt",
            self.dir_subs / "subfinder.txt",
            self.dir_subs / "assetfinder.txt",
            self.dir_subs / "crtsh.txt",
            self.dir_subs / "asn_ptr_hosts.txt",
            self.dir_subs / "shuffledns.txt",
            self.dir_subs / "ffuf.txt",
            self.dir_subs / "altdns_candidates.txt",
            self.dir_subs / "all_subdomains.txt",
            self.dir_dns / "resolved.txt",
            self.dir_dns / "resolved_hosts.txt",
            self.dir_http / "httpx_full.json",
            self.dir_http / "httpx_readable.txt",
            self.dir_http / "live_hosts.txt",
            self.dir_http / "live_200.txt",
            self.dir_http / "live_redirects.txt",
            self.dir_http / "live_403.txt",
            self.dir_urls / "katana.txt",
            self.dir_urls / "waybackurls.txt",
            self.dir_urls / "all_urls.txt",
            self.dir_urls / "js_urls.txt",
            self.dir_js / "url_map.txt",
            self.dir_js / "failed_downloads.txt",
            self.dir_js / "secrets.txt",
            self.dir_js / "endpoints.txt",
            self.dir_js / "endpoints_absolute.txt",
            self.dir_js / "endpoints_relative.txt",
            self.dir_js / "sourcemap_sources.txt",
            self.dir_ffuf / "all_vhosts.txt",
            self.dir_wayback / "backup_files.txt",
            self.dir_wayback / "backup_files_live.txt",
            self.dir_wayback / "url_secrets.txt",
            self.dir_wayback / "wayback_url_secrets.txt",
            self.dir_params / "targets.txt",
            self.dir_params / "discovered_params.txt",
            self.dir_nuclei / "nuclei_targets.txt",
            self.dir_nuclei / "nuclei_results.txt",
        ]
        for f in result_files:
            touch(f)
        ok(f"Output directory: {self.outdir}")

    def should_skip(self, label: str, sentinel: Path) -> bool:
        if self.resume and sentinel.exists() and count_lines(sentinel) > 0:
            ok(f"RESUME: {label} already done ({count_lines(sentinel)} lines) — skipping")
            return True
        return False

WL_OPTIONS = {
    "1": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "2": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "3": "/usr/share/seclists/Discovery/DNS/shubs-subdomains.txt",
    "4": "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
}
