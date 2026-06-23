#!/usr/bin/env python3
"""
Automatic Recon Framework
By Ojasva Srivastava

For authorized bug bounty, CTF, and personal lab use only.
"""

from arf.cli import parse_args, prompt_domain, select_wordlist, select_resolvers, check_deps
from arf.core.utils import print_banner
from arf.stages import (
    stage_subdomain_enum, stage_dnsx, stage_httpx, stage_port_scan,
    stage_url_collection, stage_js_analysis, stage_ffuf_vhost,
    stage_wayback_analysis, stage_param_fuzzing, stage_nuclei, print_summary
)

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

if __name__ == "__main__":
    main()
