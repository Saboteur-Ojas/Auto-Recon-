# Tools Used by Automatic Recon Framework

This file lists all external tools used by the framework.

## Required tools

- python3
- pip3
- git
- curl
- jq
- go
- subfinder
- assetfinder
- shuffledns
- massdns
- dnsx
- httpx
- katana
- waybackurls
- nuclei
- ffuf

## Optional tools

- altdns
- arjun
- naabu
- asnmap
- mapcidr
- parallel

## Python dependency

- rich

## Notes

- `massdns` is required by `shuffledns`.
- `altdns`, `arjun`, `naabu`, `asnmap`, `mapcidr`, and `parallel` are optional, but useful.
- Go tools are installed into `$HOME/go/bin`.
- Make sure `$HOME/go/bin` is in your PATH.
