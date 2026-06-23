# Automatic Recon Framework

A Python-based recon automation framework for authorized bug bounty, CTF, and personal lab testing.

## Features

- Passive subdomain enumeration
- Active subdomain bruteforcing
- DNS resolution with dnsx
- HTTP probing with httpx
- Katana crawling
- Wayback URL collection
- JS endpoint and secret extraction
- Wayback sensitive-path extraction
- Arjun parameter discovery
- Nuclei scanning
- Optional FFUF vhost discovery
- CTF mode with directory fuzzing


## Install all tools and dependencies

Run:

```bash
chmod +x requiremntent.sh
./requiremntent.sh
```

The full external tool list is available in:

```text
TOOLS.md
```


## Usage

```bash
chmod +x run.sh
./run.sh -d example.com
```

CTF mode:

```bash
./run.sh -d example.com --ctf
```

Optional vhost discovery:

```bash
./run.sh -d example.com --vhost
```

Custom output directory:

```bash
./run.sh -d example.com -o /home/kali/Desktop/recon-results
```

## Output

Results are saved under:

```text
~/Desktop/recon-results/<domain>/
```

## Disclaimer

Use only on targets you own, have permission to test, or are allowed to test under a bug bounty/CTF scope.
