# FULL RECON
### Automated Web Reconnaissance & Attack Surface Discovery Framework

**FULL RECON** is a Python-based reconnaissance automation framework designed to streamline the initial stages of web application penetration testing and bug bounty hunting.

It integrates multiple open-source security tools into a unified workflow to automate subdomain enumeration, DNS resolution, HTTP probing, endpoint discovery, JavaScript analysis, and vulnerability scanning.

The framework focuses on reducing repetitive manual work, improving reconnaissance efficiency, and organizing results for further security assessments.

## Key Features

- **Automated Reconnaissance:** Execute multiple reconnaissance stages through a single workflow.
- **Parallel Execution:** Run independent enumeration and discovery tools concurrently to reduce execution time.
- **Subdomain Enumeration:** Combine passive discovery, DNS brute-forcing, and HTTP-based discovery.
- **DNS Validation:** Resolve discovered subdomains and identify valid DNS records.
- **HTTP/HTTPS Probing:** Identify accessible web services and active hosts.
- **Web Crawling:** Discover endpoints and resources through automated crawling.
- **Historical URL Collection:** Retrieve archived URLs to expand endpoint coverage.
- **JavaScript Analysis:** Extract potentially interesting endpoints and references from JavaScript files, including those discovered through historical URLs.
- **Parameter Discovery:** Identify HTTP parameters for further security testing.
- **Vulnerability Scanning:** Integrate Nuclei for template-based security checks.
- **Interactive Terminal UI:** Display tool banners, execution progress, and individual progress bars.
- **Organized Results:** Store reconnaissance findings for subsequent analysis.

## Tools Integrated

| Tool | Purpose |
|---|---|
| Subfinder | Passive subdomain enumeration |
| Assetfinder | Additional subdomain discovery |
| ShuffleDNS | DNS brute-forcing and resolution |
| MassDNS | High-performance DNS resolution backend |
| FFUF | HTTP/HTTPS discovery and fuzzing |
| DNSx | DNS validation and record lookup |
| HTTPx | Live host and web service probing |
| Katana | Web crawling and endpoint discovery |
| Waybackurls | Historical URL collection |
| Arjun | HTTP parameter discovery |
| Nuclei | Template-based vulnerability scanning |

## Reconnaissance Workflow

The framework follows a multi-stage reconnaissance pipeline.

### Stage 1 — Subdomain Discovery

The framework collects subdomains using multiple techniques:

- Passive enumeration with Subfinder and Assetfinder.
- DNS brute-forcing using ShuffleDNS and MassDNS.
- HTTPS and HTTP discovery using FFUF.
- DNS resolution and validation.

Independent discovery tasks can execute concurrently, with the pipeline waiting for their completion before dependent stages proceed.

### Stage 2 — Host Validation

Discovered assets are processed using DNSx and HTTPx to identify resolvable domains and accessible web services.

### Stage 3 — Endpoint Discovery

Katana crawls accessible web applications while Waybackurls retrieves historical URLs.

This expands coverage beyond currently linked pages.

### Stage 4 — JavaScript Analysis

JavaScript resources discovered through crawling and historical URL collection are analyzed for potentially interesting paths, endpoints, and references.

### Stage 5 — Parameter Discovery

Arjun identifies HTTP parameters that may be useful during subsequent manual testing.

### Stage 6 — Vulnerability Scanning

Nuclei performs template-based checks against in-scope targets to identify potential security weaknesses requiring validation.

## Execution Flow

```text
                   TARGET DOMAIN
                         |
             +-----------+-----------+
             |                       |
       PASSIVE DISCOVERY       ACTIVE DISCOVERY
             |                       |
     Subfinder + Assetfinder    ShuffleDNS + FFUF
             |                       |
             +-----------+-----------+
                         |
                  DNS VALIDATION
                       DNSx
                         |
                   HTTP PROBING
                       HTTPx
                         |
             +-----------+-----------+
             |                       |
         WEB CRAWLING          HISTORICAL URLS
            Katana              Waybackurls
             |                       |
             +-----------+-----------+
                         |
                  JS ANALYSIS
                         |
                 PARAMETER DISCOVERY
                       Arjun
                         |
                 VULNERABILITY SCAN
                       Nuclei
                         |
                 ORGANIZED RESULTS
```

## Requirements

- Python 3
- Linux environment (Kali Linux recommended)
- Go-based reconnaissance tools
- Required wordlists and DNS resolvers
- Internet connectivity

All external tools must be installed and accessible through the system's `PATH`.

**Important:** Use the ProjectDiscovery version of HTTPx rather than the unrelated Python HTTPx CLI.

## Usage

Run the framework's main Python entry point:

```bash
python3 <main_script>.py
```

The framework prompts for the target domain and relevant configuration, including wordlists and DNS resolvers.

*Replace the placeholder with the actual entry-point filename in your repository.*

## Terminal Experience

FULL RECON includes a terminal interface designed to make long-running reconnaissance operations easier to follow.

It provides:

- ASCII tool banners
- Individual tool progress bars
- Dependency checks
- Stage-by-stage execution updates
- Tool completion and error reporting

## Use Cases

**Bug Bounty Hunting:** Automate initial reconnaissance and discover potentially overlooked assets.

**Web Application Penetration Testing:** Collect domains, endpoints, JavaScript resources, and parameters for manual assessment.

**Attack Surface Mapping:** Build a broader view of publicly exposed web assets.

**Security Research:** Experiment with reconnaissance techniques and tool orchestration.

## Design Philosophy

FULL RECON was built around three principles:

**Automation without losing visibility.** Reduce repetitive commands while retaining visibility into each tool's execution.

**Combine complementary techniques.** Passive discovery, active enumeration, crawling, and historical analysis reveal different parts of an attack surface.

**Keep the workflow extensible.** A modular Python architecture makes it easier to maintain integrations and introduce additional reconnaissance capabilities.

## Disclaimer

This framework is intended strictly for authorized penetration testing, bug bounty programs, and security research.

Active scanning and fuzzing must only be performed against assets for which explicit permission has been granted. Users are responsible for respecting program scope, rate limits, and applicable laws.

## Author

**Ojasva Srivastava**

Cybersecurity Enthusiast | Red Teaming | Web Application Security | Reconnaissance Automation

*Built to make reconnaissance faster, more structured, and easier to manage.*

## License

License to be determined.
