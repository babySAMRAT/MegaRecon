# MegaRecon

```
  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚════╝
```

**MegaRecon** is a guided, menu-driven CLI orchestrator for authorized web application recon.
Inspired by the modular, user-friendly design of Airgeddon — built for web app pentesters.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## What Makes MegaRecon Different

Most pentesters run 10+ tools in separate terminals, copy-paste outputs, and manually
sort through thousands of URLs. MegaRecon solves that by:

- **Guided menus** — no need to remember flags or tool syntax
- **Staged workflows** — 11 stages from subdomain discovery to nuclei checks
- **Unique features** not found in other orchestrators (see below)
- **Scope enforcement** — ScopeGuard drops everything outside your approved target
- **Clean outputs** — normalized files, ranked priorities, ready-to-use exports

---

## Unique Features

### 1. JS Secret Hunter
Automatically downloads every `.js` file from discovered URLs and scans them for:
- AWS Access Keys, Google API Keys, GitHub PATs
- Bearer tokens, OAuth secrets, JWT tokens
- Firebase URLs, MongoDB URIs, DB connection strings
- Stripe, Twilio, SendGrid, Slack keys
- Private keys (RSA, EC, OpenSSH)
- 20 pattern types total

Output: `reports/js_secrets.json`

### 2. WAF Bypass Suggester
After `wafw00f` detects a WAF, MegaRecon prints **vendor-specific bypass techniques** instead
of just naming the WAF. Covers:
- Cloudflare (H2.TE smuggling, Unicode tricks, origin IP via Shodan)
- Akamai (Ghost IP enumeration, mixed-case methods)
- AWS WAF (nested JSON, chunked encoding, crt.sh origin leaks)
- Imperva, F5 BIG-IP, Sucuri, Generic fallback

### 3. Tech Stack Attack Map
Parses `httpx` output for known technology fingerprints, then maps each detected tech to:
- Known CVEs (e.g. Spring4Shell, Log4Shell-adjacent, Drupalgeddon)
- Ready-to-run `nuclei` commands with the right tags
- 20 supported tech signatures: WordPress, Laravel, Django, Spring, Drupal, Joomla,
  Flask, Rails, Node, React, GraphQL, Jenkins, Tomcat, IIS, Redis, Elasticsearch, and more

Output: `reports/tech_attack_map.json`

### 4. Subdomain Takeover Checker
Fingerprints discovered subdomains for dangling DNS/CNAME takeover indicators across
25+ services including GitHub Pages, Heroku, Netlify, AWS S3, Azure Blob, Shopify,
Fastly, Zendesk, Tumblr, Bitbucket, Intercom, UserVoice, Pingdom, and more.

Output: `reports/takeover.json`

### 5. Smart Priority Scorer
Ranks every discovered URL using multi-signal scoring:
- Admin/auth/upload/reset paths (+35–45 pts)
- IDOR-prone numeric IDs (+45 pts)
- GraphQL, Swagger, API docs (+38 pts)
- Sensitive file extensions (.env, .git, .bak, .sql) (+35 pts)
- Debug/actuator/internal routes (+35 pts)
- SSRF-prone redirect params (+32 pts)
- Parameter count multiplier
- JS files, versioned API paths

Output: `reports/priority.txt` (tab-separated: score, URL, reason)

### 6. Recon Diff Mode
Compare two MegaRecon runs on the same target and see exactly:
- New subdomains discovered
- New live hosts
- New endpoints/URLs
- Removed/changed assets

Perfect for retests, bug bounty monitoring, and showing client-side change.
Output: `reports/diff.json`

### 7. Burp Suite XML Export
Auto-generates a Burp Suite-compatible XML sitemap from all priority-scored URLs.
Import directly into Burp → Target → Site Map.
Includes score and reason in the comment field for each item.

Output: `reports/burp_import.xml`

### 8. Replay Pack
Auto-generates a ready-to-run bash script with `curl` commands for the top 30
priority endpoints. Quick way to manually validate interesting findings.

Output: `reports/replay_pack.sh`

### 9. Mermaid Recon Graph
Generates a Mermaid flowchart of discovered hosts and URL paths.
Paste into any Mermaid renderer (GitHub markdown, Notion, Obsidian) for a visual map.

Output: `reports/recon_graph.mmd`

---

## Profiles

| Profile | Description | Tools |
|---------|-------------|-------|
| `passive` | No active requests — pure passive collection | subfinder, assetfinder, amass, gau, waybackurls, httpx |
| `balanced` | Client-safe default — recommended for most assessments | + wafw00f, katana, nuclei |
| `deep` | High-noise — full enumeration with content discovery | + ffuf, arjun, subjack |

---

## Intensity Levels

| Level | httpx rate | ffuf rate | Threads | When to use |
|-------|-----------|-----------|---------|-------------|
| `low` | 35 | 40 | 10 | Fragile targets, soft recon |
| `medium` | 75 | 100 | 25 | Standard client work |
| `high` | 150 | 200 | 50 | Full-scope, rate limits approved |

---

## Install

### 1. Clone the repo
```bash
git clone https://github.com/yourname/MegaRecon.git
cd MegaRecon
```

### 2. Install Python dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Install external tools

**Go-based tools** (requires Go installed):
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/haccer/subjack@latest
```

**Python/apt-based tools:**
```bash
pip install wafw00f arjun
sudo apt install amass -y
```

**Add Go binaries to PATH:**
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

**Recommended: Install SecLists for ffuf wordlists:**
```bash
sudo apt install seclists -y
# or: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

---

## Usage

### Interactive Menu (recommended)
```bash
python3 megarecon.py
```

On launch, MegaRecon will:
1. Show the banner
2. Run **Tool Doctor** to show which dependencies are available
3. Drop you into the **numbered main menu**

### Non-interactive / scripting mode
```bash
# Passive recon
python3 megarecon.py run -t example.com -p passive -i low --no-nuclei

# Balanced recon (default)
python3 megarecon.py run -t example.com -p balanced -i medium

# Deep recon with content discovery
python3 megarecon.py run -t https://app.example.com -p deep -i high --ffuf -w /path/to/wordlist.txt

# Skip JS hunting and takeover checks
python3 megarecon.py run -t example.com --no-js-hunt --no-takeover
```

---

## Output Structure

Each run creates a timestamped folder in `output/`:

```
output/
└── example-com-20260624-153000/
    ├── raw/                     # Raw tool outputs
    │   ├── subfinder.txt
    │   ├── assetfinder.txt
    │   ├── amass.txt
    │   ├── waf.txt
    │   ├── gau.txt
    │   ├── wayback.txt
    │   ├── katana.txt
    │   ├── ffuf.md
    │   └── nuclei.txt
    ├── normalized/              # Deduplicated, in-scope
    │   ├── subdomains.txt
    │   ├── alive.txt
    │   └── urls.txt
    ├── reports/                 # Final outputs
    │   ├── summary.md           ← Main report
    │   ├── priority.txt         ← Scored URL list
    │   ├── replay_pack.sh       ← Curl validation pack
    │   ├── burp_import.xml      ← Burp Suite import
    │   ├── recon_graph.mmd      ← Mermaid graph
    │   ├── js_secrets.json      ← JS secret findings
    │   ├── tech_attack_map.json ← Tech → CVE mapping
    │   └── takeover.json        ← Takeover candidates
    └── logs/                    # Per-tool logs for debugging
```

---

## Main Menu Options

```
 [ 1]  Recon Wizard                  Guided full-featured recon workflow
 [ 2]  Quick Passive Recon           Subdomains + historical URLs only
 [ 3]  Quick Deep Recon              Aggressive recon
 ·····················
 [ 4]  JS Secret Hunter              Standalone — scan a URL list
 [ 5]  WAF Bypass Suggester          Standalone — bypass hints for a WAF
 [ 6]  Tech Stack Attack Map         Standalone — map alive.txt to CVEs
 [ 7]  Subdomain Takeover Checker    Standalone — check a subdomain list
 ·····················
 [ 8]  Recon Diff (Compare Runs)     Detect changes between two past runs
 ·····················
 [ 9]  Show Profiles                 View profile details
 [10]  Tool Doctor                   Check installed dependencies
 ·····················
 [ 0]  Exit
```

---

## Roadmap / Planned Features

- [ ] YAML config file support (`config.yaml`)
- [ ] Plugin system for custom modules
- [ ] Screenshot capture module (gowitness)
- [ ] HTML report with embedded charts
- [ ] Parameter fuzzing prep (Burp intruder payload export)
- [ ] Shodan/Censys API integration for origin IP discovery
- [ ] SQLite backend for persistent run storage
- [ ] Docker container (`docker run megarecon -t example.com`)
- [ ] Unit tests and GitHub Actions CI
- [ ] Notification support (Slack/Telegram on completion)

---

## Disclaimer

> MegaRecon is built for authorized security testing only.
> The user is fully responsible for:
> - Obtaining written authorization before testing any target
> - Complying with all applicable laws and regulations
> - Respecting scope boundaries and rate limits
> - Any actions performed using this tool

Using MegaRecon against targets you do not have permission to test is illegal.

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Made with ❤️ by Aryan*
