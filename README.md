# MegaRecon

MegaRecon is a guided CLI orchestrator for **authorized** web application recon.

Instead of running many tools manually, MegaRecon gives you:
- Simple profiles
- WAF-aware intensity selection
- Scope protection
- Normalized outputs
- Priority scoring
- Replay packs
- Markdown reports

## Why this exists

During web app testing, recon usually becomes noisy and fragmented:
- One tool for subdomains
- One for live hosts
- One for URL collection
- One for crawling
- One for content discovery
- One for templated checks

MegaRecon combines the important recon steps into a single workflow so the tester can focus more on analysis and less on terminal chaos.

## Features

### Industry-standard tool wrappers
- `subfinder`
- `assetfinder`
- `amass`
- `httpx`
- `wafw00f`
- `gau`
- `waybackurls`
- `katana`
- `ffuf`
- `nuclei`

### Useful operator features
- **Profiles**: `passive`, `balanced`, `deep`
- **Intensity selection**: `low`, `medium`, `high`
- **ScopeGuard**: drops out-of-scope hosts and URLs
- **Priority scoring**: highlights juicy endpoints first
- **Replay pack**: auto-builds `curl` commands for quick validation
- **Recon graph**: Mermaid graph from discovered hosts and paths
- **Summary report**: clean markdown report per run
- **Tool doctor**: quickly shows missing dependencies

## Profiles

### passive
Quiet collection:
- Passive subdomains
- Historical URLs
- Light validation

### balanced
Best default for client work:
- Passive recon
- WAF detection
- Live host validation
- Historical URLs
- Crawling
- Safe nuclei checks

### deep
Noisier recon:
- Everything in `balanced`
- Content discovery with `ffuf`

## Install

### 1) Clone repo
```bash
git clone https://github.com/yourname/reconforge.git
cd reconforge
```

### 2) Install Python packages
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3) Install external tools
Example setup:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
sudo apt install amass -y
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
pip install wafw00f
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 4) Make sure your PATH is correct
Example:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Usage

### Show dependency status
```bash
python3 reconforge.py tools
```

### Show profiles
```bash
python3 reconforge.py profiles
```

### Guided wizard
```bash
python3 reconforge.py wizard
```

### Fast passive recon
```bash
python3 reconforge.py run -t example.com -p passive -i low --no-nuclei
```

### Normal client-safe recon
```bash
python3 reconforge.py run -t example.com -p balanced -i medium
```

### Deep recon with content discovery
```bash
python3 reconforge.py run -t https://app.example.com -p deep -i high --ffuf
```

## Output

Each run creates a timestamped folder in `output/`.

Example:
```text
output/example-com-20260624-153000/
├── raw/
├── normalized/
│   ├── subdomains.txt
│   ├── alive.txt
│   └── urls.txt
├── reports/
│   ├── summary.md
│   ├── priority.txt
│   ├── replay_pack.sh
│   └── recon_graph.mmd
└── logs/
```

## How intensity works

### low
Use when:
- Target looks fragile
- Client wants a very safe run
- You only need early mapping

### medium
Use when:
- Standard authenticated or unauthenticated recon is allowed
- You want a good signal/noise ratio

### high
Use when:
- Scope is approved for heavier enumeration
- WAF behavior is understood
- Rate limits are acceptable

## Safe defaults

ReconForge is designed to stay useful without becoming reckless:
- It keeps output inside approved host scope
- It uses safe nuclei tags by default
- It separates passive, balanced, and deep workflows
- It makes intensity explicit before running noisier stages

## Good next upgrades

Recommended v2 improvements:
- YAML config support
- Plugin system
- Per-tool rate controls
- Screenshot module
- JS secret and endpoint parser
- Param discovery module
- SQLite output backend
- HTML report export
- Docker support
- Unit tests and CI

## Disclaimer

Use ReconForge only on systems you are explicitly authorized to assess.

The user is responsible for:
- Scope validation
- Client approval
- Rate control
- Legal and contractual compliance