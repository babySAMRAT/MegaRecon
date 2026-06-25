#!/usr/bin/env python3
"""
███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚════╝

  MegaRecon v2.0 — Unified Web App Recon CLI
  Author : babySAMRAT | MegaRecon Project
  GitHub : https://github.com/babySAMRAT/MegaRecon
  License: MIT  |  Use ONLY on authorized targets
"""
import argparse
from typing import Optional

import json, os, re, shutil, subprocess, sys, urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt, IntPrompt
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] Missing deps. Run:  pip install rich")
    sys.exit(1)

console = Console()

VERSION = "2.0.0"
AUTHOR  = "babySAMRAT | MegaRecon Project"
GITHUB  = "https://github.com/babySAMRAT/MegaRecon"

BANNER = r"""[bold red]
  ███╗   ███╗███████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗ ████║██╔════╝██╔════╝ ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔████╔██║█████╗  ██║  ███╗███████║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚════╝
[/bold red]"""

# ─────────────────────────── REGISTRIES ────────────────────────────────────

TOOL_REGISTRY = {
    "subfinder":   {"cat": "Subdomains",        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder": {"cat": "Subdomains",        "install": "go install github.com/tomnomnom/assetfinder@latest"},
    "amass":       {"cat": "Subdomains",        "install": "sudo apt install amass -y"},
    "httpx":       {"cat": "Surface mapping",   "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "wafw00f":     {"cat": "Fingerprinting",    "install": "pip install wafw00f"},
    "gau":         {"cat": "Historical URLs",   "install": "go install github.com/lc/gau/v2/cmd/gau@latest"},
    "waybackurls": {"cat": "Historical URLs",   "install": "go install github.com/tomnomnom/waybackurls@latest"},
    "katana":      {"cat": "Crawler",           "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    "ffuf":        {"cat": "Content discovery", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    "nuclei":      {"cat": "Safe checks",       "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "arjun":       {"cat": "Param discovery",   "install": "pip install arjun"},
    "subjack":     {"cat": "Takeover checks",   "install": "go install github.com/haccer/subjack@latest"},
}

PROFILES = {
    "passive":  {"tools": ["subfinder","assetfinder","amass","gau","waybackurls","httpx"]},
    "balanced": {"tools": ["subfinder","assetfinder","amass","httpx","wafw00f","gau","waybackurls","katana","nuclei"]},
    "deep":     {"tools": ["subfinder","assetfinder","amass","httpx","wafw00f","gau","waybackurls","katana","ffuf","nuclei","arjun","subjack"]},
}

INTENSITY = {
    "low":    {"httpx_rate": 35,  "katana_rate": 10, "ffuf_rate": 40,  "threads": 10},
    "medium": {"httpx_rate": 75,  "katana_rate": 25, "ffuf_rate": 100, "threads": 25},
    "high":   {"httpx_rate": 150, "katana_rate": 50, "ffuf_rate": 200, "threads": 50},
}

# ─────────────────────── WAF BYPASS DATABASE ───────────────────────────────

WAF_BYPASS_DB: dict[str, list[str]] = {
    "cloudflare": [
        "Use chunked transfer encoding to bypass body inspection",
        "Unicode normalization tricks  e.g.  ＜script＞ instead of <script>",
        "Abuse Cloudflare Ray-ID inconsistencies to fingerprint origin IP",
        "HTTP/2 request smuggling (H2.TE) — Cloudflare is known vulnerable",
        "Fragment payloads across multiple parameters",
        "Try origin IP via Shodan: ssl.cert.subject.cn:target.com",
    ],
    "akamai": [
        "Header-based bypass: X-Forwarded-For / X-Real-IP manipulation",
        "Akamai Ghost IPs — enumerate origin via Shodan/Censys",
        "HTML entity encoding in JSON bodies to confuse body parser",
        "Mixed-case HTTP methods: GeT, PoSt — Akamai often ignores them",
        "Multipart/form-data content-type to evade body inspection rules",
    ],
    "aws": [
        "AWS WAF misses JSON-embedded payloads — try nested JSON keys",
        "Chunked transfer encoding for size-limit bypass",
        "Check for origin IP via certificate transparency logs (crt.sh)",
        "Unicode lookalikes bypass regex-based AWS WAF rules",
        "Try parameter pollution: ?id=1&id=<payload>",
    ],
    "imperva": [
        "HTTP Parameter Pollution (HPP) — Imperva has known gaps",
        "Double URL encoding for path traversal payloads",
        "Unusual Content-Type values confuse Imperva body parsers",
        "Try large headers to push WAF inspection buffer limits",
    ],
    "f5": [
        "F5 BIG-IP — check for iControl REST RCE family CVEs",
        "HTTP request smuggling: CL.TE or TE.CL variants",
        "Cookie manipulation to bypass session-based WAF rules",
        "Probe /tmui/login.jsp for exposed management interface",
    ],
    "sucuri": [
        "Sucuri relies on signature matching — try payload variations",
        "SSRF payloads to probe internal origin behind Sucuri",
        "OPTIONS/TRACE methods — Sucuri often ignores them",
        "Slow POST attack to fingerprint timeout behavior",
    ],
    "generic": [
        "Insert null bytes (%00) in payloads",
        "Try unusual HTTP verbs: PATCH, CONNECT, PROPFIND",
        "Origin IP discovery via Shodan, Censys, SecurityTrails",
        "HTTP parameter pollution to split payload across params",
        "Slow HTTP attack to fingerprint WAF timeout thresholds",
        "Try IP-direct access after finding origin via DNS history",
    ],
}

# ─────────────────────── TECH ATTACK MAP ───────────────────────────────────

TECH_ATTACK_MAP: dict[str, dict] = {
    "wordpress":  {"cves": ["CVE-2021-29447","CVE-2022-21663","CVE-2023-2732"],       "nuclei_tags": ["wordpress","wp-plugin","wp-theme"]},
    "laravel":    {"cves": ["CVE-2021-3129","CVE-2022-40940"],                         "nuclei_tags": ["laravel","php"]},
    "django":     {"cves": ["CVE-2021-31542","CVE-2022-28347"],                        "nuclei_tags": ["django","python"]},
    "spring":     {"cves": ["CVE-2022-22965","CVE-2022-22963","CVE-2021-22096"],       "nuclei_tags": ["spring","java","springboot"]},
    "drupal":     {"cves": ["CVE-2019-6340","CVE-2022-25271"],                         "nuclei_tags": ["drupal"]},
    "joomla":     {"cves": ["CVE-2023-23752","CVE-2021-26027"],                        "nuclei_tags": ["joomla"]},
    "nginx":      {"cves": ["CVE-2021-23017"],                                         "nuclei_tags": ["nginx","misconfig"]},
    "apache":     {"cves": ["CVE-2021-41773","CVE-2021-42013","CVE-2022-31813"],       "nuclei_tags": ["apache"]},
    "node":       {"cves": ["CVE-2022-32212","CVE-2023-30581"],                        "nuclei_tags": ["node","express","javascript"]},
    "react":      {"cves": [],                                                          "nuclei_tags": ["javascript","api","graphql"]},
    "graphql":    {"cves": ["CVE-2023-28159"],                                         "nuclei_tags": ["graphql"]},
    "jenkins":    {"cves": ["CVE-2024-23897","CVE-2023-27898"],                        "nuclei_tags": ["jenkins"]},
    "tomcat":     {"cves": ["CVE-2020-9484","CVE-2022-34305"],                         "nuclei_tags": ["tomcat","java"]},
    "iis":        {"cves": ["CVE-2022-30209","CVE-2021-31166"],                        "nuclei_tags": ["iis","windows"]},
    "php":        {"cves": ["CVE-2022-31625","CVE-2022-37454"],                        "nuclei_tags": ["php"]},
    "flask":      {"cves": ["CVE-2023-30861"],                                         "nuclei_tags": ["python","flask"]},
    "rails":      {"cves": ["CVE-2022-32224","CVE-2023-22794"],                        "nuclei_tags": ["ruby","rails"]},
    "mongodb":    {"cves": ["CVE-2021-32036"],                                         "nuclei_tags": ["mongodb","database"]},
    "mysql":      {"cves": [],                                                          "nuclei_tags": ["mysql","database"]},
    "redis":      {"cves": ["CVE-2022-0543"],                                          "nuclei_tags": ["redis","database"]},
    "elasticsearch":{"cves":["CVE-2021-22145","CVE-2023-31419"],                       "nuclei_tags": ["elasticsearch","exposure"]},
}

# ─────────────────────── JS SECRET PATTERNS ────────────────────────────────

JS_PATTERNS: list[tuple[str,str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',      "API Key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',   "Secret Key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',               "Hardcoded Password"),
    (r'AKIA[0-9A-Z]{16}',                                                           "AWS Access Key ID"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', "AWS Secret Key"),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                    "Google API Key"),
    (r'(?i)(firebase[_-]?url|databaseURL)\s*[=:]\s*["\']([^"\']+)["\']',          "Firebase URL"),
    (r'ghp_[0-9A-Za-z]{36}',                                                       "GitHub PAT"),
    (r'ghs_[0-9A-Za-z]{36}',                                                       "GitHub Actions Token"),
    (r'(?i)(bearer|authorization)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',   "Bearer/Auth Token"),
    (r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----',                              "Private Key"),
    (r'(?i)(slack[_-]?token|xox[baprs]-[0-9a-zA-Z\-]+)',                          "Slack Token"),
    (r'(?i)stripe[_-]?(secret|key)\s*[=:]\s*["\']([^"\']+)["\']',                "Stripe Key"),
    (r'(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',              "Twilio Token"),
    (r'(?i)sendgrid[_-]?api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',               "SendGrid Key"),
    (r'(?i)(mongodb|mongo)[^"\']*mongodb[\+]?srv?://[^\s"\']+',                    "MongoDB URI"),
    (r'(?i)(jdbc|db)[^"\']*://[^\s"\']+',                                          "DB Connection String"),
    (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',                   "JWT Token"),
    (r'(?i)access_token\s*[=:]\s*["\']([^"\']{20,})["\']',                        "OAuth Access Token"),
    (r'(?i)(client_secret|app_secret)\s*[=:]\s*["\']([^"\']{8,})["\']',           "OAuth Client Secret"),
]

# ─────────────────────── TAKEOVER FINGERPRINTS ─────────────────────────────

TAKEOVER_FP: dict[str,str] = {
    "github":          "There isn't a GitHub Pages site here",
    "heroku":          "No such app",
    "netlify":         "Not Found - Request ID",
    "aws-s3":          "NoSuchBucket",
    "azure":           "The specified container does not exist",
    "shopify":         "Sorry, this shop is currently unavailable",
    "fastly":          "Fastly error: unknown domain",
    "ghost":           "The thing you were looking for is no longer here",
    "surge.sh":        "project not found",
    "readme.io":       "Project doesnt exist",
    "statuspage":      "Better luck next time",
    "zendesk":         "Help Center Closed",
    "wordpress.com":   "Do you want to register",
    "tumblr":          "Whatever you were looking for doesn't live here",
    "bitbucket":       "Repository not found",
    "unbounce":        "The requested URL was not found",
    "helpscout":       "No settings were found for this company",
    "intercom":        "This page is reserved for artistic dogs",
    "sendgrid":        "The URL you are looking for is unavailable",
    "campaignmonitor": "Double check the URL",
    "teamwork":        "Oops - We didn't find your site",
    "uservoice":       "This UserVoice subdomain is currently available",
    "pingdom":         "This public status page does not exist",
    "tilda":           "Please renew your subscription",
    "launchrock":      "It looks like you may have taken a wrong turn",
}

# ─────────────────────── PRIORITY PATTERNS ─────────────────────────────────

PRIORITY_PATTERNS: list[tuple[str,int,str]] = [
    (r'/api/v?\d*/?(user|account|profile|admin|order|payment|invoice)', 50, "Sensitive API noun"),
    (r'\?(id|uid|user_?id|account_?id|order_?id)=\d+',                  45, "IDOR-prone param"),
    (r'/(admin|administrator|superuser|manage|management)',              45, "Admin path"),
    (r'/(login|signin|auth|oauth|sso|saml|cas)',                         40, "Auth endpoint"),
    (r'/(upload|import|export|download|file|attachment)',                40, "File operation"),
    (r'/(reset|forgot|recovery|unlock)',                                  38, "Password reset"),
    (r'/(graphql|gql)',                                                   38, "GraphQL"),
    (r'/(swagger|openapi|api-docs|redoc|api\.json|api\.yaml)',           38, "API docs exposed"),
    (r'\.(git|env|config|bak|backup|sql|dump|log)',                       35, "Sensitive file ext"),
    (r'/(debug|trace|healthz|actuator|metrics|status|ping|info)',         35, "Debug/internal"),
    (r'/(token|apikey|api_key|secret|private)',                           35, "Credential path"),
    (r'/(callback|redirect|return|next|url|forward)',                     32, "Redirect/SSRF-prone"),
    (r'\?.*=.*(http|https|ftp|file|gopher|data):',                       32, "SSRF param value"),
    (r'\.js$',                                                            20, "JavaScript file"),
    (r'/v\d+/',                                                           15, "Versioned API"),
    (r'\?',                                                                8, "Has query params"),
]

# ─────────────────────── BURP XML TEMPLATE ────────────────────────────────

_BURP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE items [<!ELEMENT items (item*)>]>
<items burpVersion="2025.1" exportTime="{ts}">
{items}
</items>"""

_BURP_ITEM = """  <item>
    <time>{time}</time>
    <url><![CDATA[{url}]]></url>
    <host ip="">{host}</host>
    <port>{port}</port>
    <protocol>{proto}</protocol>
    <method>GET</method>
    <path><![CDATA[{path}]]></path>
    <extension>{ext}</extension>
    <request base64="false"><![CDATA[GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n]]></request>
    <status>0</status><responselength>0</responselength>
    <mimetype></mimetype>
    <response base64="false"></response>
    <comment><![CDATA[score:{score} | {reason}]]></comment>
  </item>"""

# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def slugify(v: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", v.strip()).strip("-").lower()

def has(name: str) -> bool:
    return shutil.which(name) is not None

def host_from(target: str) -> str:
    p = urlparse(target if "://" in target else f"https://{target}")
    return (p.netloc or p.path).split("/")[0].split(":")[0].lower()

def base_url(target: str) -> str:
    return target.rstrip("/") if target.startswith("http") else f"https://{host_from(target)}"

def lc(p: Path) -> int:
    return len([l for l in p.read_text(errors="ignore").splitlines() if l.strip()]) if p.exists() else 0

def uniq(p: Path) -> None:
    if not p.exists(): return
    seen, out = set(), []
    for raw in p.read_text(errors="ignore").splitlines():
        l = raw.strip()
        if l and l not in seen: seen.add(l); out.append(l)
    p.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")

def ensure_dirs(d: Path) -> None:
    for sub in ["raw","normalized","reports","logs"]: (d/sub).mkdir(parents=True, exist_ok=True)

def append_lines(src: Path, dst: Path, guard: Optional[str] = None) -> None:
    if not src.exists(): return
    with src.open("r", errors="ignore") as f, dst.open("a", encoding="utf-8") as g:
        for raw in f:
            l = raw.strip()
            if not l: continue
            if guard:
                try:
                    p = urlparse(l if "://" in l else f"https://{l}")
                    h = (p.netloc or p.path).split("/")[0].split(":")[0].lower()
                    if not (h == guard or h.endswith("." + guard)): continue
                except: continue
            g.write(l + "\n")

def sh(label: str, cmd: str, run_dir: Path) -> bool:
    console.print(f"  [cyan]  ↳[/cyan] {label}")
    log = run_dir / "logs" / f"{slugify(label)}.log"
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    log.write_text((r.stdout or "") + "\n" + (r.stderr or ""), encoding="utf-8")
    if r.returncode != 0:
        console.print(f"  [yellow]  ⚠[/yellow]  Non-zero exit — see {log.name}")
        return False
    return True

def sep(char="─", color="bright_black", w=76):
    console.print(f"[{color}]  " + char * w + f"[/{color}]")

def section(title: str, icon: str = "◈"):
    sep()
    console.print(f"\n  [bold cyan]{icon}  {title}[/bold cyan]\n")

def pause():
    input("\n  Press Enter to return to main menu...")

# ═══════════════════════════════════════════════════════════════════════════
#  BANNER + STARTUP
# ═══════════════════════════════════════════════════════════════════════════

def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    console.print(BANNER)
    console.print(f"  [bright_black]{'─'*76}[/bright_black]")
    console.print(
        f"  [bold white]v{VERSION}[/bold white]  "
        f"[bright_black]|[/bright_black]  [dim]{AUTHOR}[/dim]  "
        f"[bright_black]|[/bright_black]  [dim]{GITHUB}[/dim]"
    )
    console.print(f"\n  [bold yellow]  ⚠  USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST  ⚠[/bold yellow]")
    console.print(f"  [bright_black]{'─'*76}[/bright_black]\n")

def tool_doctor():
    section("Tool Doctor — Dependency Check", "⚕")
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0,1))
    table.add_column("Tool",     style="cyan",   width=14)
    table.add_column("Status",                   width=12)
    table.add_column("Category", style="dim",    width=18)
    table.add_column("Install hint", style="dim")
    missing = []
    for tool, meta in TOOL_REGISTRY.items():
        found  = has(tool)
        status = "[bold green]● FOUND  [/bold green]" if found else "[bold red]✗ MISSING[/bold red]"
        table.add_row(tool, status, meta["cat"], meta["install"])
        if not found: missing.append(tool)
    console.print(table)
    if missing:
        console.print(f"  [yellow]Missing:[/yellow] {', '.join(missing)}")
        console.print("  [dim]MegaRecon will skip missing tools automatically.[/dim]\n")
    else:
        console.print("  [bold green]All tools present — ready to go![/bold green]\n")

# ═══════════════════════════════════════════════════════════════════════════
#  UNIQUE FEATURE MODULES
# ═══════════════════════════════════════════════════════════════════════════

# ── 1. JS SECRET HUNTER ────────────────────────────────────────────────────

def js_secret_hunt(js_urls: list[str], run_dir: Path) -> list[dict]:
    section("JS Secret Hunter", "🔍")
    hits, seen = [], set()
    total = len([u for u in js_urls if u.endswith(".js")])
    console.print(f"  Scanning [cyan]{total}[/cyan] JS files...\n")
    for url in js_urls:
        if not url.endswith(".js") or url in seen: continue
        seen.add(url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 MegaRecon"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read(500_000).decode("utf-8", errors="ignore")
        except Exception: continue
        for pat, label in JS_PATTERNS:
            for m in re.finditer(pat, content):
                hit = {"url": url, "type": label, "match": m.group(0)[:150]}
                hits.append(hit)
                console.print(f"  [bold red][HIT][/bold red] [yellow]{label}[/yellow]")
                console.print(f"        [dim]File:[/dim] {url}")
                console.print(f"        [dim]Match:[/dim] {m.group(0)[:100]}\n")
    (run_dir/"reports"/"js_secrets.json").write_text(json.dumps(hits, indent=2), encoding="utf-8")
    color = "bold red" if hits else "green"
    console.print(f"  [{color}]Found {len(hits)} potential secret(s)[/{color}] → reports/js_secrets.json\n")
    return hits


# ── 2. WAF BYPASS SUGGESTER ────────────────────────────────────────────────

def waf_bypass_suggest(waf_file: Path) -> Optional[str]:
    section("WAF Bypass Suggester", "🛡")
    if not waf_file.exists():
        console.print("  [dim]No WAF output found — run wafw00f first.[/dim]\n")
        return None
    content = waf_file.read_text(errors="ignore").lower()
    detected = next((k for k in WAF_BYPASS_DB if k in content), None)
    hints    = WAF_BYPASS_DB.get(detected or "generic")
    name     = detected.upper() if detected else "UNKNOWN / GENERIC"
    console.print(f"  [bold yellow]Detected WAF:[/bold yellow] [cyan]{name}[/cyan]\n")
    for i, h in enumerate(hints, 1):
        console.print(f"  [bold green] {i:>2}.[/bold green] {h}")
    console.print()
    return detected


# ── 3. TECH STACK ATTACK MAP ───────────────────────────────────────────────

def tech_attack_map(alive_file: Path, run_dir: Path) -> dict:
    section("Tech Stack Attack Map", "🗺")
    if not alive_file.exists():
        console.print("  [dim]No alive.txt found.[/dim]\n"); return {}
    content  = alive_file.read_text(errors="ignore").lower()
    findings = {}
    for tech, data in TECH_ATTACK_MAP.items():
        if tech in content:
            findings[tech] = data
            console.print(f"  [bold cyan]▸ {tech.upper()}[/bold cyan] detected")
            if data["cves"]:
                console.print(f"    [red]CVEs:[/red]         {', '.join(data['cves'])}")
            tags = ",".join(data["nuclei_tags"])
            console.print(f"    [yellow]Nuclei command:[/yellow] nuclei -l alive.txt -tags {tags}\n")
    if not findings:
        console.print("  [dim]No known tech fingerprints matched in httpx output.[/dim]\n")
    (run_dir/"reports"/"tech_attack_map.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return findings


# ── 4. SUBDOMAIN TAKEOVER CHECKER ──────────────────────────────────────────

def takeover_check(subs_file: Path, run_dir: Path) -> list[dict]:
    section("Subdomain Takeover Checker", "💀")
    if not subs_file.exists():
        console.print("  [dim]No subdomains file found.[/dim]\n"); return []
    subs  = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
    vulns = []
    console.print(f"  Checking [cyan]{min(len(subs),100)}[/cyan] subdomains...\n")
    for sub in subs[:100]:
        url = f"https://{sub}" if not sub.startswith("http") else sub
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 MegaRecon"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore")
        except Exception as e:
            body = str(e)
        for svc, fp in TAKEOVER_FP.items():
            if fp.lower() in body.lower():
                vulns.append({"subdomain": sub, "service": svc, "fingerprint": fp})
                console.print(f"  [bold red][VULN][/bold red] [yellow]{sub}[/yellow]  →  possible [cyan]{svc}[/cyan] takeover")
    if not vulns:
        console.print(f"  [green]No takeover signatures found.[/green]")
    (run_dir/"reports"/"takeover.json").write_text(json.dumps(vulns, indent=2), encoding="utf-8")
    console.print()
    return vulns


# ── 5. PRIORITY SCORER ─────────────────────────────────────────────────────

def priority_score(url: str) -> tuple[int, str]:
    total, reasons = 0, []
    for pat, w, label in PRIORITY_PATTERNS:
        if re.search(pat, url, re.IGNORECASE):
            total += w; reasons.append(label)
    pc = len(re.findall(r'[?&][^=&]+=', url))
    if pc >= 3: total += pc * 3; reasons.append(f"{pc} params")
    return total, " | ".join(reasons) if reasons else "no signal"

def build_priority(urls_file: Path, out_file: Path) -> list[tuple]:
    rows = []
    if urls_file.exists():
        for l in urls_file.read_text(errors="ignore").splitlines():
            u = l.strip()
            if u:
                s, r = priority_score(u)
                rows.append((s, u, r))
    rows.sort(key=lambda x: -x[0])
    with out_file.open("w", encoding="utf-8") as f:
        for s, u, r in rows:
            f.write(f"{s}\t{u}\t{r}\n")
    return rows


# ── 6. REPLAY PACK ─────────────────────────────────────────────────────────

def build_replay(rows: list, out_file: Path) -> None:
    lines = [
        "#!/usr/bin/env bash",
        "# MegaRecon Replay Pack — top-priority endpoints",
        "# Run:  bash replay_pack.sh\n",
    ]
    for s, u, r in rows[:30]:
        lines += [f"# Score:{s}  {r}", f'curl -isk "{u}" | head -n 30', ""]
    out_file.write_text("\n".join(lines), encoding="utf-8")
    out_file.chmod(0o755)


# ── 7. BURP SUITE EXPORT ───────────────────────────────────────────────────

def build_burp(rows: list, out_file: Path) -> None:
    now   = datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
    items = []
    for s, u, r in rows[:300]:
        try:
            p    = urlparse(u if "://" in u else f"https://{u}")
            host = (p.netloc or p.path).split(":")[0]
            port = str(p.port or (443 if p.scheme=="https" else 80))
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            ext  = Path(p.path).suffix.lstrip(".")
            items.append(_BURP_ITEM.format(
                time=now, url=u, host=host, port=port,
                proto=p.scheme or "https", path=path,
                ext=ext, score=s, reason=r[:80]
            ))
        except Exception: continue
    out_file.write_text(
        _BURP_XML.format(ts=datetime.now().isoformat(), items="\n".join(items)),
        encoding="utf-8"
    )


# ── 8. RECON DIFF ──────────────────────────────────────────────────────────

def recon_diff(prev: Path, curr: Path, out_file: Path) -> dict:
    section("Recon Diff — Change Detection", "🔄")
    diff = {}
    for fname in ["subdomains.txt", "alive.txt", "urls.txt"]:
        prev_set = {l.strip() for l in (prev/"normalized"/fname).read_text(errors="ignore").splitlines() if l.strip()} if (prev/"normalized"/fname).exists() else set()
        curr_set = {l.strip() for l in (curr/"normalized"/fname).read_text(errors="ignore").splitlines() if l.strip()} if (curr/"normalized"/fname).exists() else set()
        new  = sorted(curr_set - prev_set)
        gone = sorted(prev_set - curr_set)
        diff[fname] = {"new": new, "removed": gone}
        console.print(f"  [bold]{fname}[/bold]  [green]+{len(new)} new[/green]  [red]-{len(gone)} removed[/red]")
        for item in new[:10]:  console.print(f"    [green]+[/green] {item}")
        for item in gone[:5]:  console.print(f"    [red]-[/red] {item}")
        console.print()
    out_file.write_text(json.dumps(diff, indent=2), encoding="utf-8")
    console.print(f"  Diff saved → {out_file.name}\n")
    return diff


# ── 9. RECON GRAPH (Mermaid) ───────────────────────────────────────────────

def build_graph(alive_file: Path, urls_file: Path, out_file: Path) -> None:
    hosts, edges = [], []
    if alive_file.exists():
        for l in alive_file.read_text(errors="ignore").splitlines():
            parts = l.strip().split()
            if parts: hosts.append(parts[0])
    if urls_file.exists():
        for url in urls_file.read_text(errors="ignore").splitlines()[:200]:
            url = url.strip()
            if not url: continue
            p = urlparse(url if "://" in url else f"https://{url}")
            h = (p.netloc or p.path).split(":")[0]
            edges.append((h, p.path or "/"))
    graph = ["flowchart LR"]
    for h in sorted(set(hosts))[:50]:
        graph.append(f'    "{h}":::host')
    for h, path in edges[:200]:
        graph.append(f'    "{h}" --> "{path}"')
    graph.append("    classDef host fill:#1a1a2e,color:#e94560,stroke:#0f3460;")
    out_file.write_text("\n".join(graph) + "\n", encoding="utf-8")


# ── 10. MARKDOWN REPORT ────────────────────────────────────────────────────

def write_report(run_dir: Path, meta: dict,
                 js_hits: list, takeover_hits: list, tech_map: dict) -> None:
    subs   = run_dir/"normalized"/"subdomains.txt"
    alive  = run_dir/"normalized"/"alive.txt"
    urls   = run_dir/"normalized"/"urls.txt"
    prio   = run_dir/"reports"/"priority.txt"

    top = []
    if prio.exists():
        for raw in prio.read_text(errors="ignore").splitlines()[:20]:
            try:
                parts = raw.split("\t", 2)
                reason = parts[2] if len(parts) > 2 else ""
                top.append(f"- **[{parts[0]}]** `{parts[1]}` — {reason}")
            except: pass

    techs_md = ""
    for tech, data in tech_map.items():
        techs_md += f"\n### {tech.upper()}\n"
        if data["cves"]: techs_md += "**CVEs:** " + ", ".join(data["cves"]) + "\n"
        techs_md += "**Nuclei:** `nuclei -l alive.txt -tags " + ",".join(data["nuclei_tags"]) + "`\n"

    js_md       = "\n".join(f"- **{h['type']}** in `{h['url']}`" for h in js_hits[:20])  or "_None found._"
    takeover_md = "\n".join(f"- `{v['subdomain']}` → {v['service']}" for v in takeover_hits) or "_None found._"

    md = f"""# MegaRecon Report

> Generated by **MegaRecon v{VERSION}** | {GITHUB}

## Run Metadata
| Key | Value |
|---|---|
| Scope | `{meta["scope"]}` |
| Profile | `{meta["profile"]}` |
| Intensity | `{meta["intensity"]}` |
| Started | {meta["started"]} |
| Output | `{run_dir}` |

## Summary Counts
| Asset | Count |
|---|---|
| Subdomains | {lc(subs)} |
| Live hosts | {lc(alive)} |
| URLs / Endpoints | {lc(urls)} |
| JS Secrets found | {len(js_hits)} |
| Takeover candidates | {len(takeover_hits)} |
| Tech signatures | {len(tech_map)} |

## Priority Endpoints (Top 20)
{chr(10).join(top) if top else "_No endpoints scored._"}

## Tech Stack Attack Map
{techs_md if techs_md else "_No tech signatures detected._"}

## JS Secrets Found
{js_md}

## Subdomain Takeover Candidates
{takeover_md}

## Output Files
| File | Description |
|---|---|
| `normalized/subdomains.txt` | Unique in-scope subdomains |
| `normalized/alive.txt` | Live hosts + httpx metadata |
| `normalized/urls.txt` | All discovered URLs |
| `reports/priority.txt` | URLs ranked by attack priority |
| `reports/replay_pack.sh` | Auto curl commands for top endpoints |
| `reports/burp_import.xml` | Burp Suite XML sitemap import |
| `reports/recon_graph.mmd` | Mermaid flowchart of recon surface |
| `reports/js_secrets.json` | Hardcoded secrets from JS files |
| `reports/tech_attack_map.json` | Tech → CVE / nuclei tag mapping |
| `reports/takeover.json` | Takeover fingerprint results |

---
_MegaRecon — use only on authorized targets._
"""
    (run_dir/"reports"/"summary.md").write_text(md, encoding="utf-8")

# ═══════════════════════════════════════════════════════════════════════════
#  CORE WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════

def run_workflow(target: str, profile: str, intensity: str,
                 do_ffuf: bool, do_nuclei: bool, wordlist: str,
                 do_js: bool, do_takeover: bool) -> Path:

    scope  = host_from(target)
    burl   = base_url(target)
    stamp  = datetime.now().strftime("%Y%m%d-%H%M%S")
    rd     = Path("output") / f"{slugify(scope)}-{stamp}"
    ensure_dirs(rd)

    sel   = set(PROFILES[profile]["tools"])
    if not do_ffuf:    sel.discard("ffuf")
    if not do_nuclei:  sel.discard("nuclei")
    rates = INTENSITY[intensity]

    raw, norm, rep = rd/"raw", rd/"normalized", rd/"reports"
    subs_f, alive_f, urls_f = norm/"subdomains.txt", norm/"alive.txt", norm/"urls.txt"

    console.print(Panel.fit(
        f"[bold red]MegaRecon[/bold red]  v{VERSION}\n\n"
        f"  [cyan]Scope[/cyan]     {scope}\n"
        f"  [cyan]Profile[/cyan]   {profile}\n"
        f"  [cyan]Intensity[/cyan] {intensity}\n"
        f"  [cyan]Output[/cyan]    {rd}",
        border_style="red", title="[bold]Starting Recon[/bold]"
    ))

    # ── Stage 1 ── Subdomain Collection ────────────────────────────────────
    section("Stage 1 — Subdomain Collection", "①")
    for tool, flag, cmd in [
        ("subfinder",   "subfinder",   f"subfinder -d {scope} -all -silent -o {raw/'subfinder.txt'}"),
        ("assetfinder", "assetfinder", f"assetfinder --subs-only {scope} > {raw/'assetfinder.txt'}"),
        ("amass",       "amass",       f"amass enum -passive -d {scope} -o {raw/'amass.txt'}"),
    ]:
        if tool in sel and has(tool):
            sh(tool.capitalize(), cmd, rd)
            append_lines(raw/f"{tool}.txt", subs_f, scope)
    if not subs_f.exists() or lc(subs_f) == 0:
        subs_f.write_text(scope + "\n", encoding="utf-8")
    uniq(subs_f)
    console.print(f"\n  [green]✓[/green] {lc(subs_f)} subdomains collected\n")

    # ── Stage 2 ── WAF Detection + Bypass Hints ─────────────────────────────
    section("Stage 2 — WAF Detection + Bypass Hints", "②")
    if "wafw00f" in sel and has("wafw00f"):
        sh("wafw00f", f"wafw00f {burl} -a > {raw/'waf.txt'}", rd)
    waf_bypass_suggest(raw/"waf.txt")

    # ── Stage 3 ── Live Host Validation ─────────────────────────────────────
    section("Stage 3 — Live Host Mapping (httpx)", "③")
    if "httpx" in sel and has("httpx"):
        sh("httpx",
           f"httpx -l {subs_f} -silent -title -tech-detect -status-code "
           f"-follow-redirects -rate-limit {rates['httpx_rate']} "
           f"-threads {rates['threads']} -o {alive_f}", rd)
    if not alive_f.exists() or lc(alive_f) == 0:
        alive_f.write_text(burl + "\n", encoding="utf-8")
    uniq(alive_f)
    console.print(f"\n  [green]✓[/green] {lc(alive_f)} live hosts mapped\n")

    # ── Stage 4 ── Tech Stack Attack Map ────────────────────────────────────
    tmap = tech_attack_map(alive_f, rd)

    # ── Stage 5 ── Historical URL Collection ────────────────────────────────
    section("Stage 5 — Historical URL Collection", "⑤")
    if "gau" in sel and has("gau"):
        sh("gau", f"gau --subs {scope} > {raw/'gau.txt'}", rd)
        append_lines(raw/"gau.txt", urls_f, scope)
    if "waybackurls" in sel and has("waybackurls"):
        sh("waybackurls", f"echo {scope} | waybackurls > {raw/'wayback.txt'}", rd)
        append_lines(raw/"wayback.txt", urls_f, scope)

    # ── Stage 6 ── Crawling ─────────────────────────────────────────────────
    section("Stage 6 — Active Crawling (katana)", "⑥")
    if "katana" in sel and has("katana"):
        sh("katana",
           f"katana -list {alive_f} -silent -jc -d 3 "
           f"-rate-limit {rates['katana_rate']} -o {raw/'katana.txt'}", rd)
        append_lines(raw/"katana.txt", urls_f, scope)
    uniq(urls_f)
    console.print(f"\n  [green]✓[/green] {lc(urls_f)} unique URLs collected\n")

    # ── Stage 7 ── JS Secret Hunter ─────────────────────────────────────────
    js_hits = []
    if do_js and urls_f.exists():
        js_urls = [l.strip() for l in urls_f.read_text(errors="ignore").splitlines()
                   if l.strip().endswith(".js")]
        js_hits = js_secret_hunt(js_urls, rd)

    # ── Stage 8 ── Subdomain Takeover ───────────────────────────────────────
    tkover = []
    if do_takeover:
        tkover = takeover_check(subs_f, rd)
    if "subjack" in sel and has("subjack"):
        sh("subjack",
           f"subjack -w {subs_f} -t 100 -timeout 30 -ssl "
           f"-c /etc/subjack/fingerprints.json -o {rep/'subjack.txt'}", rd)

    # ── Stage 9 ── Parameter Discovery ─────────────────────────────────────
    section("Stage 9 — Parameter Discovery (arjun)", "⑨")
    if "arjun" in sel and has("arjun") and alive_f.exists():
        first = alive_f.read_text(errors="ignore").splitlines()[0].split()[0].strip()
        sh("arjun", f"arjun -u {first} -oJ {rep/'arjun_params.json'}", rd)
    else:
        console.print("  [dim]arjun not available — skipping[/dim]\n")

    # ── Stage 10 ── Content Discovery ───────────────────────────────────────
    section("Stage 10 — Content Discovery (ffuf)", "⑩")
    if do_ffuf and "ffuf" in sel and has("ffuf") and Path(wordlist).exists():
        sh("ffuf",
           f"ffuf -u {burl}/FUZZ -w {wordlist} -mc all "
           f"-rate {rates['ffuf_rate']} -of md -o {raw/'ffuf.md'}", rd)
    else:
        console.print("  [dim]ffuf skipped (disabled or wordlist missing)[/dim]\n")

    # ── Stage 11 ── Nuclei Checks ────────────────────────────────────────────
    section("Stage 11 — Nuclei Safe Checks", "⑪")
    if do_nuclei and "nuclei" in sel and has("nuclei"):
        tags = "tech,exposure,misconfig"
        if tmap:
            extra = ",".join({t for d in tmap.values() for t in d["nuclei_tags"]})
            tags += "," + extra
        sh("nuclei",
           f"nuclei -l {alive_f} -silent -tags {tags} "
           f"-severity info,low,medium "
           f"-rate-limit {rates['httpx_rate']} -o {raw/'nuclei.txt'}", rd)
    else:
        console.print("  [dim]nuclei skipped[/dim]\n")

    # ── Final exports ────────────────────────────────────────────────────────
    section("Building Outputs + Reports", "📦")
    console.print("  [cyan]↳[/cyan] Priority scoring all URLs")
    prio_rows = build_priority(urls_f, rep/"priority.txt")
    console.print("  [cyan]↳[/cyan] Building replay pack")
    build_replay(prio_rows, rep/"replay_pack.sh")
    console.print("  [cyan]↳[/cyan] Generating Burp Suite XML export")
    build_burp(prio_rows, rep/"burp_import.xml")
    console.print("  [cyan]↳[/cyan] Generating Mermaid recon graph")
    build_graph(alive_f, urls_f, rep/"recon_graph.mmd")
    console.print("  [cyan]↳[/cyan] Writing markdown report")
    write_report(rd, {
        "scope": scope, "profile": profile,
        "intensity": intensity, "started": datetime.now().isoformat()
    }, js_hits, tkover, tmap)

    return rd


# ═══════════════════════════════════════════════════════════════════════════
#  MENU HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def pick_profile() -> str:
    section("Choose Profile", "📋")
    descs = {
        "passive":  "No active requests — pure passive collection",
        "balanced": "Client-safe default — recommended for most assessments",
        "deep":     "High-noise — content discovery + full modules",
    }
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0,1))
    table.add_column("No.", style="bold yellow", width=5)
    table.add_column("Profile",     style="bold white", width=12)
    table.add_column("Description")
    table.add_column("Tools", style="dim")
    for i,(name,meta) in enumerate(PROFILES.items(), 1):
        table.add_row(str(i), name, descs[name], ", ".join(meta["tools"][:5])+"…")
    console.print(table)
    c = IntPrompt.ask("  Select profile", default=2)
    return list(PROFILES.keys())[max(0, min(c-1, 2))]

def pick_intensity() -> str:
    section("Choose Intensity", "⚡")
    rows = [
        ("1","low",    "35",  "40",  "10",  "Fragile targets, quiet scan"),
        ("2","medium", "75",  "100", "25",  "Standard client assessment"),
        ("3","high",   "150", "200", "50",  "Full-power, approved scope"),
    ]
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0,1))
    table.add_column("No.", style="bold yellow", width=5)
    table.add_column("Level",      style="bold white", width=8)
    table.add_column("httpx rate", justify="right")
    table.add_column("ffuf rate",  justify="right")
    table.add_column("Threads",    justify="right")
    table.add_column("When to use")
    for r in rows: table.add_row(*r)
    console.print(table)
    c = IntPrompt.ask("  Select intensity", default=2)
    return ["low","medium","high"][max(0, min(c-1, 2))]

def pick_modules(profile: str) -> tuple[bool,bool,bool,bool]:
    section("Optional Modules", "🧩")
    items = [
        ("JS Secret Hunter",         "Scan .js files for API keys, tokens, DB URIs, private keys"),
        ("Subdomain Takeover Check", "Fingerprint dangling subdomains across 25+ services"),
        ("Content Discovery (ffuf)", "Active directory + file brute forcing"),
        ("Safe Nuclei Checks",       "Template-based misconfig, exposure, tech-specific checks"),
    ]
    for i,(name,desc) in enumerate(items,1):
        console.print(f"  [bold yellow][{i}][/bold yellow] [cyan]{name:<30}[/cyan] [dim]{desc}[/dim]")
    console.print()
    js  = Confirm.ask("  Enable JS Secret Hunter?",         default=True)
    tk  = Confirm.ask("  Enable Subdomain Takeover Check?", default=True)
    ff  = Confirm.ask("  Enable Content Discovery (ffuf)?", default=(profile=="deep"))
    nu  = Confirm.ask("  Enable Safe Nuclei Checks?",       default=True)
    return js, tk, ff, nu

def confirm_auth(target: str) -> bool:
    console.print()
    sep(char="═", color="yellow")
    console.print(f"\n  [bold yellow]⚠  TARGET:[/bold yellow]  [cyan]{target}[/cyan]")
    console.print("  [bold yellow]You must have explicit written authorization to test this target.[/bold yellow]\n")
    sep(char="═", color="yellow")
    return Confirm.ask("\n  I confirm I am authorized to test this target")


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1",  "Recon Wizard",                "Guided full-featured recon workflow"),
    ("2",  "Quick Passive Recon",         "Subdomains + historical URLs only, no active scanning"),
    ("3",  "Quick Deep Recon",            "Aggressive recon — ensure scope is approved"),
    ("─",  "",                            ""),
    ("4",  "JS Secret Hunter",            "Standalone — scan a URL list for hardcoded secrets"),
    ("5",  "WAF Bypass Suggester",        "Standalone — get bypass hints for a target WAF"),
    ("6",  "Tech Stack Attack Map",       "Standalone — map alive.txt tech to CVEs + nuclei tags"),
    ("7",  "Subdomain Takeover Checker",  "Standalone — fingerprint a subdomain list"),
    ("─",  "",                            ""),
    ("8",  "Recon Diff (Compare Runs)",   "Highlight new/removed assets between two past runs"),
    ("─",  "",                            ""),
    ("9",  "Show Profiles",               "View passive / balanced / deep profile details"),
    ("10", "Tool Doctor",                 "Check which dependencies are installed"),
    ("─",  "",                            ""),
    ("0",  "Exit",                        ""),
]

def main_menu():
    while True:
        print_banner()
        sep(char="═", color="red")
        console.print()
        for no, name, desc in MENU_ITEMS:
            if no == "─":
                console.print(f"  [bright_black]  {'·'*60}[/bright_black]")
            elif no == "0":
                console.print(f"\n  [bold bright_black][ 0 ][/bold bright_black]  [dim]Exit[/dim]")
            else:
                console.print(
                    f"  [bold yellow][{no:>2}][/bold yellow]  "
                    f"[bold white]{name:<34}[/bold white]  [dim]{desc}[/dim]"
                )
        console.print()
        sep(char="═", color="red")
        choice = Prompt.ask("\n  [bold red]MegaRecon ›[/bold red]").strip()

        # ── 0 EXIT ─────────────────────────────────────────────────────────
        if choice == "0":
            console.print("\n  [bold red]Goodbye. Stay ethical, Aryan.[/bold red]\n")
            break

        # ── 1 WIZARD ───────────────────────────────────────────────────────
        elif choice == "1":
            print_banner()
            section("Recon Wizard", "🧙")
            target = Prompt.ask("  Target domain or base URL")
            if not target.strip(): pause(); continue
            profile   = pick_profile()
            intensity = pick_intensity()
            js, tk, ff, nu = pick_modules(profile)
            wordlist = Prompt.ask(
                "  Wordlist for ffuf",
                default="/usr/share/seclists/Discovery/Web-Content/common.txt"
            )
            if not confirm_auth(target): console.print("  [red]Aborted.[/red]"); pause(); continue
            rd = run_workflow(target, profile, intensity, ff, nu, wordlist, js, tk)
            sep()
            console.print(f"\n  [bold green]✓  Recon complete![/bold green]")
            console.print(f"  [green]Subdomains :[/green] {lc(rd/'normalized'/'subdomains.txt')}")
            console.print(f"  [green]Live hosts :[/green] {lc(rd/'normalized'/'alive.txt')}")
            console.print(f"  [green]URLs       :[/green] {lc(rd/'normalized'/'urls.txt')}")
            console.print(f"  [green]Report     :[/green] {rd/'reports'/'summary.md'}")
            console.print(f"  [green]Burp XML   :[/green] {rd/'reports'/'burp_import.xml'}")
            pause()

        # ── 2 QUICK PASSIVE ────────────────────────────────────────────────
        elif choice == "2":
            print_banner()
            target = Prompt.ask("  Target domain or base URL")
            if not confirm_auth(target): continue
            rd = run_workflow(target,"passive","low",False,False,
                              "/usr/share/seclists/Discovery/Web-Content/common.txt",True,True)
            console.print(f"\n  [green]✓ Passive recon done → {rd}[/green]")
            pause()

        # ── 3 QUICK DEEP ───────────────────────────────────────────────────
        elif choice == "3":
            print_banner()
            target   = Prompt.ask("  Target domain or base URL")
            wordlist = Prompt.ask("  Wordlist", default="/usr/share/seclists/Discovery/Web-Content/common.txt")
            if not confirm_auth(target): continue
            rd = run_workflow(target,"deep","high",True,True,wordlist,True,True)
            console.print(f"\n  [green]✓ Deep recon done → {rd}[/green]")
            pause()

        # ── 4 JS HUNTER STANDALONE ─────────────────────────────────────────
        elif choice == "4":
            print_banner()
            section("JS Secret Hunter — Standalone", "🔍")
            p = Path(Prompt.ask("  Path to URL list file"))
            if not p.exists(): console.print("  [red]File not found.[/red]"); pause(); continue
            rd = Path("output") / f"jshunt-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            (rd/"reports").mkdir(parents=True, exist_ok=True)
            js_urls = [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip().endswith(".js")]
            js_secret_hunt(js_urls, rd)
            pause()

        # ── 5 WAF BYPASS STANDALONE ────────────────────────────────────────
        elif choice == "5":
            print_banner()
            target = Prompt.ask("  Target URL")
            rd = Path("output") / "waf-temp"
            (rd/"raw").mkdir(parents=True, exist_ok=True)
            (rd/"logs").mkdir(parents=True, exist_ok=True)
            if has("wafw00f"):
                sh("wafw00f", f"wafw00f {target} -a > {rd/'raw'/'waf.txt'}", rd)
                waf_bypass_suggest(rd/"raw"/"waf.txt")
            else:
                console.print("  [red]wafw00f not installed.[/red]")
            pause()

        # ── 6 TECH MAP STANDALONE ──────────────────────────────────────────
        elif choice == "6":
            print_banner()
            p = Path(Prompt.ask("  Path to alive.txt"))
            if p.exists():
                rd = Path("output") / f"techmap-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                (rd/"reports").mkdir(parents=True, exist_ok=True)
                tech_attack_map(p, rd)
            else:
                console.print("  [red]File not found.[/red]")
            pause()

        # ── 7 TAKEOVER STANDALONE ──────────────────────────────────────────
        elif choice == "7":
            print_banner()
            p = Path(Prompt.ask("  Path to subdomains.txt"))
            if p.exists():
                rd = Path("output") / f"takeover-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                (rd/"reports").mkdir(parents=True, exist_ok=True)
                takeover_check(p, rd)
            else:
                console.print("  [red]File not found.[/red]")
            pause()

        # ── 8 RECON DIFF ───────────────────────────────────────────────────
        elif choice == "8":
            print_banner()
            od = Path("output")
            if not od.exists() or len(list(od.iterdir())) < 2:
                console.print("  [yellow]Need at least 2 previous runs.[/yellow]")
                pause(); continue
            runs = sorted(od.iterdir(), key=lambda x: x.stat().st_mtime)
            console.print("\n  [dim]Available runs (oldest → newest):[/dim]\n")
            for i,r in enumerate(runs,1): console.print(f"  [yellow][{i}][/yellow] {r.name}")
            console.print()
            a = IntPrompt.ask("  Select run A (older)", default=len(runs)-1)
            b = IntPrompt.ask("  Select run B (newer)", default=len(runs))
            out = runs[b-1]/"reports"/"diff.json"
            (runs[b-1]/"reports").mkdir(parents=True, exist_ok=True)
            recon_diff(runs[a-1], runs[b-1], out)
            pause()

        # ── 9 SHOW PROFILES ────────────────────────────────────────────────
        elif choice == "9":
            print_banner()
            pick_profile()
            pause()

        # ── 10 TOOL DOCTOR ─────────────────────────────────────────────────
        elif choice == "10":
            print_banner()
            tool_doctor()
            pause()

        else:
            console.print("  [red]Invalid option. Try again.[/red]")


# ═══════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def cli():
    parser = argparse.ArgumentParser(
        description="MegaRecon — Unified Web App Recon CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Non-interactive recon (CI/scripting mode)")
    run_p.add_argument("-t", "--target", required=True, help="Target domain or URL")
    run_p.add_argument("-p", "--profile", default="balanced",
                       choices=["passive", "balanced", "deep"], help="Recon profile")
    run_p.add_argument("-i", "--intensity", default="medium",
                       choices=["low", "medium", "high"], help="Scan intensity")
    run_p.add_argument("--ffuf", action="store_true", default=False,
                       help="Enable ffuf content discovery")
    run_p.add_argument("--nuclei", action=argparse.BooleanOptionalAction, default=True,
                       help="Enable/disable nuclei checks")
    run_p.add_argument("-w", "--wordlist",
                       default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                       help="Wordlist for ffuf")
    run_p.add_argument("--js-hunt", action=argparse.BooleanOptionalAction, default=True,
                       help="Enable/disable JS Secret Hunter")
    run_p.add_argument("--takeover", action=argparse.BooleanOptionalAction, default=True,
                       help="Enable/disable subdomain takeover checks")

    args = parser.parse_args()

    if args.command == "run":
        print_banner()
        rd = run_workflow(
            args.target, args.profile, args.intensity,
            args.ffuf, args.nuclei, args.wordlist,
            args.js_hunt, args.takeover,
        )
        console.print(f"\n[bold green]✓ Done → {rd}[/bold green]")
    else:
        # No subcommand → interactive menu
        print_banner()
        tool_doctor()
        input("  Press Enter to continue...")
        main_menu()


if __name__ == "__main__":
    cli()
