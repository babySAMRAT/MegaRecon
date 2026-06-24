#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

app = typer.Typer(
    add_completion=False,
    help="MegaRecon - guided recon CLI for authorized web application testing."
)
console = Console()

TOOL_REGISTRY = {
    "subfinder": {
        "category": "Subdomains",
        "purpose": "Fast passive subdomain discovery",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "assetfinder": {
        "category": "Subdomains",
        "purpose": "Quick subdomain collection from public sources",
        "install": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "amass": {
        "category": "Subdomains",
        "purpose": "Broader passive enumeration",
        "install": "sudo apt install amass -y",
    },
    "httpx": {
        "category": "Surface mapping",
        "purpose": "Live host validation, tech detect, status, title",
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "wafw00f": {
        "category": "Fingerprinting",
        "purpose": "WAF detection before aggressive actions",
        "install": "pip install wafw00f",
    },
    "gau": {
        "category": "Historical URLs",
        "purpose": "Collect URLs from archival/public sources",
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    "waybackurls": {
        "category": "Historical URLs",
        "purpose": "Simple Wayback URL expansion",
        "install": "go install github.com/tomnomnom/waybackurls@latest",
    },
    "katana": {
        "category": "Crawler",
        "purpose": "Modern crawling and JS-aware URL discovery",
        "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "ffuf": {
        "category": "Content discovery",
        "purpose": "Directory and file brute forcing",
        "install": "go install github.com/ffuf/ffuf/v2@latest",
    },
    "nuclei": {
        "category": "Safe checks",
        "purpose": "Template-based exposure/misconfig/tech checks",
        "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
}

PROFILES = {
    "passive": {
        "desc": "Quiet collection: subdomains + historical URLs + light validation",
        "tools": ["subfinder", "assetfinder", "amass", "gau", "waybackurls", "httpx"],
    },
    "balanced": {
        "desc": "Default client-safe recon: passive + live hosts + crawl + safe checks",
        "tools": ["subfinder", "assetfinder", "amass", "httpx", "wafw00f", "gau", "waybackurls", "katana", "nuclei"],
    },
    "deep": {
        "desc": "High-noise recon: adds directory discovery and stronger crawling",
        "tools": ["subfinder", "assetfinder", "amass", "httpx", "wafw00f", "gau", "waybackurls", "katana", "ffuf", "nuclei"],
    },
}

INTENSITY = {
    "low": {"httpx_rate": 35, "katana_rate": 10, "ffuf_rate": 40, "threads": 10},
    "medium": {"httpx_rate": 75, "katana_rate": 25, "ffuf_rate": 100, "threads": 25},
    "high": {"httpx_rate": 150, "katana_rate": 50, "ffuf_rate": 200, "threads": 50},
}


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip()).strip("-").lower()


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def host_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    return host.split("/")[0].split(":")[0].lower()


def base_url_from_target(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")
    return f"https://{host_from_target(target)}"


class ScopeGuard:
    def __init__(self, host: str):
        self.host = host.lower().strip()

    def allowed(self, candidate: str) -> bool:
        try:
            parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
            test_host = (parsed.netloc or parsed.path).split("/")[0].split(":")[0].lower()
            return test_host == self.host or test_host.endswith("." + self.host)
        except Exception:
            return False


def ensure_dirs(run_dir: Path) -> None:
    for part in ["raw", "normalized", "reports", "logs"]:
        (run_dir / part).mkdir(parents=True, exist_ok=True)


def line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return len([x for x in path.read_text(errors="ignore").splitlines() if x.strip()])


def run_shell(label: str, command: str, run_dir: Path) -> bool:
    console.print(f"[cyan][*][/cyan] {label}")
    log_file = run_dir / "logs" / f"{slugify(label)}.log"
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    log_file.write_text(combined, encoding="utf-8")
    if result.returncode != 0:
        console.print(f"[yellow][!][/yellow] {label} failed or returned non-zero. Check {log_file}")
        return False
    return True


def append_lines(src: Path, dest: Path, guard: ScopeGuard | None = None) -> None:
    if not src.exists():
        return
    with src.open("r", errors="ignore") as fsrc, dest.open("a", encoding="utf-8") as fdst:
        for raw in fsrc:
            line = raw.strip()
            if not line:
                continue
            if guard and not guard.allowed(line):
                continue
            fdst.write(line + "\n")


def uniq_file(path: Path) -> None:
    if not path.exists():
        return
    seen = set()
    output = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        output.append(line)
    path.write_text("\n".join(output) + ("\n" if output else ""), encoding="utf-8")


def score_url(url: str) -> int:
    score = 0
    hot = [
        "admin", "login", "signin", "dashboard", "upload", "import", "export",
        "graphql", "api", "swagger", "openapi", "debug", "actuator", "token",
        "auth", "callback", "oauth", "sso", "reset", "forgot", "backup",
        "internal", ".git", ".env", "config", "file", "redirect", "search"
    ]
    low = url.lower()
    for key in hot:
        if key in low:
            score += 10
    if "?" in url:
        score += 8
    if low.endswith(".js"):
        score += 6
    if re.search(r"/v[0-9]+/", low):
        score += 4
    return score


def build_priority_file(urls_file: Path, out_file: Path) -> None:
    rows = []
    if urls_file.exists():
        for line in urls_file.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line:
                rows.append((score_url(line), line))
    rows.sort(key=lambda x: (-x[0], x[1]))
    with out_file.open("w", encoding="utf-8") as f:
        for score, url in rows:
            f.write(f"{score}\t{url}\n")


def build_replay_pack(priority_file: Path, out_file: Path) -> None:
    lines = []
    if priority_file.exists():
        for raw in priority_file.read_text(errors="ignore").splitlines()[:30]:
            try:
                _, url = raw.split("\t", 1)
            except ValueError:
                continue
            lines.append(f'curl -isk "{url}"')
    out_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def build_graph(alive_file: Path, urls_file: Path, out_file: Path) -> None:
    hosts = []
    edges = []
    if alive_file.exists():
        for line in alive_file.read_text(errors="ignore").splitlines():
            parts = line.strip().split()
            if parts:
                hosts.append(parts[0])

    if urls_file.exists():
        for url in urls_file.read_text(errors="ignore").splitlines()[:200]:
            url = url.strip()
            if not url:
                continue
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = parsed.netloc or parsed.path
            path = parsed.path or "/"
            host = host.split(":")[0]
            edges.append((host, path))

    graph = ["flowchart LR"]
    for host in sorted(set(hosts))[:50]:
        graph.append(f'    "{host}":::host')
    for host, path in edges[:200]:
        graph.append(f'    "{host}" --> "{path}"')
    graph.append("    classDef host fill:#1f2937,color:#fff,stroke:#0ea5e9;")
    out_file.write_text("\n".join(graph) + "\n", encoding="utf-8")


def write_report(run_dir: Path, meta: dict) -> None:
    report = run_dir / "reports" / "summary.md"
    subs = run_dir / "normalized" / "subdomains.txt"
    alive = run_dir / "normalized" / "alive.txt"
    urls = run_dir / "normalized" / "urls.txt"
    priority = run_dir / "reports" / "priority.txt"

    top_urls = []
    if priority.exists():
        for raw in priority.read_text(errors="ignore").splitlines()[:15]:
            try:
                score, url = raw.split("\t", 1)
                top_urls.append(f"- [{score}] {url}")
            except ValueError:
                pass

    md = f"""# MegaRecon Report

## Run metadata
- Scope: {meta["scope"]}
- Profile: {meta["profile"]}
- Intensity: {meta["intensity"]}
- Started: {meta["started"]}
- Output: `{run_dir}`

## Counts
- Subdomains: {line_count(subs)}
- Live hosts: {line_count(alive)}
- URLs/endpoints: {line_count(urls)}

## Priority endpoints
{chr(10).join(top_urls) if top_urls else "- No endpoints were scored."}

## Generated files
- `normalized/subdomains.txt`
- `normalized/alive.txt`
- `normalized/urls.txt`
- `reports/priority.txt`
- `reports/replay_pack.sh`
- `reports/recon_graph.mmd`

## Notes
- ScopeGuard removes lines outside approved host scope.
- WAF detection runs before higher-noise stages.
- Nuclei pack is intentionally limited to tech, exposure, and misconfig style recon by default.
"""
    report.write_text(md, encoding="utf-8")


def run_workflow(
    target: str,
    profile: str,
    intensity: str,
    enable_ffuf: bool,
    enable_nuclei: bool,
    wordlist: str,
) -> None:
    scope_host = host_from_target(target)
    base_url = base_url_from_target(target)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = Path("output") / f"{slugify(scope_host)}-{stamp}"
    ensure_dirs(run_dir)

    guard = ScopeGuard(scope_host)
    selected = set(PROFILES[profile]["tools"])
    if not enable_ffuf:
        selected.discard("ffuf")
    if not enable_nuclei:
        selected.discard("nuclei")
    rates = INTENSITY[intensity]

    console.print(
        Panel.fit(
            f"[bold]MegaRecon[/bold]\n"
            f"Scope: {scope_host}\n"
            f"Profile: {profile}\n"
            f"Intensity: {intensity}\n"
            f"Output: {run_dir}",
            border_style="cyan",
        )
    )

    raw = run_dir / "raw"
    norm = run_dir / "normalized"
    reports = run_dir / "reports"

    subdomains_all = norm / "subdomains.txt"
    alive_file = norm / "alive.txt"
    urls_file = norm / "urls.txt"

    # Stage 1 - subdomain collection
    if "subfinder" in selected and has_tool("subfinder"):
        run_shell(
            "Subfinder passive collection",
            f"subfinder -d {scope_host} -all -silent -o {raw / 'subfinder.txt'}",
            run_dir,
        )
        append_lines(raw / "subfinder.txt", subdomains_all, guard)

    if "assetfinder" in selected and has_tool("assetfinder"):
        run_shell(
            "Assetfinder passive collection",
            f"assetfinder --subs-only {scope_host} > {raw / 'assetfinder.txt'}",
            run_dir,
        )
        append_lines(raw / "assetfinder.txt", subdomains_all, guard)

    if "amass" in selected and has_tool("amass"):
        run_shell(
            "Amass passive collection",
            f"amass enum -passive -d {scope_host} -o {raw / 'amass.txt'}",
            run_dir,
        )
        append_lines(raw / "amass.txt", subdomains_all, guard)

    if not subdomains_all.exists() or line_count(subdomains_all) == 0:
        subdomains_all.write_text(scope_host + "\n", encoding="utf-8")

    uniq_file(subdomains_all)

    # Stage 2 - WAF and live surface
    if "wafw00f" in selected and has_tool("wafw00f"):
        run_shell(
            "WAF detection",
            f"wafw00f {base_url} -a > {raw / 'waf.txt'}",
            run_dir,
        )

    if "httpx" in selected and has_tool("httpx"):
        run_shell(
            "HTTPX live host validation",
            (
                f"httpx -l {subdomains_all} -silent -title -tech-detect -status-code "
                f"-follow-redirects -rate-limit {rates['httpx_rate']} -threads {rates['threads']} "
                f"-o {alive_file}"
            ),
            run_dir,
        )

    if not alive_file.exists() or line_count(alive_file) == 0:
        alive_file.write_text(base_url + "\n", encoding="utf-8")

    uniq_file(alive_file)

    # Stage 3 - historical URL discovery
    if "gau" in selected and has_tool("gau"):
        run_shell(
            "GAU historical URLs",
            f"gau --subs {scope_host} > {raw / 'gau.txt'}",
            run_dir,
        )
        append_lines(raw / "gau.txt", urls_file, guard)

    if "waybackurls" in selected and has_tool("waybackurls"):
        run_shell(
            "Wayback URL collection",
            f"echo {scope_host} | waybackurls > {raw / 'waybackurls.txt'}",
            run_dir,
        )
        append_lines(raw / "waybackurls.txt", urls_file, guard)

    # Stage 4 - crawling
    if "katana" in selected and has_tool("katana"):
        run_shell(
            "Katana crawling",
            (
                f"katana -list {alive_file} -silent -jc -d 3 "
                f"-rate-limit {rates['katana_rate']} -o {raw / 'katana.txt'}"
            ),
            run_dir,
        )
        append_lines(raw / "katana.txt", urls_file, guard)

    # Stage 5 - optional content discovery
    if "ffuf" in selected and has_tool("ffuf") and Path(wordlist).exists():
        run_shell(
            "FFUF content discovery",
            (
                f"ffuf -u {base_url}/FUZZ -w {wordlist} -mc all "
                f"-rate {rates['ffuf_rate']} -of md -o {raw / 'ffuf.md'}"
            ),
            run_dir,
        )

    # Stage 6 - optional safe nuclei checks
    if "nuclei" in selected and has_tool("nuclei"):
        run_shell(
            "Nuclei safe recon checks",
            (
                f"nuclei -l {alive_file} -silent "
                f"-tags tech,exposure,misconfig -severity info,low,medium "
                f"-rate-limit {rates['httpx_rate']} -o {raw / 'nuclei.txt'}"
            ),
            run_dir,
        )

    uniq_file(urls_file)
    build_priority_file(urls_file, reports / "priority.txt")
    build_replay_pack(reports / "priority.txt", reports / "replay_pack.sh")
    build_graph(alive_file, urls_file, reports / "recon_graph.mmd")

    meta = {
        "scope": scope_host,
        "profile": profile,
        "intensity": intensity,
        "started": datetime.now().isoformat(),
    }
    write_report(run_dir, meta)

    console.print("\n[bold green][+] Recon complete[/bold green]")
    console.print(f"[green]Subdomains:[/green] {line_count(subdomains_all)}")
    console.print(f"[green]Live hosts:[/green] {line_count(alive_file)}")
    console.print(f"[green]URLs:[/green] {line_count(urls_file)}")
    console.print(f"[green]Report:[/green] {reports / 'summary.md'}")


@app.command()
def tools() -> None:
    """Show dependency status."""
    table = Table(title="MegaRecon Tool Doctor")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Category")
    table.add_column("Purpose")
    table.add_column("Install hint")

    for tool, meta in TOOL_REGISTRY.items():
        status = "[green]FOUND[/green]" if has_tool(tool) else "[red]MISSING[/red]"
        table.add_row(tool, status, meta["category"], meta["purpose"], meta["install"])

    console.print(table)


@app.command()
def profiles() -> None:
    """List available scan profiles."""
    table = Table(title="Profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Description")
    table.add_column("Tools")
    for name, meta in PROFILES.items():
        table.add_row(name, meta["desc"], ", ".join(meta["tools"]))
    console.print(table)


@app.command()
def wizard() -> None:
    """Interactive guided flow."""
    console.print(Panel.fit(
        "[bold]MegaRecon Wizard[/bold]\n"
        "Authorized targets only. Choose profile, intensity, and optional modules.",
        border_style="blue"
    ))

    target = Prompt.ask("Target domain or base URL", default="example.com")
    profile = Prompt.ask("Profile", choices=list(PROFILES.keys()), default="balanced")
    intensity = Prompt.ask("Intensity", choices=list(INTENSITY.keys()), default="medium")
    enable_ffuf = Confirm.ask("Enable content discovery (ffuf)?", default=(profile == "deep"))
    enable_nuclei = Confirm.ask("Enable safe nuclei recon checks?", default=True)
    wordlist = Prompt.ask(
        "Wordlist path for ffuf",
        default="/usr/share/seclists/Discovery/Web-Content/common.txt"
    )

    run_workflow(target, profile, intensity, enable_ffuf, enable_nuclei, wordlist)


@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target domain or base URL"),
    profile: str = typer.Option("balanced", "--profile", "-p", help="passive | balanced | deep"),
    intensity: str = typer.Option("medium", "--intensity", "-i", help="low | medium | high"),
    enable_ffuf: bool = typer.Option(False, "--ffuf", help="Enable ffuf content discovery"),
    enable_nuclei: bool = typer.Option(True, "--nuclei/--no-nuclei", help="Enable safe nuclei checks"),
    wordlist: str = typer.Option(
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "--wordlist",
        "-w",
        help="Wordlist for ffuf",
    ),
) -> None:
    """Run a recon workflow."""
    if profile not in PROFILES:
        raise typer.BadParameter(f"Unknown profile: {profile}")
    if intensity not in INTENSITY:
        raise typer.BadParameter(f"Unknown intensity: {intensity}")

    run_workflow(target, profile, intensity, enable_ffuf, enable_nuclei, wordlist)


if __name__ == "__main__":
    app()