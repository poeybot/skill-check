#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".ps1", ".go", ".rb", ".php", ".java", ".rs"}
DOC_EXT = {".md", ".txt", ".rst", ".adoc", ".json", ".yaml", ".yml", ".toml"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "test-fixtures"}
MAX_FILE_BYTES = 1_000_000
NOSCAN = re.compile(r"#\s*noscan|<!--\s*noscan\s*-->", re.IGNORECASE)

PATTERNS = {
    "filesystem_sensitive": [r"\.ssh", r"\.aws", r"keychain", r"/etc", r"\.env", r"auth-profiles\.json"],
    "process_exec": [r"subprocess\.", r"os\.system\(", r"child_process", r"spawn\(", r"exec\("],
    "network": [r"requests\.", r"httpx\.", r"urllib", r"fetch\(", r"axios", r"websocket", r"socket", r"curl\b", r"wget\b"],
    "persistence": [r"cron", r"systemd", r"launchd", r"schtasks", r"rc\.local", r"\.bashrc", r"\.zshrc"],
    "archive_risk": [r"extractall\(", r"tarfile\.extract\(", r"zipfile\.ZipFile"],
    "malware_critical": [r"curl\s+.*\|\s*(sh|bash)", r"wget\s+.*\|\s*(sh|bash)", r"reverse shell", r"base64\.b64decode.*exec\("],
}

KNOWN_GOOD_NETWORK = (
    "api.github.com", "api.openai.com", "api.anthropic.com", "registry.npmjs.org", "pypi.org", "clawhub.com", "localhost", "127.0.0.1"
)


def is_code_file(p: Path) -> bool:
    return p.suffix.lower() in CODE_EXT


def is_doc_file(p: Path) -> bool:
    return p.suffix.lower() in DOC_EXT


def scan_text(text, pats):
    hits = []
    for p in pats:
        if re.search(p, text, re.IGNORECASE):
            hits.append(p)
    return hits


def malware_hit_is_signature_catalog(text: str, pattern: str) -> bool:
    for line in text.splitlines():
        if re.search(pattern, line, re.IGNORECASE):
            l = line.lower()
            if NOSCAN.search(l):
                return True
            if "pattern" in l or "signature" in l or "rule" in l or "detect" in l or "example" in l:
                return True
    return False


def list_files(root: Path):
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except Exception:
            continue
        out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--format", choices=["json", "text"], default="text")
    args = ap.parse_args()

    root = Path(args.target)
    if not root.is_dir():
        raise SystemExit("target must be directory")

    files = list_files(root)
    findings = []

    declared = ""
    for f in files:
        if f.name.lower() in ("skill.md", "readme.md", "readme"):
            declared += f.read_text(errors="ignore") + "\n"

    cap_hits = {k: set() for k in PATTERNS.keys()}
    malware_doc_hits = []
    malware_signature_hits = []

    for f in files:
        txt = f.read_text(errors="ignore")
        for k, pats in PATTERNS.items():
            for h in scan_text(txt, pats):
                if k == "network" and any(dom in txt.lower() for dom in KNOWN_GOOD_NETWORK):
                    # keep but lower-noise by not hard-failing on known-good API use
                    pass
                if k == "malware_critical":
                    if is_doc_file(f):
                        malware_doc_hits.append((str(f), h))
                        continue
                    if is_code_file(f) and malware_hit_is_signature_catalog(txt, h):
                        malware_signature_hits.append((str(f), h))
                        continue
                cap_hits[k].add((str(f), h))

    declared_l = declared.lower()
    declared_network = any(w in declared_l for w in ["network", "http", "api", "webhook", "request"])
    declared_exec = any(w in declared_l for w in ["exec", "process", "subprocess", "command", "shell"])

    code_network_hits = [(a, b) for (a, b) in cap_hits["network"] if is_code_file(Path(a))]
    code_exec_hits = [(a, b) for (a, b) in cap_hits["process_exec"] if is_code_file(Path(a))]

    if code_network_hits and not declared_network:
        findings.append({"severity": "critical", "type": "undeclared_capability", "detail": "Network capability detected in executable files but not declared"})
    if code_exec_hits and not declared_exec:
        findings.append({"severity": "high", "type": "undeclared_capability", "detail": "Process execution detected in executable files but not declared"})

    if cap_hits["malware_critical"]:
        findings.append({"severity": "critical", "type": "malware_pattern", "detail": "Critical malware-like execution pattern(s) in executable files"})
    elif malware_signature_hits:
        findings.append({"severity": "medium", "type": "signature_catalog_context", "detail": "Malware signatures appear mostly as scanner catalog/rules"})

    if cap_hits["filesystem_sensitive"]:
        findings.append({"severity": "medium", "type": "secret_access_surface", "detail": "Sensitive filesystem paths referenced"})
    if cap_hits["persistence"]:
        findings.append({"severity": "high", "type": "persistence_surface", "detail": "Persistence mechanism references detected"})
    if cap_hits["archive_risk"]:
        findings.append({"severity": "high", "type": "archive_extraction_surface", "detail": "Archive extraction patterns found; verify Zip Slip/path checks"})

    report = {
        "target": str(root),
        "summary": {
            "files_scanned": len(files),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        },
        "capabilities": {k: [{"file": a, "pattern": b} for a, b in sorted(v)] for k, v in cap_hits.items()},
        "context": {
            "malware_doc_hits": [{"file": a, "pattern": b} for a, b in malware_doc_hits],
            "malware_signature_hits": [{"file": a, "pattern": b} for a, b in malware_signature_hits],
        },
        "findings": findings,
    }

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"Scanned {report['summary']['files_scanned']} files")
        print("Findings:", findings)


if __name__ == "__main__":
    main()
