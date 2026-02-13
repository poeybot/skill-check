#!/usr/bin/env python3
import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static_audit.py"
VERDICT = ROOT / "verdict.py"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def parse_files_list(stdout: str):
    files = []
    in_files = False
    for line in stdout.splitlines():
        if line.strip() == "Files:":
            in_files = True
            continue
        if not in_files or not line.strip():
            continue
        parts = line.split("  ")
        fp = parts[0].strip()
        if "/" in fp or fp.endswith((".md", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml", ".toml", ".txt", ".cfg", ".ini")):
            files.append(fp)
    return files


def main():
    ap = argparse.ArgumentParser(description="Scan ClawHub skill by slug without installing")
    ap.add_argument("slug")
    ap.add_argument("--version", default=None, help="Specific version")
    ap.add_argument("--category", type=int, choices=[1, 2, 3, 4], default=2)
    ap.add_argument("--policy", default=None)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--profiles", default=None)
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="skill-check-"))
    try:
        inspect_cmd = ["clawhub", "inspect", args.slug, "--files"]
        if args.version:
            inspect_cmd += ["--version", args.version]

        meta = run(inspect_cmd)
        if meta.returncode != 0:
            print(meta.stderr or meta.stdout)
            raise SystemExit(1)

        files = parse_files_list(meta.stdout)
        if not files:
            raise SystemExit("No files parsed from clawhub inspect --files output")

        target = tmp / "skill"
        target.mkdir(parents=True, exist_ok=True)

        for fp in files:
            out_cmd = ["clawhub", "inspect", args.slug, "--file", fp]
            if args.version:
                out_cmd += ["--version", args.version]
            out = run(out_cmd)
            if out.returncode != 0:
                continue
            content = out.stdout
            if content.startswith("- Fetching skill"):
                content = "\n".join(content.splitlines()[1:]).lstrip("\n")
            dst = target / fp
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(content, encoding="utf-8")

        findings = tmp / "findings.json"
        r1 = run(["python3", str(STATIC), str(target), "--format", "json"])
        if r1.returncode != 0:
            print(r1.stderr or r1.stdout)
            raise SystemExit(r1.returncode)
        findings.write_text(r1.stdout, encoding="utf-8")

        verdict_cmd = ["python3", str(VERDICT), str(findings), "--category", str(args.category)]
        if args.policy:
            verdict_cmd += ["--policy", args.policy]
        if args.profile:
            verdict_cmd += ["--profile", args.profile]
        if args.profiles:
            verdict_cmd += ["--profiles", args.profiles]

        r2 = run(verdict_cmd)
        if r2.returncode != 0:
            print(r2.stderr or r2.stdout)
            raise SystemExit(r2.returncode)
        print(r2.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
