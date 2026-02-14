---
name: skill-check
description: Security audit gate for new OpenClaw skills before installation/use. Use when reviewing ClawHub/GitHub/local skills for malicious patterns, undeclared capabilities, supply-chain risk, prompt-injection traps, and runtime abuse; return APPROVED/CAUTION/REJECT with policy-based scoring.
---

# Skill Check

Use this skill **before enabling or installing** third-party skills.

## 1) Threat category (sets strictness)

1. Pure compute
2. Local I/O
3. Networked
4. System-level

Higher category => stricter verdict policy.

## 2) Fast triage (5 min)

```bash
scripts/quick_triage.sh /path/to/skill
```

Immediate CAUTION/REJECT triggers:
- Unknown/unverifiable source
- Download+exec patterns
- Undeclared capability
- Unsafe archive extraction patterns

## 3) Mandatory static audit

```bash
python3 scripts/static_audit.py /path/to/skill --format json > findings.json
python3 scripts/verdict.py findings.json --category 2 --policy references/audit-policy.example.json
```

## 4) Dynamic probe (required for category 3/4 or suspicious)

```bash
scripts/dynamic_probe.sh /path/to/skill
```

## 5) ClawHub pre-install scan without installing

```bash
python3 scripts/scan_hub_slug.py skill-scanner --category 2 --profile balanced
# or strict:
python3 scripts/scan_hub_slug.py skill-scanner --category 3 --profile strict
# or custom policy file:
python3 scripts/scan_hub_slug.py skill-scanner --category 2 --policy references/audit-policy.gc.json
```

This downloads skill files via `clawhub inspect --file` into a temp workspace, scans, prints verdict, then cleans up.

## 5.1) Enforced installer (recommended default)

Use the safe installer wrapper so install is blocked unless verdict is APPROVED:

```bash
scripts/safe_install.sh <slug>
# optional
scripts/safe_install.sh <slug> --version 1.2.3 --category 2 --policy references/audit-policy.gc.json
```

Behavior:
- runs `scan_hub_slug.py`
- aborts install on CAUTION/REJECT/failure
- proceeds with `clawhub install` only when APPROVED
- writes audit log to `~/.openclaw/workspace/.learnings/skill-audit-*.log`

## 5.2) Shell guard (auto-enforce `clawhub install`)

One-time setup:

```bash
scripts/install_shell_guard.sh
source ~/.bashrc   # or reopen shell
```

After this, `clawhub install <slug>` is intercepted and routed through `scripts/safe_install.sh`.

## 6) Decision policy

- **APPROVED**: low risk, declared/minimal behavior
- **CAUTION**: meaningful but controlled risk; manual review required
- **REJECT**: critical risk, undeclared high-impact capability, persistence/exfil/obfuscation abuse

## 7) Report output (always)

Use `references/report-template.md` format:
- identity + source + pinned version
- category + summary
- key findings
- verdict
- remediation + retest commands

## Notable hardening rules in this skill

- Avoid doc-only false positives (distinguish executable behavior vs docs/signature catalogs)
- Support `noscan` suppression markers for intentionally listed patterns
- Policy-based severity/threshold tuning by category
- Sandbox-first workflow (`tools/project-mode.sh ...`)

## Runtime configurability (production)

Environment variable support:

- `SKILLCHECK_PROFILE` (`strict|balanced|lenient|gc`)
- `SKILLCHECK_CATEGORY` (`1..4`)
- `SKILLCHECK_POLICY` (custom policy JSON path)
- `SKILLCHECK_PROFILES` (custom profiles JSON path)

Priority:
1. explicit CLI flags
2. env vars
3. defaults

## References

- `references/toolkit.md`
- `references/risk-patterns.md`
- `references/report-template.md`
- `references/audit-policy.example.json`
- `references/audit-policy.gc.json`
- `references/policy-profiles.json`
- `references/competitive-findings.md`
