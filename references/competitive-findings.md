# Competitive Findings (Skill Scanner Landscape)

Analyzed targets:
- `skill-scan` (dgriffin831)
- `ai-skill-scanner` (HugoSbl)
- `clawhub-skill-scanner` (amir-ag)
- `openclaw-skill-scanner` (epwhesq)

## Useful patterns adopted into Skill Check

1. **Pre-install workflow enforcement**
- Added `scripts/scan_hub_slug.py` to scan ClawHub slugs **without installation**.

2. **Category-based scoring and policy gates**
- Kept and extended policy-driven verdicts (`--policy`, `--category`) for deterministic decisions.

3. **False-positive controls**
- Distinguish executable behavior from docs/signature catalogs.
- Honor `noscan` markers for intentional signature lists.
- Keep known-good API domains from escalating automatically.

4. **Archive risk detection**
- Added `archive_extraction_surface` finding (Zip Slip hardening checks).

5. **Operational reporting discipline**
- Keep mandatory output structure with actionable remediation/retest steps.

## Useful ideas not blindly adopted

- Huge static rulesets with broad regex-only matching: high recall but high noise.
- Auto-blocking all medium findings: too aggressive for legitimate integration skills.
- Installing then scanning: rejected; we prefer scan-before-install.

## Observed caveats in competitor skills

- Several scanners include signatures/examples that self-trigger their own critical rules.
- Some rely heavily on README semantics (high false-positive risk).
- Some include strong claims ("12-layer", "60+ rules") without robust runtime verification.
