#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

DEFAULT_WEIGHTS = {"critical": 100, "high": 30, "medium": 10, "low": 1}
DEFAULT_THRESHOLDS = {"rejectMinScore": 100, "cautionMinScore": 20}
ROOT = Path(__file__).resolve().parent
DEFAULT_POLICY = ROOT.parent / "references" / "audit-policy.example.json"
DEFAULT_PROFILES = ROOT.parent / "references" / "policy-profiles.json"


def deep_merge(base, patch):
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_json(path: Path):
    return json.loads(path.read_text())


def resolve_profile(profile_name: str, profiles_doc: dict):
    profiles = profiles_doc.get("profiles", {})
    if profile_name not in profiles:
        raise SystemExit(f"Unknown profile '{profile_name}'. Available: {', '.join(sorted(profiles.keys()))}")
    selected = profiles[profile_name]
    if isinstance(selected, dict) and "$ref" in selected:
        ref = (DEFAULT_PROFILES.parent / selected["$ref"]).resolve()
        return load_json(ref)
    return selected


def apply_policy(findings, policy, category):
    p = policy or {}
    weights = deep_merge(DEFAULT_WEIGHTS, p.get("severityWeights", {}))
    thresholds = deep_merge(DEFAULT_THRESHOLDS, p.get("verdictThresholds", {}))
    rules = p.get("rules", {})

    cat = str(category) if category is not None else None
    if cat and "overridesByCategory" in p and cat in p["overridesByCategory"]:
        ov = p["overridesByCategory"][cat]
        weights = deep_merge(weights, ov.get("severityWeights", {}))
        thresholds = deep_merge(thresholds, ov.get("verdictThresholds", {}))
        rules = deep_merge(rules, ov.get("rules", {}))

    normalized = []
    score = 0
    for f in findings:
        sev = f.get("severity", "low")
        typ = f.get("type", "unknown")
        if typ in rules and "severity" in rules[typ]:
            sev = rules[typ]["severity"]
        w = int(weights.get(sev, 0))
        score += w
        nf = dict(f)
        nf["effectiveSeverity"] = sev
        nf["weight"] = w
        normalized.append(nf)

    reject_min = int(thresholds.get("rejectMinScore", 100))
    caution_min = int(thresholds.get("cautionMinScore", 20))

    if score >= reject_min:
        verdict = "REJECT"
    elif score >= caution_min:
        verdict = "CAUTION"
    else:
        verdict = "APPROVED"

    return verdict, score, normalized, {"weights": weights, "thresholds": thresholds, "rules": rules}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings_json", help="JSON from static_audit.py")
    ap.add_argument("--policy", help="Path to policy JSON", default=os.getenv("SKILLCHECK_POLICY"))
    ap.add_argument("--profiles", help="Path to profile JSON", default=os.getenv("SKILLCHECK_PROFILES", str(DEFAULT_PROFILES)))
    ap.add_argument("--profile", help="Profile key from policy-profiles.json", default=os.getenv("SKILLCHECK_PROFILE"))
    ap.add_argument("--category", type=int, choices=[1, 2, 3, 4], default=int(os.getenv("SKILLCHECK_CATEGORY", "2")))
    args = ap.parse_args()

    with open(args.findings_json) as f:
        report = json.load(f)

    # Precedence: explicit --policy > --profile > default policy file
    policy = None
    policy_source = "default"
    if args.policy:
        p = Path(args.policy)
        if not p.exists():
            raise SystemExit(f"Policy file not found: {p}")
        policy = load_json(p)
        policy_source = str(p)
    elif args.profile:
        pf = Path(args.profiles)
        if not pf.exists():
            raise SystemExit(f"Profiles file not found: {pf}")
        policy = resolve_profile(args.profile, load_json(pf))
        policy_source = f"profile:{args.profile}"
    else:
        policy = load_json(DEFAULT_POLICY)
        policy_source = str(DEFAULT_POLICY)

    verdict, score, normalized, effective = apply_policy(report.get("findings", []), policy, args.category)

    print(
        json.dumps(
            {
                "target": report.get("target"),
                "category": args.category,
                "policySource": policy_source,
                "verdict": verdict,
                "riskScore": score,
                "summary": report.get("summary", {}),
                "effectivePolicy": effective,
                "findings": normalized,
                "next_actions": {
                    "APPROVED": "Enable with normal monitoring",
                    "CAUTION": "Apply remediations and re-test in sandbox",
                    "REJECT": "Do not install/enable; isolate and investigate",
                }[verdict],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
