# Audit Toolkit (Practical Stack)

Use this as a menu based on skill risk category.

## Static analysis
- **Semgrep**: custom rules for dangerous patterns (`curl|sh`, `exec`, unsafe extraction).
- **Bandit** (Python): insecure Python constructs.
- **npm audit / pnpm audit / yarn audit**: JS dependency risk.
- **pip-audit / safety**: Python dependency CVEs.

## SBOM + vuln correlation
- **Syft**: generate SBOM.
- **Grype** or **Trivy**: scan SBOM/filesystem for known vulns.
- **OSV-Scanner**: ecosystem-aware vuln matching.

## Secret scanning
- **gitleaks**: fast baseline secret detector.
- **trufflehog**: high-signal secret detection with verification options.

## Runtime / behavior
- **strace**: process, file, socket behavior tracing.
- **auditd**: host-level syscall auditing policy.
- **Falco (eBPF)**: runtime anomaly detection in containerized workloads.
- **iptables/nftables**: explicit network deny/allow checks during execution.

## Supply-chain trust
- Pin source by immutable commit SHA/tag.
- Prefer signed tags/commits and provenance attestations when available.
- Record source URL + commit in final report.
- Reject floating refs (`main`, `latest`) for production approvals.

## Policy gates
- Optional: OPA/Conftest to enforce machine-checkable policy:
  - deny undeclared network capability
  - deny download+exec
  - require source pinning

## Minimal baseline by risk category
- Cat 1: quick triage + static audit
- Cat 2: + secret scan + dependency audit
- Cat 3: + dynamic probe with network restrictions
- Cat 4: full stack + strict sandbox + manual review
