# High-Risk Patterns and Gate Outcomes

## Immediate REJECT patterns
- Download + execute (`curl|sh`, remote script eval)
- Obfuscated payload execution (`base64 -> eval/exec`, staged loaders)
- Reverse shell/backdoor behavior
- Undeclared sensitive capability (network/process/persistence/secrets)
- Unsafe archive extraction in shared context (Zip Slip risk)

## Typical CAUTION patterns
- Network use declared but not tightly scoped
- Process execution with partial sanitization
- Minor docs mismatch (feature drift)
- Writes outside expected subdir but still inside workspace

## Hardening requirements
- Validate all file/archive paths before extraction
- Normalize + enforce path boundaries
- Strict input schema + type/length limits
- Deny-by-default egress for tests
- Redact secrets from logs
