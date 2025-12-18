# Lab 0 (Python) — PyPay Risk Monitor: Hardening With SonarCloud Quality Gates

## Story
You have joined **PyPay**, a fast-growing fintech building internal services for vendor risk checks and payout validation.

The team had incidents:
- a leaked API key in code and logs,
- unsafe “debug endpoints” used by attackers,
- untrusted data parsing leading to remote code execution risk,
- missing TLS checks and timeouts causing outages,
- path traversal and IDOR issues exposing data.

Your mission is to make the repo “merge-safe” by enforcing:
- SonarCloud scan on every push/PR
- Quality Gate that blocks unsafe code
- simple, line-by-line security fixes

## What You Will Do
1) Create a GitHub repository and push the starter code.
2) Connect the repository to SonarCloud.
3) Add the SonarCloud token as GitHub Actions secret:
   - `SONAR_TOKEN`
4) Add `sonar-project.properties` and `.github/workflows/build.yml`.
5) Push changes and verify:
   - GitHub Actions workflow runs
   - SonarCloud receives analysis
   - Quality Gate is computed

## Student Tasks (Fix by replacing the vulnerable line)
The project contains issues across severities:
- Critical
- High
- Medium
- Low

Rule:
- For each vulnerable line, replace it with the `# FIX:` line directly below it.
- Do not refactor large blocks.
- Keep fixes minimal, copy/paste style.

### app/config.py — Questions
1) Identify which lines represent secret handling violations.
2) Which defaults are unsafe for production?
3) Why does “timeout=0” create reliability and security risk?
4) What is the risk of `ALLOW_INSECURE_TLS=true`?
5) Which settings should fail the build if misconfigured?

### app/security.py — Questions
1) Why is `pickle.loads` dangerous with untrusted data?
2) Why is `yaml.load` risky compared to `safe_load`?
3) Why is `md5` not acceptable for signing?
4) What is wrong with allowing JWT `alg=none`?
5) What is the risk of `shell=True`?

### app/main.py — Questions
1) Where is SSRF present and how do you remove it safely?
2) Where is path traversal present and how do you prevent it?
3) Where is TLS validation disabled and why is that bad?
4) Where is IDOR present and how do you enforce proper access control?
5) Where do logs leak secrets and how do you redact them?

## Completion Criteria
- GitHub Actions pipeline is green
- SonarCloud Quality Gate is “Passed”
- PR contains minimal line-level fixes
- No secrets are logged or hardcoded
- Debug endpoints are removed or blocked
