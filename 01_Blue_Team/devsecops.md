# DevSecOps Security Scanners: Reference

A reference list of security scanning tools: what each one does and what it's good for.

---

## Summary table

| # | Tool | Category | Runs where | Cost | Good for |
|---|---|---|---|---|---|
| 1 | TruffleHog | Secrets (history + verification) | CLI | Free (OSS) | Finding leaked credentials anywhere and checking whether they still work |
| 2 | Gitleaks | Secrets (prevention) | Pre-commit hook + CI | Free (OSS) | Stopping secrets before they're committed or merged |
| 3 | OSV-Scanner | Dependency vulnerabilities (SCA) | CLI + CI | Free (OSS) | Flagging third-party packages with known vulnerabilities |
| 4 | Semgrep | Static code analysis (SAST) | CLI + CI | Free (OSS CE) | Catching bug patterns across a codebase with prebuilt or custom rules |
| 5 | Claude Code Security Review | AI PR review | GitHub Actions | API usage | Automatic AI security review on every pull request |
| 6 | Cloudflare Security Audit | AI audit skill | Coding agent (skill) | Agent usage | Deep, multi-phase code audit with verified findings |
| 7 | NVIDIA SkillSpector | AI skill/plugin vetting | CLI | Free (OSS) | Checking agent skills for prompt injection and data exfiltration before installing |
| 8 | Strix | AI pentesting (DAST) | Docker + LLM | LLM tokens | Actively pentesting a running app and helping fix findings |

**Categories at a glance:**

- **Secrets:** TruffleHog (find what already leaked), Gitleaks (stop new leaks)
- **Dependencies:** OSV-Scanner
- **Source code:** Semgrep (rules-based), Claude Code Security Review and Cloudflare Security Audit (AI-based)
- **Running app:** Strix
- **AI tooling supply chain:** SkillSpector

---

## 1. TruffleHog

**Link:** https://github.com/trufflesecurity/trufflehog

**What it does:** Finds leaked credentials (API keys, passwords, tokens) in git history, filesystems, cloud storage, and whole GitHub or GitLab organizations. It also tests whether each credential still works, which separates real emergencies from old noise.

**Good for:**
- One-time or periodic sweeps of full commit history across many repos
- Telling live, exploitable secrets apart from dead ones

**Install:**
```bash
# Linux / macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# Windows
winget install trufflesecurity.trufflehog   # or download a release binary
```

**Common commands:**
```bash
trufflehog gitlab --token="$GITLAB_TOKEN" --only-verified   # every GitLab project the token can see
trufflehog github --org=<org> --only-verified               # every repo in a GitHub org
trufflehog git file://. --only-verified                     # one local repo, full history
trufflehog filesystem ./path --only-verified                # a folder (not git-aware)
```

**Notes:**
- `--only-verified` = the credential still authenticates. Rotate these immediately.
- Removing a secret in a later commit does not remove it from history. Rotate the credential.

---

## 2. Gitleaks

**Link:** https://github.com/gitleaks/gitleaks

**What it does:** A fast secret scanner designed to block secrets before they land in a commit or merge. It doesn't check whether a secret works (that's TruffleHog's job).

**Good for:**
- Pre-commit hooks on developer machines
- A fast, blocking secret check in CI pipelines

**Install:**
```bash
brew install gitleaks              # macOS / Linuxbrew
winget install Gitleaks.Gitleaks   # Windows
# or download a release binary from GitHub
```

**Common commands (v8.19+ syntax):**
```bash
gitleaks git .                                   # scan repo history
gitleaks dir .                                   # scan files on disk
gitleaks git --pre-commit --staged --redact -v   # check staged changes before commit
gitleaks git . --report-path gitleaks.json       # write a report
gitleaks git . --baseline-path gitleaks.json     # ignore previously accepted findings
```
> Older versions use `gitleaks detect` / `gitleaks protect --staged`.

**Pre-commit hook (pre-commit framework):**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2   # pin to a current release
    hooks:
      - id: gitleaks
```

**Notes:** False positives go in `.gitleaksignore` (by fingerprint) or a `.gitleaks.toml` allowlist.

---

## 3. OSV-Scanner (Google)

**Link:** https://github.com/google/osv-scanner

**What it does:** Reads dependency files (lockfiles and manifests) and reports packages with known vulnerabilities from the OSV.dev database. Supports most ecosystems: Python, npm, Go, Maven, Cargo, and more.

**Good for:**
- Low-noise dependency vulnerability checks in CI
- A quick scan across many repos at once

**Install:**
```bash
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
# or download a release binary from GitHub
```

**Common commands:**
```bash
osv-scanner scan source -r .                 # v2: scan current dir recursively
osv-scanner -r .                             # v1 syntax
osv-scanner scan source -r . --format json   # machine-readable output
```

**Notes:**
- Unpinned dependencies (no version specified) can't be matched precisely, so pin versions for accurate results.
- Accepted risks go in `osv-scanner.toml` with an `[[IgnoredVulns]]` entry and a reason.

---

## 4. Semgrep

**Link:** https://github.com/semgrep/semgrep

**What it does:** Pattern-based static analysis for 30+ languages. It ships with rule packs for common bugs (injection, insecure configs, unsafe `eval`, missing CSRF protection, and so on), and you can write your own rule once to catch the same pattern in every file.

**Good for:**
- General SAST in CI
- Encoding recurring mistakes as custom rules so they never come back

**Install:**
```bash
pip install semgrep        # or: pipx install semgrep / brew install semgrep
```

**Common commands:**
```bash
semgrep scan --config auto                                   # auto-select rules for the project
semgrep scan --config p/python --config p/django --config p/secrets
semgrep scan --config p/python --error                       # non-zero exit on findings (CI)
semgrep scan --config ./semgrep-rules/                       # run custom rules
semgrep scan --config p/python --json -o semgrep.json
```

**Useful rule packs:** `p/python`, `p/django`, `p/flask`, `p/javascript`, `p/typescript`, `p/secrets`, `p/owasp-top-ten`, `p/docker`, `p/terraform`

**Custom rule example:**
```yaml
rules:
  - id: requests-without-timeout
    languages: [python]
    severity: WARNING
    message: requests call without timeout can hang forever
    patterns:
      - pattern: requests.$METHOD(...)
      - pattern-not: requests.$METHOD(..., timeout=$T, ...)
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(get|post|put|patch|delete|head)$
```

**Notes:**
- Silence one line with `# nosemgrep: rule-id`.
- PowerShell support is limited. PSScriptAnalyzer (`Invoke-ScriptAnalyzer -Path . -Recurse`) covers that gap.

---

## 5. Claude Code Security Review

**Link:** https://github.com/anthropics/claude-code-security-review

**What it does:** A GitHub Action that has Claude review each pull request for security issues and post findings as PR comments, before a human reviewer opens it.

**Good for:**
- Automated first-pass security review on every PR
- Catching logic-level issues that rule-based scanners miss

**Notes:**
- Runs on GitHub Actions only and needs an Anthropic API key.
- Claude Code also has a built-in `/security-review` command that reviews the current branch's changes locally, with no CI setup.

---

## 6. Cloudflare Security Audit

**Link:** https://lnkd.in/ed2r4c98 *(LinkedIn short link: replace with the real repo URL)*

**What it does:** A skill for coding agents that runs a security audit in several phases and verifies every finding before reporting it, which cuts down on false positives.

**Good for:**
- A deep, periodic audit of a single application
- Getting a reviewed list of real issues instead of raw scanner output

**Notes:** Review a skill's contents before installing it (see SkillSpector).

---

## 7. NVIDIA SkillSpector

**Link:** https://lnkd.in/ehhbYDpF *(LinkedIn short link: replace with the real repo URL)*

**What it does:** Scans AI agent skills and plugins for prompt injection, hidden instructions, and data exfiltration before you install them.

**Good for:**
- Vetting third-party agent skills and plugins before installing them
- Auditing skills that are already installed

**Notes:** Skills run with the user's permissions and can see code and credentials. This is supply-chain security for AI tooling.

---

## 8. Strix

**Link:** https://github.com/usestrix/strix

**What it does:** AI agents that actively pentest a running application (dynamic testing), then help fix what they find.

**Good for:**
- Finding exploitable issues that only show up at runtime (auth flaws, injection, access control)
- Validating fixes against a live target

**Notes:**
- Requires Docker and an LLM API key. Token usage can be high.
- It actively attacks the target. Only run it against systems you own, ideally a disposable staging copy, never production.

---

## Glossary

- **SAST:** Static Application Security Testing; analyzes source code without running it (Semgrep).
- **SCA:** Software Composition Analysis; checks third-party dependencies for known vulnerabilities (OSV-Scanner).
- **DAST:** Dynamic Application Security Testing; attacks a running app (Strix).
- **Secret scanning:** finds credentials committed to code or history (Gitleaks, TruffleHog).
- **Verified secret:** a found credential that was tested and still works.
- **Pre-commit hook:** a script that runs locally before `git commit` completes and can block the commit.
