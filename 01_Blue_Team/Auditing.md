# Microsoft 365 Security Assessment Tools

Reference for open-source tools used to assess an M365 tenant (and related cloud/identity infrastructure) against security baselines. Each tool is read-only by design, but check the permissions each one requests before running it in production.

## Quick comparison

| Tool | Focus | Runs as | Output | Best for |
|------|-------|---------|--------|----------|
| [Maester](https://maester.dev/) | M365 / Entra security tests (Pester-based) | PowerShell module | HTML, Markdown, JSON, CI/CD results | Repeatable, scheduled tests; custom tests; drift detection |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | M365 against CISA SCuBA baselines | PowerShell module | HTML report, JSON, CSV | Government-aligned baseline compliance |
| [Prowler](https://github.com/prowler-cloud/prowler) | Multi-cloud security and compliance (AWS, Azure, GCP, M365, Kubernetes, more) | CLI / local server | HTML, CSV, JSON, compliance reports | Covering M365 alongside other cloud environments |
| [M365-Assess](https://github.com/Galvnyz/M365-Assess) | M365 assessment, 290+ checks across 14 compliance frameworks | PowerShell | Interactive HTML report | Framework mapping; no data leaves the machine |
| [Purple Knight](https://www.semperis.com/purple-knight/) | On-prem Active Directory security posture (also covers Entra ID) | Windows executable (Semperis, free community tool) | Scored report of indicators of exposure/compromise | AD hardening and finding AD misconfigurations M365 tools don't see |
