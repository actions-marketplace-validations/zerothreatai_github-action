# ZeroThreat – AI-Powered Automated Penetration Testing Platform

ZeroThreat is an AI-powered automated penetration testing platform that uncovers real, exploitable vulnerabilities across modern web applications and APIs with proof-based validation and vulnerability coverage. It uses Agentic AI to execute adaptive attacker workflows, combining deep CVE coverage, authenticated testing, business logic testing, and community-driven attack templates to help teams prioritize real risk and eliminate false positives.

## Inputs

| Input               | Description                                                          | Required | Default |
| ------------------- | -------------------------------------------------------------------- | -------- | ------- |
| `ZT_TOKEN`          | ZT_TOKEN to authenticate API request & start the scan.               | Yes      |         |
| `WAIT_FOR_ANALYSIS` | Set this true to wait for analysis to complete before finishing job. | No       | false   |
| `ON_PREM_PROXY_API_URL` | Set proxy url host to scan internal targets. | No       |    |


## How It Works

1. **ZeroThreat AI Scanner**: The DAST scan is triggered by passing the `zt_token`. Each token corresponds to a specific target defined within the ZeroThreat application. Upon receiving the token, the ZeroThreat DevOps Bot executes prerequisite checks before commencing the scan process.
2. **Scan Report**: As soon as the ZeroThreat DevOps Bot starts the security scan, The scan report will be available in the ZeroThreat Portal.

### Secrets Setup
1. Generate the `zt_token` from the ZeroThreat Portal.
   
2. Add the secret in your GitHub repository under **Settings > Secrets**:
    - `zt_token`: ZT_TOKEN to authenticate API request & start the scan.


## Notes

- Ensure secrets are correctly configured in your GitHub repository for scan initiation. 
- ZeroThreat offers a centralized dashboard displaying all scan results.

