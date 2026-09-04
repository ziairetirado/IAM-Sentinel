# IAM Sentinel

**Automated AWS IAM Security Audit Tool** — a read-only Python/boto3 script that scans an AWS account's identity configuration and reports on common misconfigurations before they become an incident.

---

## The Problem

IAM is the most common source of AWS breaches — not misconfigured S3 buckets or unpatched EC2 instances, but **overly permissive, stale, or unmonitored identities**. Specifically:

- **Users without MFA** are a single-factor point of failure. A leaked password is a full account compromise.
- **Long-lived, unrotated access keys** widen the window of exposure if a key is ever leaked (committed to a repo, logged, phished, etc.). AWS and most compliance frameworks (CIS AWS Foundations, SOC 2, PCI-DSS) recommend rotation at 90 days or less.
- **Overly permissive policies** (`"Action": "*"` on `"Resource": "*"`, or broad service wildcards like `s3:*`) violate least-privilege and turn a single compromised credential into full account takeover.

These issues are easy to introduce (a developer grants `AdministratorAccess` "just for now" and forgets to revoke it) and easy to miss, because IAM has no built-in dashboard that surfaces them together. Manually auditing IAM via the console does not scale past a handful of users, and it's the kind of check that gets skipped under deadline pressure — which is exactly when it matters most.

**IAM Sentinel automates that audit** so it can run on a schedule, gate a CI/CD pipeline, or be handed to an auditor as evidence of ongoing review — instead of relying on someone remembering to check the console.

---

## What It Does

IAM Sentinel connects to an AWS account (read-only) and checks every IAM user for:

| Check | What it catches | Why it matters |
|---|---|---|
| **MFA status** | Users with zero MFA devices registered | Removes the single point of failure on password-only auth |
| **Access key age** | Active access keys older than a configurable threshold (default: 90 days) | Limits the blast radius of a leaked long-lived credential |
| **Policy permissiveness** | Inline and managed policies — attached directly *or* inherited via group membership — that combine wildcard actions (`*`, `s3:*`, etc.) with wildcard resources (`*`) | Flags least-privilege violations before they're exploited |

It then produces a **clean, structured report** — human-readable in the console, and optionally exported as JSON (for tooling/SIEM ingestion) or CSV (for spreadsheets and audit evidence).

---

## How It Works

1. Authenticates to AWS via boto3 (credentials from `aws configure`, environment variables, an IAM role, or a named `--profile`).
2. Confirms the session is valid via `sts:GetCallerIdentity` — fails fast with a clear error if credentials are missing or invalid.
3. Paginates through every IAM user in the account (`iam:ListUsers`).
4. For each user, runs three independent checks:
   - `list_mfa_devices` — flags any user with an empty device list.
   - `list_access_keys` — filters to `Active` keys, calculates age from `CreateDate`, flags anything over the threshold.
   - Walks the user's full effective policy set — inline user policies, managed policies attached to the user, and both inline and managed policies inherited from every group the user belongs to — and parses each policy document for risky `Allow` statements.
5. Aggregates results into a single report object with a summary count and full details per finding.
6. Prints the report, writes optional JSON/CSV output, and exits with status code `1` if any findings exist (`0` if clean) — so it can be used as a pass/fail gate in automation.

All API calls are **read-only** — the script never modifies IAM state.

---

## Tech Stack

- **Python 3.8+**
- **boto3** — AWS SDK for Python
- No other dependencies. No framework, no external services required to run it locally.

---

## Installation

```bash
git clone <your-repo-url>
cd iam-sentinel
pip install boto3
```

### AWS credentials

Any standard boto3 credential source works:

```bash
aws configure                     # interactive, stores in ~/.aws/credentials
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# or
python iam_audit.py --profile my-named-profile
# or run from an EC2 instance / Lambda with an attached IAM role — no keys needed
```

### Required IAM permissions (least privilege, read-only)

Attach this policy to whatever identity runs the audit:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListGroupPolicies",
        "iam:GetGroupPolicy",
        "iam:ListAttachedGroupPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Usage

```bash
# Basic scan, 90-day key age threshold, console output only
python iam_audit.py

# Custom key age threshold
python iam_audit.py --max-key-age 60

# Named profile + region + save both report formats
python iam_audit.py --profile prod --region us-west-2 --json report.json --csv report.csv
```

| Flag | Description | Default |
|---|---|---|
| `--profile` | AWS named profile to use | none (default credential chain) |
| `--region` | AWS region for the session | `us-east-1` |
| `--max-key-age` | Days before an active access key is flagged as stale | `90` |
| `--json PATH` | Save the full report as JSON | not saved |
| `--csv PATH` | Save findings as a flat CSV | not saved |

**Exit codes:** `0` = no findings, `1` = findings present (or a fatal auth error) — safe to use as a CI/CD or cron job gate.

---

## Deployment Options

**1. Local / ad-hoc**
Run it manually from your workstation before audits or after onboarding new team members.

**2. Scheduled via cron**
```bash
# Run every Monday at 8am, save a dated JSON report
0 8 * * 1 /usr/bin/python3 /opt/iam-sentinel/iam_audit.py --json /var/log/iam-audit-$(date +\%F).json
```

**3. Serverless — AWS Lambda + EventBridge (recommended for production)**
Package the script (plus boto3, which is already included in the Lambda Python runtime) into a Lambda function, trigger it on an EventBridge schedule (e.g., daily), and have it push findings to SNS, Slack, or AWS Security Hub instead of stdout. This turns the script from a manual tool into a continuous compliance control with zero infrastructure to manage.

**4. CI/CD gate**
Run it as a pipeline step against a sandbox/staging account; a non-zero exit code fails the build, catching IAM drift before it reaches production.

---

## Sample Output

```
==============================================================
  IAM SECURITY AUDIT REPORT
==============================================================
  Generated:        2026-09-04T14:02:11+00:00
  Users scanned:    12
  Key age threshold:90 days
==============================================================

  SUMMARY
  ----------------------------------------------
  Users without MFA .............. 3
  Stale access keys (90+ days) ... 2
  Overly permissive policy users . 1
  TOTAL FINDINGS .................. 6

  [!] USERS WITHOUT MFA (3)
  ----------------------------------------------
    - jsmith
    - svc-deploy
    - contractor01

  [!] STALE ACCESS KEYS (2)
  ----------------------------------------------
    - jsmith               key=AKIA...ABCD age=142d created=2026-04-15
    - svc-deploy            key=AKIA...WXYZ age=210d created=2026-02-05

  [!] OVERLY PERMISSIVE POLICIES (1)
  ----------------------------------------------
    - contractor01
        * managed:user:AdministratorAccess
==============================================================
```

---

## Project Structure

```
iam-sentinel/
├── iam_audit.py     # Main script — audit logic, checks, and report generation
└── README.md        # This file
```

---

## Design Notes

- **Read-only by design.** The tool never calls a mutating IAM API — it can be run safely against production without approval friction.
- **Group-aware permission analysis.** Most simple auditors only check policies attached directly to a user and miss permissions inherited through group membership, which is how most real-world overprivileged accounts happen. This tool walks the full effective policy set.
- **Fails loud, not silent.** A `ClientError` on an individual user (e.g., a permissions gap) is logged and skipped rather than crashing the whole scan, so one bad user doesn't block the audit of everyone else.
- **Automation-friendly exit codes** make it trivial to wire into cron, CI/CD, or Lambda without extra glue code.

## Roadmap / Possible Extensions

- [ ] Root account checks (MFA, access key existence) via `iam:GetAccountSummary`
- [ ] Password policy compliance check (`iam:GetAccountPasswordPolicy`)
- [ ] Unused credential detection via IAM credential reports (`GenerateCredentialReport`)
- [ ] Slack/SNS/email alerting on findings
- [ ] Terraform/SAM template for one-command Lambda + EventBridge deployment
- [ ] Push findings directly to AWS Security Hub as custom findings

## License

MIT — free to use, modify, and include in your own portfolio or internal tooling.
