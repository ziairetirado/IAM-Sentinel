#!/usr/bin/env python3
"""
IAM Security Audit Tool
------------------------
Scans an AWS account's IAM configuration for common security risks:
  1. Users with no MFA device enabled
  2. Access keys older than a configurable age threshold (default 90 days)
  3. Overly permissive policies (wildcard Action "*" and/or Resource "*",
     attached directly to users, via groups, or via managed policies)

Outputs a clean, readable report to the console and optionally saves it
as JSON and/or CSV for record-keeping or ingestion into other tools.

Requirements:
    pip install boto3

AWS credentials/permissions needed (read-only):
    iam:ListUsers, iam:ListMFADevices, iam:ListAccessKeys,
    iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy,
    iam:ListGroupsForUser, iam:ListAttachedGroupPolicies, iam:ListGroupPolicies,
    iam:GetGroupPolicy, iam:GetPolicy, iam:GetPolicyVersion,
    iam:GenerateCredentialReport, iam:GetCredentialReport

Usage:
    python iam_audit.py                     # scan with 90-day key threshold
    python iam_audit.py --max-key-age 60     # custom threshold
    python iam_audit.py --json out.json --csv out.csv --profile myprofile
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    print("ERROR: boto3 is required. Install it with: pip install boto3")
    sys.exit(1)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def days_since(dt):
    """Return whole days elapsed since a timezone-aware datetime."""
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return (now - dt).days


def policy_doc_is_risky(doc):
    """
    Inspect a policy document dict and flag it as overly permissive if any
    statement allows Action "*" (or includes it in a list) combined with
    Resource "*" (or includes it in a list), and Effect is Allow.
    """
    if not doc:
        return False
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        has_wildcard_action = "*" in actions
        has_wildcard_resource = "*" in resources

        if has_wildcard_action and has_wildcard_resource:
            return True

        # Also flag service-level wildcards like "s3:*" combined with "*" resource,
        # or fully wildcarded actions on a broad resource set.
        broad_action = any(a == "*" or a.endswith(":*") for a in actions)
        if broad_action and has_wildcard_resource:
            return True

    return False


# --------------------------------------------------------------------------
# Core audit class
# --------------------------------------------------------------------------

class IAMAuditor:
    def __init__(self, session, max_key_age_days=90):
        self.iam = session.client("iam")
        self.max_key_age_days = max_key_age_days
        self.findings = {
            "no_mfa": [],
            "stale_access_keys": [],
            "overly_permissive": [],
        }
        self.user_count = 0

    # ---- Data collection -------------------------------------------------

    def list_all_users(self):
        users = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])
        return users

    def get_policy_document(self, policy_arn):
        """Fetch the JSON document for the current default version of a managed policy."""
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            return version["PolicyVersion"]["Document"]
        except ClientError:
            return None

    def collect_user_policy_documents(self, username):
        """
        Gather every effective policy document for a user: inline user policies,
        attached managed user policies, and (inline + attached managed) policies
        from every group the user belongs to.
        """
        documents = []

        # Inline policies directly on the user
        for policy_name in self.iam.list_user_policies(UserName=username)["PolicyNames"]:
            doc = self.iam.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
            documents.append(("inline:user:" + policy_name, doc))

        # Managed policies attached directly to the user
        for pol in self.iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]:
            doc = self.get_policy_document(pol["PolicyArn"])
            if doc:
                documents.append(("managed:user:" + pol["PolicyName"], doc))

        # Groups the user belongs to
        for group in self.iam.list_groups_for_user(UserName=username)["Groups"]:
            gname = group["GroupName"]

            for policy_name in self.iam.list_group_policies(GroupName=gname)["PolicyNames"]:
                doc = self.iam.get_group_policy(GroupName=gname, PolicyName=policy_name)["PolicyDocument"]
                documents.append((f"inline:group:{gname}:{policy_name}", doc))

            for pol in self.iam.list_attached_group_policies(GroupName=gname)["AttachedPolicies"]:
                doc = self.get_policy_document(pol["PolicyArn"])
                if doc:
                    documents.append((f"managed:group:{gname}:{pol['PolicyName']}", doc))

        return documents

    # ---- Checks ------------------------------------------------------------

    def check_mfa(self, username):
        devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
        if len(devices) == 0:
            self.findings["no_mfa"].append(username)

    def check_access_keys(self, username):
        keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] != "Active":
                continue
            age = days_since(key["CreateDate"])
            if age is not None and age >= self.max_key_age_days:
                self.findings["stale_access_keys"].append({
                    "user": username,
                    "access_key_id": key["AccessKeyId"],
                    "age_days": age,
                    "created": key["CreateDate"].strftime("%Y-%m-%d"),
                })

    def check_permissions(self, username):
        risky_sources = []
        for source, doc in self.collect_user_policy_documents(username):
            if policy_doc_is_risky(doc):
                risky_sources.append(source)
        if risky_sources:
            self.findings["overly_permissive"].append({
                "user": username,
                "risky_policies": risky_sources,
            })

    # ---- Orchestration -------------------------------------------------

    def run(self):
        users = self.list_all_users()
        self.user_count = len(users)
        for user in users:
            username = user["UserName"]
            try:
                self.check_mfa(username)
                self.check_access_keys(username)
                self.check_permissions(username)
            except ClientError as e:
                print(f"  [!] Skipped checks for {username}: {e.response['Error']['Message']}")
        return self.findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_report(findings, user_count, max_key_age_days):
    total_issues = (
        len(findings["no_mfa"])
        + len(findings["stale_access_keys"])
        + len(findings["overly_permissive"])
    )
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "users_scanned": user_count,
        "max_key_age_days": max_key_age_days,
        "summary": {
            "users_without_mfa": len(findings["no_mfa"]),
            "stale_access_keys": len(findings["stale_access_keys"]),
            "users_with_overly_permissive_policies": len(findings["overly_permissive"]),
            "total_issues": total_issues,
        },
        "details": findings,
    }
    return report


def print_console_report(report):
    line = "=" * 62
    print(f"\n{line}")
    print("  IAM SECURITY AUDIT REPORT")
    print(line)
    print(f"  Generated:        {report['generated_at']}")
    print(f"  Users scanned:    {report['users_scanned']}")
    print(f"  Key age threshold:{report['max_key_age_days']} days")
    print(line)

    s = report["summary"]
    print(f"\n  SUMMARY")
    print(f"  ----------------------------------------------")
    print(f"  Users without MFA .............. {s['users_without_mfa']}")
    print(f"  Stale access keys (90+ days) ... {s['stale_access_keys']}")
    print(f"  Overly permissive policy users . {s['users_with_overly_permissive_policies']}")
    print(f"  TOTAL FINDINGS .................. {s['total_issues']}")

    d = report["details"]

    if d["no_mfa"]:
        print(f"\n  [!] USERS WITHOUT MFA ({len(d['no_mfa'])})")
        print("  ----------------------------------------------")
        for u in d["no_mfa"]:
            print(f"    - {u}")

    if d["stale_access_keys"]:
        print(f"\n  [!] STALE ACCESS KEYS ({len(d['stale_access_keys'])})")
        print("  ----------------------------------------------")
        for k in d["stale_access_keys"]:
            print(f"    - {k['user']:<20} key={k['access_key_id']} "
                  f"age={k['age_days']}d created={k['created']}")

    if d["overly_permissive"]:
        print(f"\n  [!] OVERLY PERMISSIVE POLICIES ({len(d['overly_permissive'])})")
        print("  ----------------------------------------------")
        for p in d["overly_permissive"]:
            print(f"    - {p['user']}")
            for src in p["risky_policies"]:
                print(f"        * {src}")

    if report["summary"]["total_issues"] == 0:
        print("\n  No issues found. IAM configuration looks clean.")

    print(f"\n{line}\n")


def save_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  Saved JSON report -> {path}")


def save_csv(report, path):
    rows = []
    for u in report["details"]["no_mfa"]:
        rows.append({"finding_type": "no_mfa", "user": u, "detail": ""})
    for k in report["details"]["stale_access_keys"]:
        rows.append({
            "finding_type": "stale_access_key",
            "user": k["user"],
            "detail": f"key={k['access_key_id']}, age_days={k['age_days']}, created={k['created']}",
        })
    for p in report["details"]["overly_permissive"]:
        rows.append({
            "finding_type": "overly_permissive_policy",
            "user": p["user"],
            "detail": "; ".join(p["risky_policies"]),
        })

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["finding_type", "user", "detail"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Saved CSV report  -> {path}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Automated IAM Security Audit Tool")
    parser.add_argument("--profile", help="AWS named profile to use", default=None)
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--max-key-age", type=int, default=90,
                         help="Flag active access keys older than this many days (default: 90)")
    parser.add_argument("--json", help="Path to save JSON report", default=None)
    parser.add_argument("--csv", help="Path to save CSV report", default=None)
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        # Trigger a lightweight call early to surface credential errors up front.
        session.client("sts").get_caller_identity()
    except (NoCredentialsError, ProfileNotFound) as e:
        print(f"ERROR: AWS credentials not found or invalid ({e}).")
        print("Configure credentials via `aws configure` or set --profile.")
        sys.exit(1)
    except ClientError as e:
        print(f"ERROR: Could not authenticate with AWS: {e}")
        sys.exit(1)

    print("Scanning IAM users... this may take a moment for large accounts.")
    start = time.time()

    auditor = IAMAuditor(session, max_key_age_days=args.max_key_age)
    findings = auditor.run()
    report = build_report(findings, auditor.user_count, args.max_key_age)

    elapsed = time.time() - start
    print(f"Scan complete in {elapsed:.1f}s.")

    print_console_report(report)

    if args.json:
        save_json(report, args.json)
    if args.csv:
        save_csv(report, args.csv)

    # Non-zero exit code if issues found — useful for CI/CD gating.
    sys.exit(1 if report["summary"]["total_issues"] > 0 else 0)


if __name__ == "__main__":
    main()
