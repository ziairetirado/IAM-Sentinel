# IAM-Sentinel
Read-only Python/boto3 tool that audits AWS IAM for missing MFA, stale access keys (90+ days), and overly permissive policies — including group-inherited permissions. Outputs clean console/JSON/CSV reports and exits non-zero on findings, making it drop-in ready for cron, CI/CD, or Lambda + EventBridge.
