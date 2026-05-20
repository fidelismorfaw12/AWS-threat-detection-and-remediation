# ─────────────────────────────────────────────
# General
# ─────────────────────────────────────────────
aws_region   = "us-east-1"
project_name = "myproject"
environment  = "security"

# ─────────────────────────────────────────────
# Networking
# Replace with your actual VPC ID
# ─────────────────────────────────────────────
vpc_id = "vpc-xxxxxxxxxxxxxxxxx"

# ─────────────────────────────────────────────
# GuardDuty
# Set to false if GuardDuty is already enabled
# ─────────────────────────────────────────────
enable_guardduty              = true
enable_s3_protection          = true
enable_malware_protection     = true
guardduty_finding_frequency   = "FIFTEEN_MINUTES"

# ─────────────────────────────────────────────
# Remediation thresholds
# ─────────────────────────────────────────────
severity_threshold = 7.0
nacl_rule_number   = 1

# ─────────────────────────────────────────────
# Alerts — add your email addresses
# Each address must confirm the SNS subscription
# ─────────────────────────────────────────────
alert_emails = [
  "security@yourcompany.com",
]

# ─────────────────────────────────────────────
# Lambda
# ─────────────────────────────────────────────
lambda_timeout     = 60
lambda_memory_size = 128
log_retention_days = 30

# ─────────────────────────────────────────────
# S3
# ─────────────────────────────────────────────
findings_bucket_name    = ""   # leave empty to auto-generate
findings_retention_days = 365
