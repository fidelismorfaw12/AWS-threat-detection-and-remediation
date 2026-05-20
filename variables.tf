# ─────────────────────────────────────────────
# General
# ─────────────────────────────────────────────
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix used across all resources"
  type        = string
}

variable "environment" {
  description = "Environment label"
  type        = string
  default     = "security"
}

# ─────────────────────────────────────────────
# Networking — target VPC for quarantine SG
# ─────────────────────────────────────────────
variable "vpc_id" {
  description = "VPC ID where the quarantine Security Group will be created"
  type        = string
}

# ─────────────────────────────────────────────
# GuardDuty
# ─────────────────────────────────────────────
variable "enable_guardduty" {
  description = "Whether to enable GuardDuty detector (disable if already enabled in the account)"
  type        = bool
  default     = true
}

variable "enable_s3_protection" {
  description = "Enable GuardDuty S3 data event monitoring"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty malware protection for EC2"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "Frequency of GuardDuty findings export. Valid values: FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

# ─────────────────────────────────────────────
# Remediation
# ─────────────────────────────────────────────
variable "severity_threshold" {
  description = "Minimum GuardDuty severity score (0-10) to trigger instance isolation. IP blocking always occurs."
  type        = number
  default     = 7.0
}

variable "nacl_rule_number" {
  description = "NACL rule number to use for the attacker IP deny rule (lower = higher priority)"
  type        = number
  default     = 1
}

# ─────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────
variable "alert_emails" {
  description = "List of email addresses to receive security alerts via SNS"
  type        = list(string)
  default     = []
}

# ─────────────────────────────────────────────
# Lambda
# ─────────────────────────────────────────────
variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 128
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days for Lambda logs"
  type        = number
  default     = 30
}

# ─────────────────────────────────────────────
# S3
# ─────────────────────────────────────────────
variable "findings_bucket_name" {
  description = "Override the default S3 bucket name for findings. Leave empty to auto-generate."
  type        = string
  default     = ""
}

variable "findings_retention_days" {
  description = "Days before findings in S3 are permanently deleted"
  type        = number
  default     = 365
}
