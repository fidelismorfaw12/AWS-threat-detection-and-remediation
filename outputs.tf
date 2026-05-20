# ─────────────────────────────────────────────
# GuardDuty
# ─────────────────────────────────────────────
output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = local.guardduty_detector_id
}

# ─────────────────────────────────────────────
# Lambda
# ─────────────────────────────────────────────
output "lambda_function_name" {
  description = "Name of the remediation Lambda function"
  value       = aws_lambda_function.remediation.function_name
}

output "lambda_function_arn" {
  description = "ARN of the remediation Lambda function"
  value       = aws_lambda_function.remediation.arn
}

output "lambda_log_group" {
  description = "CloudWatch log group for Lambda output"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

# ─────────────────────────────────────────────
# EventBridge
# ─────────────────────────────────────────────
output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule filtering GuardDuty findings"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

# ─────────────────────────────────────────────
# S3
# ─────────────────────────────────────────────
output "findings_bucket_name" {
  description = "Name of the S3 bucket storing finding audit records"
  value       = aws_s3_bucket.findings.id
}

output "findings_bucket_arn" {
  description = "ARN of the findings S3 bucket"
  value       = aws_s3_bucket.findings.arn
}

# ─────────────────────────────────────────────
# SNS
# ─────────────────────────────────────────────
output "sns_topic_arn" {
  description = "ARN of the SNS security alerts topic"
  value       = aws_sns_topic.alerts.arn
}

# ─────────────────────────────────────────────
# Security Groups
# ─────────────────────────────────────────────
output "quarantine_sg_id" {
  description = "ID of the quarantine Security Group applied to isolated instances"
  value       = aws_security_group.quarantine.id
}

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
output "deployment_summary" {
  description = "Quick reference of all deployed resources"
  value = {
    guardduty_detector  = local.guardduty_detector_id
    lambda_function     = aws_lambda_function.remediation.function_name
    eventbridge_rule    = aws_cloudwatch_event_rule.guardduty_findings.name
    findings_bucket     = aws_s3_bucket.findings.id
    sns_topic           = aws_sns_topic.alerts.arn
    quarantine_sg       = aws_security_group.quarantine.id
    severity_threshold  = var.severity_threshold
    region              = var.aws_region
  }
}
