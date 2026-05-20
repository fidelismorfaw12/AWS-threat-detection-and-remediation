# ─────────────────────────────────────────────────────────────────────────────
# Package the Lambda source code into a zip
# ─────────────────────────────────────────────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/remediation.py"
  output_path = "${path.module}/lambda/remediation.zip"
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda Function
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_function" "remediation" {
  function_name = "${var.project_name}-remediation"
  description   = "Automated threat remediation — GuardDuty → EventBridge → Lambda"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  role    = aws_iam_role.lambda_execution.arn
  handler = "remediation.handler"
  runtime = "python3.12"
  timeout = var.lambda_timeout
  memory_size = var.lambda_memory_size

  environment {
    variables = {
      QUARANTINE_SG_ID   = aws_security_group.quarantine.id
      S3_BUCKET          = aws_s3_bucket.findings.id
      SNS_TOPIC_ARN      = aws_sns_topic.alerts.arn
      SEVERITY_THRESHOLD = tostring(var.severity_threshold)
      NACL_RULE_NUMBER   = tostring(var.nacl_rule_number)
    }
  }

  tags = local.common_tags

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch Log Group for Lambda
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-remediation"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}
