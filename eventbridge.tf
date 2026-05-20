# ─────────────────────────────────────────────────────────────────────────────
# EventBridge Rule — captures GuardDuty findings with severity >= 7
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-high-severity"
  description = "Triggers remediation Lambda for GuardDuty findings with severity >= ${var.severity_threshold}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.severity_threshold] }]
    }
  })

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# EventBridge Target — invoke the remediation Lambda
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_cloudwatch_event_target" "remediation_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "${var.project_name}-remediation-lambda"
  arn       = aws_lambda_function.remediation.arn
}

# ─────────────────────────────────────────────────────────────────────────────
# Permission — allow EventBridge to invoke the Lambda
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}
