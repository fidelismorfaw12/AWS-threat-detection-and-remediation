# ─────────────────────────────────────────────────────────────────────────────
# SNS Topic — security alert notifications
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name         = "${var.project_name}-security-alerts"
  display_name = "AWS Security Alerts — ${var.project_name}"

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# SNS Topic Policy — restrict publish to Lambda and GuardDuty only
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution.arn
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# Email subscriptions — one per address in var.alert_emails
# Note: each address must confirm the subscription via email after apply
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_sns_topic_subscription" "email" {
  count = length(var.alert_emails)

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}
