# ─────────────────────────────────────────────────────────────────────────────
# Lambda Execution Role
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_execution" {
  name        = "${var.project_name}-lambda-execution-role"
  description = "Execution role for the GuardDuty remediation Lambda function"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "LambdaAssumeRole"
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# Attach AWS managed policy for basic Lambda execution (CloudWatch Logs)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ─────────────────────────────────────────────────────────────────────────────
# Custom inline policy — scoped remediation permissions
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role_policy" "remediation_permissions" {
  name = "${var.project_name}-remediation-policy"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [

      # ── EC2 Read ──────────────────────────────────────────────────────────
      {
        Sid    = "EC2Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
        ]
        Resource = "*"
      },

      # ── NACL Remediation ─────────────────────────────────────────────────
      {
        Sid    = "NACLRemediation"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkAclEntry",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
        ]
        Resource = "*"
      },

      # ── Instance Isolation ────────────────────────────────────────────────
      {
        Sid    = "InstanceIsolation"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
        ]
        Resource = "*"
      },

      # ── S3 Audit Logging ──────────────────────────────────────────────────
      {
        Sid      = "S3FindingsWrite"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.findings.arn}/findings/*"
      },

      # ── SNS Alerting ──────────────────────────────────────────────────────
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
    ]
  })
}
