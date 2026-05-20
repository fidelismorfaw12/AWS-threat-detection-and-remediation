# ─────────────────────────────────────────────────────────────────────────────
# GuardDuty Detector
# Set enable_guardduty = false if GuardDuty is already active in your account
# to avoid conflicts with the existing detector.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }

    kubernetes {
      audit_logs {
        enable = false
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = local.common_tags
}

# ─────────────────────────────────────────────────────────────────────────────
# Data source: reference existing detector when enable_guardduty = false
# ─────────────────────────────────────────────────────────────────────────────
data "aws_guardduty_detector" "existing" {
  count = var.enable_guardduty ? 0 : 1
}

locals {
  guardduty_detector_id = var.enable_guardduty ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
}
