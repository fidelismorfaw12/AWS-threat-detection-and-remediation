locals {
  common_tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }

  # Use override bucket name or auto-generate with account ID
  findings_bucket_name = var.findings_bucket_name != "" ? var.findings_bucket_name : "${var.project_name}-findings-${data.aws_caller_identity.current.account_id}"
}
