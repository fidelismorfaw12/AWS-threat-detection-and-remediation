data "aws_caller_identity" "current" {}

# ─────────────────────────────────────────────────────────────────────────────
# S3 Bucket — stores all GuardDuty finding audit records
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "findings" {
  bucket        = local.findings_bucket_name
  force_destroy = false

  tags = local.common_tags
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning — protect audit records from accidental deletion
resource "aws_s3_bucket_versioning" "findings" {
  bucket = aws_s3_bucket.findings.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle — move old findings to cheaper storage, then expire
resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  bucket = aws_s3_bucket.findings.id

  rule {
    id     = "findings-lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = var.findings_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
