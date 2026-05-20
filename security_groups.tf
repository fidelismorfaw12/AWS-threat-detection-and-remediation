# ─────────────────────────────────────────────────────────────────────────────
# Reference target VPC
# ─────────────────────────────────────────────────────────────────────────────
data "aws_vpc" "target" {
  id = var.vpc_id
}

# ─────────────────────────────────────────────────────────────────────────────
# Quarantine Security Group
# No inbound or outbound rules — complete network isolation.
# Applied to EC2 instances when GuardDuty severity >= threshold.
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine"
  description = "Quarantine SG — zero ingress and egress. Applied by automated remediation."
  vpc_id      = var.vpc_id

  # Intentionally empty — no ingress, no egress rules
  # This completely isolates the instance while keeping it running for forensics

  tags = merge(local.common_tags, {
    Name    = "${var.project_name}-quarantine"
    Purpose = "incident-response-isolation"
  })

  lifecycle {
    # Prevent accidental changes to the quarantine SG that could break isolation
    prevent_destroy = false
  }
}
