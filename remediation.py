"""
AWS Threat Detection — Automated Remediation
=============================================
Triggered by EventBridge when GuardDuty raises a high-severity finding.

Actions taken:
  1. Extract attacker IP and affected EC2 instance from the finding.
  2. Block the attacker IP at the subnet NACL level.
  3. Isolate the instance with a quarantine SG if severity >= threshold.
  4. Log the full finding record to S3.
  5. Send an alert via SNS.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS clients ───────────────────────────────────────────────────────────────
ec2 = boto3.client("ec2")
s3  = boto3.client("s3")
sns = boto3.client("sns")

# ── Environment variables (injected by Terraform) ─────────────────────────────
QUARANTINE_SG_ID   = os.environ["QUARANTINE_SG_ID"]
S3_BUCKET          = os.environ["S3_BUCKET"]
SNS_TOPIC_ARN      = os.environ["SNS_TOPIC_ARN"]
SEVERITY_THRESHOLD = float(os.environ.get("SEVERITY_THRESHOLD", "7.0"))
NACL_RULE_NUMBER   = int(os.environ.get("NACL_RULE_NUMBER", "1"))


# ── Entry point ───────────────────────────────────────────────────────────────
def handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    detail       = event.get("detail", {})
    severity     = float(detail.get("severity", 0))
    finding_id   = detail.get("id", "unknown")
    finding_type = detail.get("type", "unknown")
    region       = detail.get("region", os.environ.get("AWS_REGION", "unknown"))

    attacker_ip = _extract_attacker_ip(detail)
    instance_id = _extract_instance_id(detail)

    logger.info(
        "Finding=%s | Severity=%.1f | IP=%s | Instance=%s",
        finding_type, severity, attacker_ip, instance_id,
    )

    actions_taken = []

    # ── Step 1: Block IP at NACL level ────────────────────────────────────────
    if attacker_ip:
        try:
            _block_ip_in_nacl(instance_id, attacker_ip)
            actions_taken.append(f"Blocked {attacker_ip} in subnet NACL")
        except Exception as exc:
            logger.error("NACL block failed: %s", exc)
            actions_taken.append(f"NACL block FAILED for {attacker_ip}: {exc}")

    # ── Step 2: Isolate instance if severity >= threshold ─────────────────────
    if severity >= SEVERITY_THRESHOLD and instance_id:
        try:
            _isolate_instance(instance_id)
            actions_taken.append(f"Isolated {instance_id} with quarantine SG {QUARANTINE_SG_ID}")
        except Exception as exc:
            logger.error("Instance isolation failed: %s", exc)
            actions_taken.append(f"Isolation FAILED for {instance_id}: {exc}")

    # ── Step 3: Log to S3 ─────────────────────────────────────────────────────
    try:
        _log_to_s3(finding_id, finding_type, attacker_ip, instance_id, severity, region, actions_taken)
    except Exception as exc:
        logger.error("S3 logging failed: %s", exc)

    # ── Step 4: Send SNS alert ────────────────────────────────────────────────
    try:
        _send_alert(finding_id, finding_type, attacker_ip, instance_id, severity, region, actions_taken)
    except Exception as exc:
        logger.error("SNS alert failed: %s", exc)

    return {
        "statusCode": 200,
        "body": json.dumps({"finding_id": finding_id, "actions": actions_taken}),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────
def _extract_attacker_ip(detail: dict) -> str | None:
    """Pull attacker IPv4 from GuardDuty network connection action."""
    try:
        return (
            detail
            .get("service", {})
            .get("action", {})
            .get("networkConnectionAction", {})
            .get("remoteIpDetails", {})
            .get("ipAddressV4")
        )
    except Exception:
        return None


def _extract_instance_id(detail: dict) -> str | None:
    """Pull affected EC2 instance ID from GuardDuty resource details."""
    try:
        return (
            detail
            .get("resource", {})
            .get("instanceDetails", {})
            .get("instanceId")
        )
    except Exception:
        return None


def _block_ip_in_nacl(instance_id: str | None, attacker_ip: str):
    """
    Find the NACL associated with the instance's subnet and insert
    a DENY rule for the attacker IP.
    """
    nacl_id = _get_nacl_for_instance(instance_id)
    if not nacl_id:
        logger.warning("Could not resolve NACL — skipping IP block")
        return

    try:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=NACL_RULE_NUMBER,
            Protocol="-1",          # all protocols
            RuleAction="deny",
            Egress=False,           # inbound
            CidrBlock=f"{attacker_ip}/32",
        )
        logger.info("Inserted DENY rule for %s in NACL %s", attacker_ip, nacl_id)
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NetworkAclEntryAlreadyExists":
            logger.info("DENY rule for %s already exists in NACL %s", attacker_ip, nacl_id)
        else:
            raise


def _get_nacl_for_instance(instance_id: str | None) -> str | None:
    """Resolve NACL ID from instance → subnet → NACL association."""
    if not instance_id:
        return None

    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        subnet_id = reservations[0]["Instances"][0]["SubnetId"]
    except (IndexError, KeyError, ClientError) as exc:
        logger.error("Could not get subnet for instance %s: %s", instance_id, exc)
        return None

    try:
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )["NetworkAcls"]
        return nacls[0]["NetworkAclId"] if nacls else None
    except ClientError as exc:
        logger.error("Could not get NACL for subnet %s: %s", subnet_id, exc)
        return None


def _isolate_instance(instance_id: str):
    """Replace the instance's security groups with the quarantine SG."""
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID],
    )
    logger.info("Applied quarantine SG %s to instance %s", QUARANTINE_SG_ID, instance_id)


def _log_to_s3(
    finding_id, finding_type, attacker_ip, instance_id, severity, region, actions
):
    """Write a structured JSON record to S3 for audit/forensics."""
    timestamp = datetime.now(timezone.utc).isoformat()
    date_path = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    s3_key = f"findings/{date_path}/{finding_id}.json"

    record = {
        "finding_id":    finding_id,
        "finding_type":  finding_type,
        "severity":      severity,
        "attacker_ip":   attacker_ip,
        "instance_id":   instance_id,
        "region":        region,
        "timestamp":     timestamp,
        "actions_taken": actions,
    }

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=s3_key,
        Body=json.dumps(record, indent=2),
        ContentType="application/json",
    )
    logger.info("Logged finding to s3://%s/%s", S3_BUCKET, s3_key)


def _send_alert(
    finding_id, finding_type, attacker_ip, instance_id, severity, region, actions
):
    """Publish a human-readable alert to SNS."""
    action_lines = "\n".join(f"  • {a}" for a in actions) if actions else "  • No actions taken"

    message = (
        f"🚨 AWS Security Alert — GuardDuty Automated Remediation\n"
        f"{'─' * 55}\n\n"
        f"Finding Type  : {finding_type}\n"
        f"Severity      : {severity}\n"
        f"Attacker IP   : {attacker_ip or 'N/A'}\n"
        f"Instance ID   : {instance_id or 'N/A'}\n"
        f"Region        : {region}\n"
        f"Finding ID    : {finding_id}\n\n"
        f"Actions Taken :\n{action_lines}\n\n"
        f"Timestamp     : {datetime.now(timezone.utc).isoformat()} UTC\n"
    )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[GuardDuty] Severity {severity} — {finding_type}",
        Message=message,
    )
    logger.info("SNS alert published to %s", SNS_TOPIC_ARN)
