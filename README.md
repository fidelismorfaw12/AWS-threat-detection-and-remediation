# AWS Threat Detection & Automated Remediation

Terraform project that deploys a fully automated security pipeline on AWS.
When GuardDuty detects a high-severity threat, the system automatically blocks the attacker, isolates the affected instance, logs the finding, and alerts your team — in seconds, with no human intervention required.

---

## Architecture

```
 ┌─────────────────┐     ┌──────────────────┐     ┌──────────────────────┐
 │  Amazon         │────▶│  Amazon          │────▶│  AWS Lambda          │
 │  GuardDuty      │     │  EventBridge     │     │  (remediation.py)    │
 │                 │     │  severity >= 7   │     │                      │
 └─────────────────┘     └──────────────────┘     └──────┬───────────────┘
                                                          │
                    ┌─────────────────────────────────────┤
                    │                                     │
          ┌─────────▼──────────┐               ┌─────────▼──────────┐
          │  EC2 NACL          │               │  EC2 Instance      │
          │  DENY attacker IP  │               │  → Quarantine SG   │
          │  (subnet-wide)     │               │  (zero rules)      │
          └────────────────────┘               └────────────────────┘
                    │
       ┌────────────┴────────────┐
       │                         │
┌──────▼──────┐           ┌──────▼──────┐
│  Amazon S3  │           │  Amazon SNS │
│  Audit Log  │           │  Email Alert│
└─────────────┘           └─────────────┘
```

---

## Remediation Flow

| Step | Service | Action |
|---|---|---|
| 1 | GuardDuty | Detects suspicious activity, generates finding |
| 2 | EventBridge | Filters findings with severity ≥ 7, invokes Lambda |
| 3 | Lambda | Extracts attacker IP + instance ID from finding |
| 4 | EC2 NACL | Attacker IP denied at subnet level (all protocols) |
| 5 | EC2 SG | Instance replaced with quarantine SG if severity ≥ threshold |
| 6 | S3 | Full finding record written to `findings/YYYY/MM/DD/{id}.json` |
| 7 | SNS | Alert email sent to configured addresses |

---

## Resources Created

| Resource | Description |
|---|---|
| `aws_guardduty_detector` | GuardDuty with S3 + malware protection enabled |
| `aws_cloudwatch_event_rule` | EventBridge rule filtering severity ≥ 7 findings |
| `aws_lambda_function` | Python 3.12 remediation function |
| `aws_iam_role` + `aws_iam_role_policy` | Scoped execution role for Lambda |
| `aws_s3_bucket` | Encrypted, versioned findings audit bucket |
| `aws_sns_topic` | Alert topic with email subscriptions |
| `aws_security_group` | Quarantine SG — zero inbound/outbound rules |
| `aws_cloudwatch_log_group` | Lambda log retention |

---

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5.7
- AWS CLI configured with IAM permissions for EC2, GuardDuty, Lambda, EventBridge, S3, SNS, IAM
- An existing VPC ID to deploy the quarantine Security Group into

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/your-username/aws-threat-detection.git
cd aws-threat-detection

# 2. Edit variable values
vi terraform.tfvars

# 3. Initialise
terraform init

# 4. Preview
terraform plan

# 5. Deploy
terraform apply
```

After apply, **confirm the SNS email subscription** from the inbox of each address in `alert_emails`.

---

## File Structure

```
.
├── versions.tf          # Terraform + provider version constraints
├── provider.tf          # AWS provider + default tags
├── variables.tf         # All input variables
├── locals.tf            # Computed local values
├── guardduty.tf         # GuardDuty detector (or data source if existing)
├── eventbridge.tf       # EventBridge rule + Lambda target + permission
├── lambda.tf            # Lambda function + log group
├── iam.tf               # Execution role + scoped remediation policy
├── s3.tf                # Findings bucket + encryption + lifecycle
├── sns.tf               # Alert topic + email subscriptions
├── security_groups.tf   # Quarantine SG (zero rules)
├── outputs.tf           # All useful output values
├── terraform.tfvars     # Variable values (edit before applying)
└── lambda/
    └── remediation.py   # Python 3.12 remediation logic
```

---

## Key Variables

| Variable | Default | Description |
|---|---|---|
| `vpc_id` | — | VPC where quarantine SG is created |
| `severity_threshold` | `7.0` | Min severity to trigger instance isolation |
| `nacl_rule_number` | `1` | NACL rule number for attacker IP deny |
| `alert_emails` | `[]` | Email addresses for SNS alerts |
| `enable_guardduty` | `true` | Set `false` if GuardDuty already exists |
| `findings_retention_days` | `365` | Days before S3 findings expire |

---

## GuardDuty Severity Scale

| Score | Level | Action Taken |
|---|---|---|
| 0.1 – 3.9 | Low | No action (not captured by EventBridge rule) |
| 4.0 – 6.9 | Medium | No action (below threshold) |
| 7.0 – 8.9 | High | IP blocked + instance isolated |
| 9.0 – 10.0 | Critical | IP blocked + instance isolated |

---

## Related Posts

- [AWS Threat Detection & Automated Remediation — Part 1](https://medium.com/aws-in-plain-english/aws-threat-detection-and-automated-remediation-8df09d9dc924)

---

## License

MIT
