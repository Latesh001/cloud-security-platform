"""Infrastructure as Code analysis: Terraform, CloudFormation, Docker, Kubernetes."""
import re
from typing import Dict, List

from phase1.detectors.base import (
    build_finding, deduplicate, iter_files, read_lines, scan_lines,
)

DETECTOR_NAME = "Infrastructure"

IAC_EXTENSIONS = [".tf", ".tfvars", ".hcl"]
IAC_FILENAMES = [
    "dockerfile", "dockerfile.prod", "dockerfile.dev",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "template.yaml", "template.yml", "cloudformation.yaml", "cloudformation.json",
    "serverless.yml", "deployment.yaml", "deployment.yml", "service.yaml",
    "pod.yaml", "statefulset.yaml", "daemonset.yaml", "ingress.yaml",
]
IAC_NAME_HINTS = ["terraform", "cloudformation", "k8s", "kubernetes", "helm"]

NETWORK_RULES = [
    (r"(?i)cidr_blocks?\s*=\s*\[[^\]]*[\"']0\.0\.0\.0/0[\"']", "Public SSH Access", "Critical",
     "Restrict the security group ingress CIDR to known administrative IP ranges or use AWS Systems Manager Session Manager."),
    (r"(?i)CidrIp\s*:\s*[\"']?0\.0\.0\.0/0", "Public SSH Access", "Critical",
     "Restrict the CloudFormation security group ingress to specific IP ranges."),
    (r"(?i)source_ranges\s*=\s*\[[^\]]*[\"']0\.0\.0\.0/0[\"']", "Public SSH Access", "Critical",
     "Restrict the firewall source ranges to trusted networks."),
    (r"(?i)ipv6_cidr_blocks?\s*=\s*\[[^\]]*[\"']::/0[\"']", "Public SSH Access", "Critical",
     "Restrict IPv6 ingress instead of allowing the entire internet."),
]

STORAGE_RULES = [
    (r"(?i)acl\s*[:=]\s*[\"']public-read(?:-write)?[\"']", "Public S3 Bucket", "Critical",
     "Set the bucket ACL to private and enable S3 Block Public Access at the account level."),
    (r"(?i)block_public_acls\s*=\s*false", "Public S3 Bucket", "Critical",
     "Set block_public_acls to true so public ACLs cannot be applied."),
    (r"(?i)restrict_public_buckets\s*=\s*false", "Public S3 Bucket", "High",
     "Enable restrict_public_buckets to block public bucket policies."),
    (r"(?i)publicly_accessible\s*=\s*true", "Public Database", "Critical",
     "Place the database in a private subnet and disable public accessibility."),
    (r"(?i)PubliclyAccessible\s*:\s*[\"']?true", "Public Database", "Critical",
     "Place the database in a private subnet and disable public accessibility."),
]

ENCRYPTION_RULES = [
    (r"(?i)(?:encrypted|storage_encrypted|encryption_enabled)\s*[:=]\s*false",
     "Missing Encryption", "High",
     "Enable encryption at rest using a customer-managed KMS key."),
    (r"(?i)Encrypted\s*:\s*[\"']?false", "Missing Encryption", "High",
     "Enable encryption at rest for the resource."),
    (r"(?i)(?:enable_key_rotation)\s*=\s*false", "Missing Encryption", "Medium",
     "Enable automatic KMS key rotation."),
]

LOGGING_RULES = [
    (r"(?i)(?:enable_logging|logging_enabled|access_logs?\s*\{?\s*enabled)\s*[:=]\s*false",
     "Logging Disabled", "Medium",
     "Enable access logging so security events can be audited after an incident."),
]

CONTAINER_RULES = [
    (r"(?i)^\s*USER\s+root\s*$", "Container Runs As Root", "High",
     "Create an unprivileged user in the Dockerfile and switch to it with USER before the entrypoint."),
    (r"(?i)privileged\s*:\s*true", "Privileged Container", "Critical",
     "Remove privileged mode; grant only the specific Linux capabilities the container needs."),
    (r"(?i)allowPrivilegeEscalation\s*:\s*true", "Privileged Container", "High",
     "Set allowPrivilegeEscalation to false in the pod security context."),
    (r"(?i)hostNetwork\s*:\s*true", "Privileged Container", "High",
     "Avoid host networking so the container cannot access the node network namespace."),
    (r"(?i)^\s*FROM\s+\S+:latest\s*$", "Unpinned Base Image", "Medium",
     "Pin the base image to an immutable digest or explicit version tag for reproducible builds."),
    (r"(?i)runAsNonRoot\s*:\s*false", "Container Runs As Root", "High",
     "Set runAsNonRoot to true in the pod security context."),
]

IAC_RULES = NETWORK_RULES + STORAGE_RULES + ENCRYPTION_RULES + LOGGING_RULES + CONTAINER_RULES

# IAM wildcards must be matched structurally. A bare `*` appears in comments,
# glob patterns, and arithmetic, so only wildcards bound to an IAM Action,
# Resource, or Principal field are reported.
IAM_WILDCARD_RULES = [
    (re.compile(r"(?i)[\"']?(?:Action|Resource|Principal)[\"']?\s*[:=]\s*\[?\s*[\"']\*[\"']"),
     "Excessive IAM Permissions", "High",
     "Replace the wildcard with the specific actions and resource ARNs the role requires."),
    (re.compile(r"(?i)[\"']?Action[\"']?\s*[:=]\s*\[?\s*[\"'][a-z0-9]+:\*[\"']"),
     "Excessive IAM Permissions", "High",
     "Grant individual API actions instead of an entire service wildcard such as s3:*."),
    (re.compile(r"(?i)[\"']?Effect[\"']?\s*[:=]\s*[\"']Allow[\"'].*[\"']?Resource[\"']?\s*[:=]\s*[\"']\*[\"']"),
     "Excessive IAM Permissions", "High",
     "Scope the policy statement to explicit resource ARNs."),
    (re.compile(r"(?i)\"AWS\"\s*:\s*\"\*\""), "Excessive IAM Permissions", "Critical",
     "A wildcard principal allows any AWS account to assume this role. Name the trusted accounts explicitly."),
]

POLICY_EXTENSIONS = [".tf", ".json", ".yaml", ".yml", ".hcl", ".template"]
POLICY_KEYWORDS = re.compile(r"(?i)(iam|policy|role|assume|statement|principal|trust)")


class InfrastructureAnalyzer:
    """Detects cloud and container misconfigurations in Infrastructure as Code."""

    @staticmethod
    def analyze_directory(root_path: str, category: str = "General Software") -> List[Dict]:
        findings: List[Dict] = []

        for abs_path, rel_path in iter_files(
            root_path,
            extensions=IAC_EXTENSIONS + [".yml", ".yaml"],
            filenames=IAC_FILENAMES,
            filename_contains=IAC_NAME_HINTS,
        ):
            lines = read_lines(abs_path)
            if not lines:
                continue
            findings.extend(scan_lines(lines, IAC_RULES, rel_path, DETECTOR_NAME, category))

        findings.extend(InfrastructureAnalyzer._scan_iam_policies(root_path, category))
        return deduplicate(findings)

    @staticmethod
    def _scan_iam_policies(root_path: str, category: str) -> List[Dict]:
        """Check IAM policy documents for wildcard grants.

        Only files whose content references IAM concepts are inspected, so a
        wildcard inside unrelated JSON or YAML is not misreported.
        """
        findings: List[Dict] = []
        for abs_path, rel_path in iter_files(
            root_path,
            filenames=["template.yaml", "template.yml", "cloudformation.yaml", "cloudformation.json"],
            filename_contains=["iam", "policy", "role", "trust"],
        ):
            lines = read_lines(abs_path)
            if not lines:
                continue
            head = "\n".join(lines[:400])
            if not POLICY_KEYWORDS.search(head):
                continue

            for line_no, line in enumerate(lines, 1):
                if not line.strip() or len(line) > 1000:
                    continue
                for regex, problem, severity, solution in IAM_WILDCARD_RULES:
                    if regex.search(line):
                        findings.append(build_finding(rel_path, line_no, problem, severity,
                                                      DETECTOR_NAME, solution, line, category))
                        break
        return findings
