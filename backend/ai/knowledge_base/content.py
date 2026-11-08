"""Knowledge base backing the AI Security Assistant.

Every entry follows the same shape so answers can be rendered consistently:
definition, why it matters, how to fix it, and an authoritative reference.
This is the grounding layer used when no external LLM is configured, and it is
also injected as context when one is.
"""

KNOWLEDGE_BASE = {
    # ----- Application security -----
    "sql injection": {
        "definition": "SQL Injection lets an attacker alter a database query by supplying input that is concatenated directly into SQL.",
        "impact": "Full database disclosure, authentication bypass, data tampering, and in some engines command execution on the database host.",
        "fix": "Use parameterized queries or prepared statements everywhere. Never build SQL with string concatenation, f-strings, or template literals. Apply least-privilege database accounts.",
        "reference": "OWASP A03:2021 Injection / CWE-89",
    },
    "xss": {
        "definition": "Cross-Site Scripting injects attacker-controlled script into a page that other users then execute in their browser.",
        "impact": "Session hijacking, credential theft, keylogging, and full account takeover in the victim's browser context.",
        "fix": "Encode output for its context, avoid innerHTML and dangerouslySetInnerHTML, sanitize with DOMPurify, and enforce a strict Content Security Policy.",
        "reference": "OWASP A03:2021 Injection / CWE-79",
    },
    "csrf": {
        "definition": "Cross-Site Request Forgery tricks an authenticated browser into submitting an unintended state-changing request.",
        "impact": "Attackers perform actions as the victim: transferring funds, changing an email address, or escalating permissions.",
        "fix": "Use anti-CSRF tokens on every state-changing request, set SameSite=Strict on session cookies, and verify the Origin header.",
        "reference": "OWASP A01:2021 Broken Access Control / CWE-352",
    },
    "command injection": {
        "definition": "Command Injection occurs when user input reaches a shell interpreter as part of a system command.",
        "impact": "Arbitrary command execution on the host, typically leading to full server compromise.",
        "fix": "Avoid shells entirely. Use subprocess with shell=False and an argument list, or ProcessBuilder in Java, and validate inputs against an allowlist.",
        "reference": "OWASP A03:2021 Injection / CWE-78",
    },
    "hardcoded secret": {
        "definition": "A credential, API key, or token written directly into source code or configuration committed to the repository.",
        "impact": "Anyone with repository access obtains production credentials. Git history preserves the secret even after it is deleted from the working tree.",
        "fix": "Move secrets to environment variables or a managed store such as AWS Secrets Manager. Rotate any exposed secret immediately, because deletion alone does not revoke it.",
        "reference": "CWE-798 Use of Hard-coded Credentials",
    },
    "insecure deserialization": {
        "definition": "Reconstructing objects from untrusted serialized data, allowing an attacker to control the objects that get created.",
        "impact": "Remote code execution, privilege escalation, and denial of service.",
        "fix": "Use data-only formats such as JSON with a strict schema. Never use pickle, unserialize, or BinaryFormatter on untrusted input.",
        "reference": "OWASP A08:2021 Software and Data Integrity Failures / CWE-502",
    },
    "path traversal": {
        "definition": "Path Traversal uses sequences such as ../ to escape the intended directory and reach arbitrary files.",
        "impact": "Disclosure of configuration files, credentials, and source code; in write contexts, arbitrary file overwrite.",
        "fix": "Resolve the path and confirm it stays under a fixed base directory. Prefer an allowlist of permitted filenames over user-supplied paths.",
        "reference": "OWASP A01:2021 Broken Access Control / CWE-22",
    },
    "weak hashing": {
        "definition": "Using a fast or broken hash such as MD5 or SHA-1, particularly for password storage.",
        "impact": "Passwords can be recovered at scale with rainbow tables and GPU cracking; collisions undermine integrity checks.",
        "fix": "Use bcrypt, scrypt, or Argon2id with a per-user salt for passwords, and SHA-256 or better for integrity.",
        "reference": "OWASP A02:2021 Cryptographic Failures / CWE-327",
    },
    "owasp": {
        "definition": "The OWASP Top 10 is the industry-standard awareness list of the most critical web application security risks.",
        "impact": "It provides a shared vocabulary for triage and is widely referenced in security audits and compliance reviews.",
        "fix": "Map each finding in your report to its OWASP category and remediate the highest-severity categories first.",
        "reference": "OWASP Top 10:2021",
    },

    # ----- Authentication and cryptography -----
    "mfa": {
        "definition": "Multi-Factor Authentication requires two or more independent factors: something you know, have, or are.",
        "impact": "Blocks the overwhelming majority of credential-stuffing and phishing attacks, since a stolen password alone is insufficient.",
        "fix": "Require MFA for every account, and enforce it without exception for administrative and cloud-console access.",
        "reference": "NIST SP 800-63B",
    },
    "jwt": {
        "definition": "A JSON Web Token is a signed, self-contained token carrying identity claims between a client and a server.",
        "impact": "Enables stateless authentication, but a weak signing secret or unverified signature allows complete authentication bypass.",
        "fix": "Use a long random secret, always verify the signature and algorithm, keep expiry short, and never place sensitive data in the payload since it is only base64-encoded.",
        "reference": "RFC 7519",
    },
    "bcrypt": {
        "definition": "bcrypt is an adaptive password hashing function with a tunable work factor and a built-in per-hash salt.",
        "impact": "Deliberate slowness makes large-scale offline cracking economically impractical.",
        "fix": "Use a cost factor of at least 12 and re-hash on login when the factor is raised. This platform hashes all passwords with bcrypt.",
        "reference": "OWASP Password Storage Cheat Sheet",
    },
    "encryption": {
        "definition": "Encryption converts data into ciphertext readable only with the correct key, applied both at rest and in transit.",
        "impact": "Without it, a stolen disk, intercepted request, or exposed backup discloses everything in plaintext.",
        "fix": "Enforce TLS 1.2 or higher in transit and AES-256 at rest with keys managed by a KMS and rotated regularly.",
        "reference": "OWASP A02:2021 Cryptographic Failures",
    },
    "zero trust": {
        "definition": "Zero Trust removes implicit trust based on network location and verifies every request explicitly.",
        "impact": "Limits lateral movement, so a single compromised host does not expose the rest of the environment.",
        "fix": "Authenticate and authorize every request, apply least privilege, segment the network, and assume breach.",
        "reference": "NIST SP 800-207",
    },

    # ----- Cloud and AWS -----
    "cloudtrail": {
        "definition": "AWS CloudTrail records every API call made in an account, including who made it, from where, and when.",
        "impact": "It is the primary forensic record for cloud investigations; without it an incident cannot be reconstructed.",
        "fix": "Enable CloudTrail in all regions, deliver logs to a dedicated S3 bucket with object lock, and enable log file validation.",
        "reference": "AWS CloudTrail User Guide",
    },
    "cloudwatch": {
        "definition": "Amazon CloudWatch collects metrics, logs, and alarms across AWS resources and applications.",
        "impact": "Provides the operational telemetry needed to detect anomalies and trigger automated responses.",
        "fix": "Ship application logs to CloudWatch Logs and define alarms on security-relevant metrics such as failed console logins.",
        "reference": "Amazon CloudWatch User Guide",
    },
    "guardduty": {
        "definition": "Amazon GuardDuty is a managed threat detection service that analyses CloudTrail, VPC Flow Logs, and DNS logs.",
        "impact": "Surfaces credential compromise, cryptomining, and reconnaissance without any agent deployment.",
        "fix": "Enable GuardDuty in every region and route findings to Security Hub or EventBridge for automated response.",
        "reference": "Amazon GuardDuty User Guide",
    },
    "iam": {
        "definition": "AWS Identity and Access Management controls who is authenticated and what they are authorized to do.",
        "impact": "Over-permissive IAM is the single most common cause of cloud breaches; a wildcard policy grants far more than intended.",
        "fix": "Grant least privilege with explicit actions and resource ARNs, prefer roles over long-lived access keys, and require MFA for privileged users.",
        "reference": "AWS IAM Best Practices",
    },
    "s3": {
        "definition": "Amazon S3 is an object storage service where each bucket has its own access policy.",
        "impact": "A publicly readable bucket is a frequent source of large-scale data breaches.",
        "fix": "Enable S3 Block Public Access at the account level, use private ACLs, enforce encryption, and enable versioning and access logging.",
        "reference": "AWS S3 Security Best Practices",
    },
    "ec2": {
        "definition": "Amazon EC2 provides virtual machines whose network exposure is governed by security groups.",
        "impact": "A security group allowing 0.0.0.0/0 on SSH or RDP exposes the instance to continuous internet-wide brute force.",
        "fix": "Restrict ingress to known CIDR ranges, use Systems Manager Session Manager instead of open SSH, and patch regularly.",
        "reference": "AWS EC2 Security Best Practices",
    },
    "security hub": {
        "definition": "AWS Security Hub aggregates and prioritizes security findings from AWS services and partner tools.",
        "impact": "Gives a single view of posture across accounts and measures compliance against standards such as CIS.",
        "fix": "Enable Security Hub with the CIS AWS Foundations Benchmark and remediate failed controls by severity.",
        "reference": "AWS Security Hub User Guide",
    },
    "vpc flow logs": {
        "definition": "VPC Flow Logs capture metadata about IP traffic entering and leaving network interfaces.",
        "impact": "Essential for detecting exfiltration, port scanning, and command-and-control traffic.",
        "fix": "Enable flow logs on all VPCs and retain them long enough to support incident investigation.",
        "reference": "Amazon VPC Flow Logs Documentation",
    },

    # ----- AI and detection -----
    "isolation forest": {
        "definition": "Isolation Forest is an unsupervised anomaly detector: it builds random trees that isolate points with few splits. Rare / unusual points (attacks) are isolated sooner than normal traffic, so a short path length signals an anomaly.",
        "impact": "Detects novel attacks without labelled examples — ideal for security telemetry where new attack patterns appear continuously.",
        "fix": "Train on a baseline of normal behaviour, tune contamination to the expected anomaly rate, and always pair with a confidence model (here: Random Forest) so raw anomalies are not auto-escalated.",
        "reference": "Liu, Ting & Zhou, Isolation Forest (ICDM 2008) — used in this platform's Phase 2 detector",
    },
    "random forest": {
        "definition": "Random Forest is a supervised ensemble of decision trees whose votes are averaged into a prediction.",
        "impact": "Delivers calibrated probabilities used as the confidence score, and resists overfitting better than a single tree.",
        "fix": "Train on labelled attack and benign samples, then validate with a held-out test split before deployment.",
        "reference": "Breiman, Random Forests (2001)",
    },
    "false positive": {
        "definition": "A false positive is a benign event incorrectly classified as malicious.",
        "impact": "High false positive rates cause alert fatigue, and genuine incidents get lost in the noise.",
        "fix": "This platform applies a confidence threshold: only predictions at or above 85% become incidents, and the rest are stored as observations.",
        "reference": "SOC Alert Triage Best Practices",
    },
    "user behaviour analytics": {
        "definition": "UBA builds a per-user baseline of normal activity and scores deviations from it.",
        "impact": "Catches insider threats and account takeover that signature-based detection misses entirely.",
        "fix": "Track login hour, source country, device, and data volume per user, then alert on statistically significant deviations.",
        "reference": "Gartner UEBA Market Guide",
    },
    "event correlation": {
        "definition": "Correlation links individually unremarkable events into a single attack narrative.",
        "impact": "A login, a key creation, and a large download are each ordinary; together they describe credential theft and exfiltration.",
        "fix": "Define attack chain patterns over a sliding time window and raise one incident per chain rather than one alert per event.",
        "reference": "MITRE ATT&CK Framework",
    },

    # ----- SOC operations -----
    "siem": {
        "definition": "A SIEM centralizes log collection, normalization, correlation, and alerting across an environment.",
        "impact": "Provides the detection and visibility layer of a security operations centre.",
        "fix": "Phase 2 of this platform performs the SIEM role: it collects cloud logs, normalizes them, and detects threats.",
        "reference": "Gartner SIEM Market Guide",
    },
    "soar": {
        "definition": "SOAR adds automated, playbook-driven response on top of detection.",
        "impact": "Cuts mean time to respond from hours to seconds by removing the wait for a human analyst.",
        "fix": "Phase 3 of this platform performs the SOAR role: it maps each threat to a playbook and executes the response steps automatically.",
        "reference": "Gartner SOAR Market Guide",
    },
    "digital forensics": {
        "definition": "Digital forensics preserves and analyses evidence to reconstruct what happened during an incident.",
        "impact": "Determines scope and root cause, and supports legal or regulatory proceedings.",
        "fix": "Capture evidence immediately and immutably. This platform stores forensic records and a full timeline in MongoDB for every incident.",
        "reference": "NIST SP 800-86",
    },
    "incident response": {
        "definition": "Incident response is the structured process of preparing for, detecting, containing, eradicating, and recovering from security incidents.",
        "impact": "A defined process limits damage and shortens recovery compared with improvised reaction.",
        "fix": "Follow the NIST lifecycle: preparation, detection and analysis, containment, eradication and recovery, then post-incident review.",
        "reference": "NIST SP 800-61 Rev. 2",
    },
    "mitre att&ck": {
        "definition": "MITRE ATT&CK is a curated knowledge base of real-world adversary tactics and techniques.",
        "impact": "Provides a common language for describing attacker behaviour and measuring detection coverage.",
        "fix": "Map each detected threat category to its ATT&CK technique to identify gaps in coverage.",
        "reference": "MITRE ATT&CK Enterprise Matrix",
    },

    # ----- Threat categories -----
    "credential theft": {
        "definition": "An adversary obtains valid credentials and authenticates as a legitimate user.",
        "impact": "Full account compromise with activity that looks legitimate in the logs, making it hard to spot without behavioural analysis.",
        "fix": "Lock the account, invalidate active sessions, force a password reset, and rotate every access key. Require MFA going forward.",
        "reference": "MITRE ATT&CK T1078 Valid Accounts",
    },
    "brute force": {
        "definition": "Repeated authentication attempts to guess a password or key.",
        "impact": "Account compromise when passwords are weak or reused, plus service degradation from request volume.",
        "fix": "Apply progressive account lockout, rate limiting, CAPTCHA, and MFA. Record and block the source IP.",
        "reference": "MITRE ATT&CK T1110 Brute Force",
    },
    "data exfiltration": {
        "definition": "Unauthorized transfer of data out of the environment.",
        "impact": "Regulatory breach notification obligations, contractual penalties, and lasting reputational damage.",
        "fix": "Suspend the transfer session, block the source IP, apply DLP controls, and audit what was accessed.",
        "reference": "MITRE ATT&CK T1041 Exfiltration Over C2 Channel",
    },
    "privilege escalation": {
        "definition": "An adversary gains permissions beyond those originally granted.",
        "impact": "Converts limited access into administrative control over the environment.",
        "fix": "Revoke the elevated permissions, audit all recent IAM changes, and enforce least privilege with approval workflows.",
        "reference": "MITRE ATT&CK TA0004 Privilege Escalation",
    },
    "insider threat": {
        "definition": "A threat originating from someone with legitimate authorized access.",
        "impact": "Particularly damaging because the activity is authorized and bypasses perimeter controls entirely.",
        "fix": "Apply least privilege, separation of duties, and behavioural monitoring for unusual access patterns.",
        "reference": "CISA Insider Threat Mitigation Guide",
    },
    "ddos": {
        "definition": "A Distributed Denial of Service floods a service with traffic from many sources until it becomes unavailable.",
        "impact": "Service outage and revenue loss; sometimes used as a distraction during a parallel intrusion.",
        "fix": "Use AWS Shield and rate limiting at the edge, and design for horizontal scaling under load.",
        "reference": "MITRE ATT&CK T1498 Network Denial of Service",
    },
    "reconnaissance": {
        "definition": "Information gathering about a target before an attack, such as enumerating APIs or scanning ports.",
        "impact": "Often the earliest observable signal of an attack, offering the best opportunity for early intervention.",
        "fix": "Rate-limit and monitor enumeration patterns, and alert on unusual API discovery activity.",
        "reference": "MITRE ATT&CK TA0043 Reconnaissance",
    },

    # ----- Platform concepts -----
    "phase 1": {
        "definition": "Phase 1 is the pre-deployment security assessment. It extracts the uploaded archive and runs five detectors: secrets, source code, configuration, infrastructure as code, and dependencies.",
        "impact": "It is the gate that keeps vulnerable applications out of the runtime monitoring pipeline.",
        "fix": "Reach a score of 65 or above with zero critical findings to be approved. Fix criticals first since each costs 20 points.",
        "reference": "Platform Documentation, Phase 1",
    },
    "phase 2": {
        "definition": "Phase 2 continuously monitors approved projects. It generates cloud events, normalizes them, engineers features, and runs AI threat detection with correlation.",
        "impact": "Provides runtime detection for applications that already passed static assessment.",
        "fix": "Monitoring can only start when the project is approved, so complete Phase 1 first.",
        "reference": "Platform Documentation, Phase 2",
    },
    "phase 3": {
        "definition": "Phase 3 is the automated response layer. It creates an incident, selects a playbook via the rule engine, executes simulated containment, preserves evidence, and generates a PDF report.",
        "impact": "Reduces mean time to respond and guarantees that forensic evidence is captured for every incident.",
        "fix": "Review the incident report and apply the recommended preventive measures to stop recurrence.",
        "reference": "Platform Documentation, Phase 3",
    },
    "security score": {
        "definition": "A 0-100 residual risk score. Findings subtract severity-weighted penalties with diminishing returns for duplicates, then soft saturation keeps busy scans from always collapsing to zero.",
        "impact": "It drives approval and dashboard risk visibility. Higher residual scores with manageable criticals can proceed to Phase 2 monitoring.",
        "fix": "Fix critical and high findings first, rescan, and watch the score and finding breakdown on the project report.",
        "reference": "Platform Scoring Engine",
    },
    "project category": {
        "definition": "The category selected at project creation (banking, healthcare, e-commerce, etc.) drives domain-aware analysis rather than being a display label.",
        "impact": "A hardcoded credential in a banking system is escalated in severity and weighted more heavily than the same issue in a general application.",
        "fix": "Choose the category that genuinely matches the domain so the assessment reflects its real regulatory risk.",
        "reference": "Platform Documentation, Category Intelligence",
    },
    "decision engine": {
        "definition": "The decision engine approves a project when residual risk is acceptable for continuous monitoring (score near the configured threshold with a limited critical count).",
        "impact": "Approved projects enable Phase 2 monitoring; others stay in Pending Remediation and can be fixed and rescanned.",
        "fix": "Projects that fail are never permanently rejected — remediate findings and upload again.",
        "reference": "Platform Decision Engine",
    },
    "playbook": {
        "definition": "A playbook is an ordered set of response actions bound to a specific threat category.",
        "impact": "Guarantees a consistent, auditable response instead of ad hoc reaction under pressure.",
        "fix": "Review the executed steps on the incident page. Actions are simulated and recorded, never applied to real cloud resources.",
        "reference": "Platform Playbook Engine",
    },
}

# Tab-specific starter questions surfaced by the assistant UI.
TAB_SUGGESTIONS = {
    "project": [
        "Explain my project architecture",
        "How do the three phases connect?",
        "Why do I need to choose a project category?",
        "What happens after I upload my ZIP file?",
        "Explain the project lifecycle and statuses",
        "Which technologies were detected in my project?",
    ],
    "security": [
        "Explain my security score",
        "What should I fix first?",
        "What is SQL Injection?",
        "Explain hardcoded secrets",
        "How can I improve my score above 90?",
        "What is the OWASP Top 10?",
        "Explain XSS and how to prevent it",
        "Why was my project not approved?",
    ],
    "soc": [
        "Explain how threat detection works",
        "What is Isolation Forest?",
        "Why was this threat marked Critical?",
        "Explain my recent incidents",
        "What is CloudTrail?",
        "How does event correlation work?",
        "Explain the response playbook that ran",
        "What is the difference between SIEM and SOAR?",
    ],
    "viva": [
        "Explain your project architecture and why you chose a three-phase design.",
        "Why is the security score threshold set at 65?",
        "Explain the difference between SIEM and SOAR in your project.",
        "Why did you use Isolation Forest for threat detection?",
        "How does project category influence security recommendations?",
        "Explain the hybrid rule-based and AI approach in your platform.",
        "Why simulate cloud events instead of deploying to AWS?",
        "How do Phase 1, 2, and 3 connect through the Project ID?",
        "How does your platform reduce false positives?",
        "What would you change to support real AWS integration?",
    ],
}

SUGGESTED_QUESTIONS = TAB_SUGGESTIONS["security"]
VIVA_QUESTIONS = TAB_SUGGESTIONS["viva"]

# Model answers for project review preparation. The assistant returns these
# verbatim so the developer can rehearse a defensible explanation.
VIVA_ANSWERS = {
    "three-phase": (
        "The three phases map onto the real lifecycle of an application. Phase 1 is static assessment "
        "before deployment, Phase 2 is runtime monitoring after deployment, and Phase 3 is automated "
        "response once a threat is confirmed. Separating them means each has one responsibility, they "
        "can be tested independently, and Phase 2 can be repointed at real AWS CloudTrail later without "
        "touching Phase 1 or Phase 3. All three stay connected through the Project ID and shared metadata."
    ),
    "threshold": (
        "65 is a deliberate balance. With penalties of 20 per critical, 10 per high, 5 per medium and 2 per low, "
        "a score of 65 means roughly three high-severity issues remain. That is strict enough to block genuinely "
        "insecure applications but achievable for a real project. The threshold is not used alone: the decision "
        "engine also requires zero critical findings, so a project cannot pass on score while a critical issue is open."
    ),
    "siem vs soar": (
        "SIEM is detection: it collects and correlates logs and raises alerts, which is what Phase 2 does. "
        "SOAR is response: it takes a confirmed alert and executes a playbook automatically, which is what "
        "Phase 3 does. The distinction matters because SIEM alone still needs a human analyst, whereas SOAR "
        "closes the loop and reduces mean time to respond."
    ),
    "isolation forest": (
        "Isolation Forest is unsupervised, so it does not need labelled attack data, which is exactly the "
        "constraint in security where new attack types appear continuously. It isolates anomalies with random "
        "partitioning and is efficient on high-dimensional data. It is paired with a Random Forest classifier "
        "that supplies a calibrated confidence score, so the platform gets both novelty detection and a "
        "probability it can threshold on."
    ),
    "category": (
        "The category is an input to the analysis engine, not a label. It escalates the severity of the checks "
        "that matter for that domain and increases their scoring weight. A hardcoded credential in a banking "
        "system is escalated and weighted more heavily than the same finding in a general application, because "
        "the regulatory and financial consequences differ. This makes recommendations context-aware instead of "
        "treating every application identically."
    ),
    "hybrid": (
        "Machine learning is used only where it adds value. Phase 1 is rule-based because vulnerability patterns "
        "such as hardcoded secrets and injection are deterministic and precisely expressible as rules, and "
        "training a model to recognise every vulnerability from arbitrary source code is not realistic. Phase 2 "
        "uses machine learning because runtime behaviour is statistical and anomalies cannot be enumerated in "
        "advance. This mirrors how commercial SAST and UEBA products are actually built."
    ),
    "simulate": (
        "Deploying uploaded projects to AWS would cost money, require credentials, and create real risk from "
        "running untrusted code. The Cloud Event Generator produces realistic CloudTrail-style events for approved "
        "projects, which exercises the entire detection and response pipeline locally. Because the generator sits "
        "behind a clean module boundary, swapping it for real CloudTrail ingestion changes one component and "
        "leaves the rest of the system unchanged."
    ),
    "connect": (
        "The Project ID is the join key. Phase 1 creates the project record and writes the score, status, and "
        "monitoring_enabled flag. Phase 2 loads only projects where monitoring_enabled is true and tags every log "
        "and threat with that same ID. Phase 3 creates incidents against the ID and links evidence, timeline, and "
        "reports back to it. PostgreSQL holds the relational records and MongoDB holds the documents, joined by ID."
    ),
    "false positive": (
        "Two mechanisms. First, a confidence threshold: a prediction becomes an incident only at 85% confidence or "
        "above, and anything lower is stored as an observation for review. Second, event correlation: rather than "
        "alerting on each event, the engine matches known attack chains and raises a single incident for the whole "
        "sequence, so one attack produces one alert instead of four."
    ),
    "aws integration": (
        "The Cloud Event Generator would be replaced with a collector reading real CloudTrail, CloudWatch, and "
        "GuardDuty findings, and the simulated playbook actions would call boto3 to disable IAM users or revoke "
        "security group rules. Nothing else changes: preprocessing, feature engineering, the models, correlation, "
        "the rule engine, evidence collection, and reporting all consume the same normalized log shape."
    ),
}
