"""Seed playbooks, IOCs, compliance controls, and sample assets if empty."""
from advanced import store


PLAYBOOKS = [
    {
        "playbook_id": "PB-BRUTE",
        "name": "Brute Force Response",
        "trigger": "Repeated ConsoleLoginFailure",
        "condition": "failed_logins >= 5 OR threat == Brute Force",
        "action": "Lock account, record source IP, notify user",
        "description": "Stops password-spray and brute-force campaigns against console logins.",
        "status": "Ready",
        "threat_types": ["Brute Force", "Brute Force Attack"],
    },
    {
        "playbook_id": "PB-MALWARE",
        "name": "Malware Isolation",
        "trigger": "Malware Activity or suspicious process",
        "condition": "severity in [High, Critical]",
        "action": "Quarantine resource, save forensic evidence",
        "description": "Isolates a host when malware or a suspicious process is confirmed.",
        "status": "Ready",
        "threat_types": ["Malware Activity"],
    },
    {
        "playbook_id": "PB-IP",
        "name": "IP Blocking",
        "trigger": "High-risk source IP or IOC match",
        "condition": "source_ip in IOC or high-risk country + no MFA",
        "action": "Block source IP at the edge (simulated)",
        "description": "Blocks a high-risk or IOC-matched source IP at the perimeter.",
        "status": "Ready",
        "threat_types": ["Suspicious Login", "Data Exfiltration"],
    },
    {
        "playbook_id": "PB-USER",
        "name": "User Disable",
        "trigger": "Credential theft or insider threat",
        "condition": "threat in [Credential Theft, Insider Threat]",
        "action": "Disable user, revoke sessions, force password reset",
        "description": "Disables a compromised identity and forces credential rotation.",
        "status": "Ready",
        "threat_types": ["Credential Theft", "Insider Threat"],
    },
    {
        "playbook_id": "PB-EMAIL",
        "name": "Email Notification",
        "trigger": "Any Phase 3 incident",
        "condition": "incident created",
        "action": "Notify project owner and SOC analyst",
        "description": "Sends an incident notification to the project owner and SOC inbox.",
        "status": "Ready",
        "threat_types": ["*"],
    },
]

IOCS = [
    {"ioc_id": "IOC-0001", "type": "ip", "value": "185.220.101.1", "threat_type": "Tor / anonymizer",
     "severity": "High", "mitre": "T1090", "capec": "CAPEC-117",
     "description": "Known exit-node range used for credential stuffing.",
     "recommended_action": "Block inbound auth from this range and require MFA."},
    {"ioc_id": "IOC-0002", "type": "ip", "value": "45.155.205.233", "threat_type": "C2 beacon",
     "severity": "Critical", "mitre": "T1071", "capec": "CAPEC-594",
     "description": "Command-and-control IP observed in exfiltration campaigns.",
     "recommended_action": "Block egress and isolate any host that contacted it."},
    {"ioc_id": "IOC-0003", "type": "domain", "value": "update-service-cdn.net", "threat_type": "Phishing",
     "severity": "High", "mitre": "T1566", "capec": "CAPEC-98",
     "description": "Lookalike software-update domain used for payload delivery.",
     "recommended_action": "Sinkhole the domain and reset credentials of click-through users."},
    {"ioc_id": "IOC-0004", "type": "domain", "value": "secure-login-reset.com", "threat_type": "Credential theft",
     "severity": "Critical", "mitre": "T1556", "capec": "CAPEC-151",
     "description": "Fake SSO portal collecting passwords.",
     "recommended_action": "Force password reset and revoke sessions."},
    {"ioc_id": "IOC-0005", "type": "cve", "value": "CVE-2021-44228", "threat_type": "RCE (Log4Shell)",
     "severity": "Critical", "mitre": "T1190", "capec": "CAPEC-242",
     "description": "Remote code execution in Apache Log4j 2.",
     "recommended_action": "Upgrade Log4j to 2.17+ and scan for JNDI payloads."},
    {"ioc_id": "IOC-0006", "type": "cve", "value": "CVE-2023-46604", "threat_type": "RCE (ActiveMQ)",
     "severity": "Critical", "mitre": "T1190", "capec": "CAPEC-242",
     "description": "Apache ActiveMQ OpenWire deserialization RCE.",
     "recommended_action": "Patch broker and restrict OpenWire to trusted networks."},
    {"ioc_id": "IOC-0007", "type": "ip", "value": "91.240.118.172", "threat_type": "Brute force",
     "severity": "Medium", "mitre": "T1110", "capec": "CAPEC-49",
     "description": "Password-spray source targeting cloud consoles.",
     "recommended_action": "Enable lockout and CAPTCHA; block the IP."},
    {"ioc_id": "IOC-0008", "type": "domain", "value": "cdn-analytics-stats.io", "threat_type": "Malware CDN",
     "severity": "High", "mitre": "T1105", "capec": "CAPEC-186",
     "description": "Secondary payload host used after phishing.",
     "recommended_action": "Block domain and hunt for related hashes."},
]

COMPLIANCE = [
    {"control_id": "ISO-A.9.4", "framework": "ISO 27001", "title": "Access control",
     "description": "Privileged access is limited and reviewed.", "maps_to": "iam"},
    {"control_id": "ISO-A.12.6", "framework": "ISO 27001", "title": "Technical vulnerability management",
     "description": "Vulnerabilities are identified and remediated.", "maps_to": "vuln"},
    {"control_id": "ISO-A.16.1", "framework": "ISO 27001", "title": "Incident management",
     "description": "Security incidents are reported and handled.", "maps_to": "incident"},
    {"control_id": "NIST-ID.RA", "framework": "NIST CSF", "title": "Risk assessment",
     "description": "Cyber risk is identified and prioritized.", "maps_to": "score"},
    {"control_id": "NIST-PR.AC", "framework": "NIST CSF", "title": "Identity management",
     "description": "Identities and credentials are managed.", "maps_to": "iam"},
    {"control_id": "NIST-DE.CM", "framework": "NIST CSF", "title": "Security continuous monitoring",
     "description": "The environment is monitored for anomalies.", "maps_to": "monitor"},
    {"control_id": "NIST-RS.RP", "framework": "NIST CSF", "title": "Response planning",
     "description": "Response processes are executed during an event.", "maps_to": "incident"},
    {"control_id": "CIS-4", "framework": "CIS Controls", "title": "Secure configuration",
     "description": "Secure configurations are maintained.", "maps_to": "config"},
    {"control_id": "CIS-7", "framework": "CIS Controls", "title": "Continuous vulnerability management",
     "description": "Vulnerabilities are assessed and remediated.", "maps_to": "vuln"},
    {"control_id": "CIS-8", "framework": "CIS Controls", "title": "Audit log management",
     "description": "Audit logs are collected and reviewed.", "maps_to": "monitor"},
    {"control_id": "GDPR-32", "framework": "GDPR", "title": "Security of processing",
     "description": "Appropriate technical measures protect personal data.", "maps_to": "secret"},
    {"control_id": "GDPR-33", "framework": "GDPR", "title": "Breach notification",
     "description": "Personal-data breaches are documented and notified.", "maps_to": "incident"},
    {"control_id": "HIPAA-164.312", "framework": "HIPAA", "title": "Technical safeguards",
     "description": "Access control, audit, integrity, and transmission security.", "maps_to": "secret"},
    {"control_id": "HIPAA-164.308", "framework": "HIPAA", "title": "Security management process",
     "description": "Risk analysis and incident procedures are in place.", "maps_to": "score"},
]


def ensure_playbooks() -> None:
    store.ensure_collections()
    for item in PLAYBOOKS:
        existing = store.find_one("playbooks", {"playbook_id": item["playbook_id"]})
        if existing:
            continue
        store.insert("playbooks", item)


def seed_if_empty() -> None:
    store.ensure_collections()
    ensure_playbooks()
    if store.count("ioc_database") == 0:
        for item in IOCS:
            store.insert("ioc_database", item)
    if store.count("compliance_reports") == 0:
        store.insert("compliance_reports", {
            "report_id": "COMP-SEED",
            "frameworks": [c["framework"] for c in COMPLIANCE],
            "controls": COMPLIANCE,
            "note": "Control catalog. Live pass/fail is computed from Phase 1–3 data.",
        })
