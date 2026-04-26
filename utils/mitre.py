"""
utils/mitre.py — MITRE ATT&CK technique lookup table.

Maps tool-specific finding categories to ATT&CK technique IDs, names,
tactics, and detection notes.  Centralised here so reporters can embed
ATT&CK context without scanner modules needing to know it.

References: https://attack.mitre.org/techniques/
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Technique:
    id: str                  # e.g. "T1595"
    name: str                # e.g. "Active Scanning"
    tactic: str              # e.g. "Reconnaissance"
    url: str                 # ATT&CK permalink
    description: str         # Short description
    detection: str           # High-level detection note
    sub_id: Optional[str] = None   # e.g. "T1595.001"
    sub_name: Optional[str] = None # e.g. "Scanning IP Blocks"

    def to_dict(self) -> dict:
        return {
            "technique_id":   self.sub_id or self.id,
            "technique_name": self.sub_name or self.name,
            "tactic":         self.tactic,
            "url":            self.url,
            "description":    self.description,
            "detection":      self.detection,
        }


# ── Master technique registry ─────────────────────────────────────────────────

_TECHNIQUES: dict[str, Technique] = {

    # ── Reconnaissance ───────────────────────────────────────────────────────

    "active_scanning": Technique(
        id="T1595", name="Active Scanning", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1595/",
        description="Adversaries scan victim IP ranges to gather actionable information.",
        detection="Monitor for port scan patterns (SYN floods, sequential port requests) in network traffic.",
        sub_id="T1595.001", sub_name="Scanning IP Blocks",
    ),
    "port_scan": Technique(
        id="T1046", name="Network Service Discovery", tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
        description="Adversaries enumerate running services on hosts to identify attack surface.",
        detection="Detect rapid sequential connection attempts across multiple ports from a single source.",
    ),
    "subdomain_enum": Technique(
        id="T1590", name="Gather Victim Network Information", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1590/",
        description="Adversaries gather network information including DNS records and subdomains.",
        detection="Monitor DNS query volume per source; alert on dictionary-pattern subdomain queries.",
        sub_id="T1590.002", sub_name="DNS",
    ),
    "whois": Technique(
        id="T1591", name="Gather Victim Org Information", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1591/",
        description="Adversaries gather organisational information to prepare targeted attacks.",
        detection="WHOIS queries are passive and hard to detect; monitor for aggregated OSINT tooling.",
    ),
    "banner_grabbing": Technique(
        id="T1592", name="Gather Victim Host Information", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1592/",
        description="Adversaries gather host information including software versions via service banners.",
        detection="Alert on non-standard user agents or probe patterns against service banner endpoints.",
        sub_id="T1592.002", sub_name="Software",
    ),
    "shodan_osint": Technique(
        id="T1596", name="Search Open Technical Databases", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1596/",
        description="Adversaries query services like Shodan/Censys to discover internet-facing infrastructure.",
        detection="Passive technique — no direct detection.  Minimise internet-facing attack surface.",
        sub_id="T1596.005", sub_name="Scan Databases",
    ),

    # ── Initial Access / Web ─────────────────────────────────────────────────

    "sql_injection": Technique(
        id="T1190", name="Exploit Public-Facing Application", tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1190/",
        description="SQL injection exploits insufficient input validation to manipulate database queries.",
        detection="WAF rules for SQL keywords in parameters; anomaly detection on database error responses.",
    ),
    "xss": Technique(
        id="T1059", name="Command and Scripting Interpreter", tactic="Execution",
        url="https://attack.mitre.org/techniques/T1059/",
        description="XSS executes attacker-controlled JavaScript in victim browsers.",
        detection="CSP headers, WAF filtering of <script> and event handlers, output encoding enforcement.",
        sub_id="T1059.007", sub_name="JavaScript",
    ),
    "info_disclosure": Technique(
        id="T1592", name="Gather Victim Host Information", tactic="Reconnaissance",
        url="https://attack.mitre.org/techniques/T1592/",
        description="Exposed headers, error pages, and sensitive files leak software versions and paths.",
        detection="Audit server headers; remove X-Powered-By, Server version strings; catch-all error pages.",
    ),
    "path_traversal": Technique(
        id="T1083", name="File and Directory Discovery", tactic="Discovery",
        url="https://attack.mitre.org/techniques/T1083/",
        description="Path traversal reads arbitrary files outside the web root via ../ sequences.",
        detection="Alert on ../ patterns in URL parameters; canonicalize paths before file open calls.",
    ),

    # ── API Security ─────────────────────────────────────────────────────────

    "bola_idor": Technique(
        id="T1078", name="Valid Accounts", tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1078/",
        description="BOLA/IDOR allows accessing objects belonging to other users using valid auth tokens.",
        detection="API gateway: enforce object-level auth; log cross-user resource access; anomaly on ID sweeps.",
    ),
    "jwt_none_alg": Technique(
        id="T1550", name="Use Alternate Authentication Material", tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1550/",
        description="JWT none-algorithm bypass forges tokens without a valid signature.",
        detection="Reject tokens with alg=none; log algorithm field mismatches; use asymmetric keys.",
        sub_id="T1550.001", sub_name="Application Access Token",
    ),
    "rate_limit_bypass": Technique(
        id="T1110", name="Brute Force", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
        description="Missing rate limiting allows password spraying, credential stuffing, and enumeration.",
        detection="Track request rate per IP and account; implement exponential backoff; CAPTCHA on login.",
    ),

    # ── Active Directory ─────────────────────────────────────────────────────

    "kerberoasting": Technique(
        id="T1558", name="Steal or Forge Kerberos Tickets", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1558/",
        description="Kerberoasting requests TGS tickets for SPN-bearing accounts and cracks them offline.",
        detection="Event 4769 with encryption type 0x17 (RC4-HMAC); alert on bulk TGS requests.",
        sub_id="T1558.003", sub_name="Kerberoasting",
    ),
    "asrep_roasting": Technique(
        id="T1558", name="Steal or Forge Kerberos Tickets", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1558/",
        description="AS-REP Roasting extracts hashes from accounts with pre-auth disabled.",
        detection="Event 4768 without pre-authentication flag; monitor for accounts with DONT_REQUIRE_PREAUTH.",
        sub_id="T1558.004", sub_name="AS-REP Roasting",
    ),
    "unconstrained_delegation": Technique(
        id="T1558", name="Steal or Forge Kerberos Tickets", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1558/",
        description="Unconstrained delegation lets a service impersonate any user that authenticates to it.",
        detection="Audit UAC flag 0x80000 (TrustedForDelegation); alert on TGT writes to delegation hosts.",
    ),
    "weak_password_policy": Technique(
        id="T1110", name="Brute Force", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
        description="Weak domain password policy enables offline cracking or online brute-force attacks.",
        detection="Event 4625 burst from single source; audit Fine-Grained Password Policies via LDAP.",
    ),
    "privileged_group_abuse": Technique(
        id="T1078", name="Valid Accounts", tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1078/",
        description="Membership in Domain Admins / Enterprise Admins / Backup Operators grants excessive rights.",
        detection="Audit group membership changes (Event 4728, 4756); alert on unexpected additions.",
        sub_id="T1078.002", sub_name="Domain Accounts",
    ),
    "dangerous_acl": Technique(
        id="T1484", name="Domain Policy Modification", tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1484/",
        description="WriteDACL / GenericAll ACEs allow arbitrary privilege escalation in AD.",
        detection="BloodHound / PingCastle ACL audits; event 4670 (permissions changed on object).",
    ),

    # ── Container / DevSecOps ────────────────────────────────────────────────

    "privileged_container": Technique(
        id="T1611", name="Escape to Host", tactic="Privilege Escalation",
        url="https://attack.mitre.org/techniques/T1611/",
        description="Privileged containers share the host kernel and can escape via /proc, device access, etc.",
        detection="OPA/Gatekeeper policy denying privileged:true; Falco rule for privileged container start.",
    ),

    "container_secret_leak": Technique(
        id="T1552", name="Unsecured Credentials", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1552/",
        description="Secrets in env vars or image labels are readable by any process in the container.",
        detection="Scan image layers with Trivy/truffleHog; enforce secret manager usage (Vault, AWS SM).",
        sub_id="T1552.007", sub_name="Container API",
    ),


    # ── Phishing / Social Engineering ────────────────────────────────────────

    "phishing_campaign": Technique(
        id="T1566", name="Phishing", tactic="Initial Access",
        url="https://attack.mitre.org/techniques/T1566/",
        description="Phishing emails deliver malicious links/attachments to harvest credentials.",
        detection="Email gateway URL scanning; DMARC/DKIM/SPF enforcement; user awareness training.",
        sub_id="T1566.002", sub_name="Spearphishing Link",
    ),

    # ── Detection / Log ──────────────────────────────────────────────────────

    "event_log_clearing": Technique(
        id="T1070", name="Indicator Removal", tactic="Defense Evasion",
        url="https://attack.mitre.org/techniques/T1070/",
        description="Adversaries clear Windows event logs to remove evidence of intrusion.",
        detection="Event 1102 (audit log cleared); Event 4719 (audit policy changed); SIEM alert.",
        sub_id="T1070.001", sub_name="Clear Windows Event Logs",
    ),
    "new_service": Technique(
        id="T1543", name="Create or Modify System Process", tactic="Persistence",
        url="https://attack.mitre.org/techniques/T1543/",
        description="Adversaries install malicious services to maintain persistence across reboots.",
        detection="Event 7045 (new service installed); baseline approved service list; Sigma rule.",
        sub_id="T1543.003", sub_name="Windows Service",
    ),
    "brute_force_login": Technique(
        id="T1110", name="Brute Force", tactic="Credential Access",
        url="https://attack.mitre.org/techniques/T1110/",
        description="Repeated login attempts to guess credentials via password spraying or stuffing.",
        detection="Event 4625 burst threshold; account lockout policies; MFA enforcement.",
    ),
}


# ── Public API ─────────────────────────────────────────────────────────────────

def get(key: str) -> Optional[Technique]:
    """Return the Technique for a given category key, or None."""
    return _TECHNIQUES.get(key)


def get_dict(key: str) -> dict:
    """Return a serialisable dict for a given category key, or {}."""
    t = _TECHNIQUES.get(key)
    return t.to_dict() if t else {}


def list_all() -> List[Technique]:
    """Return all registered techniques."""
    return list(_TECHNIQUES.values())


def keys() -> List[str]:
    """Return all registered category keys."""
    return list(_TECHNIQUES.keys())
