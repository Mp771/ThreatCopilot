def generate_report(events):

    ips = list(set(e["source_ip"] for e in events if e.get("source_ip")))
    mitre = list(set(e["mitre_technique"] for e in events if e.get("mitre_technique")))

    report = f"""
ThreatCopilot SOC Incident Report
----------------------------------

Total Events: {len(events)}

Source IPs:
{', '.join(ips)}

MITRE Techniques:
{', '.join(mitre)}

Recommended Actions:
• Block malicious IPs
• Enable MFA
• Monitor authentication logs
"""

    return report

