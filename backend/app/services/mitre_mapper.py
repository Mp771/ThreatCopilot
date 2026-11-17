
MITRE_MAPPING = {
    "Port Scan": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
}


UNKNOWN_MAPPING = {
    "technique": "Unknown",
    "name": "Unmapped",
    "tactic": "Unknown",
}


def map_alert(alert_type: str, evidence: dict | None = None) -> dict:
    """
    Map an alert only when its classification has sufficient
    behavioural evidence.

    High Connection Volume alone is not sufficient to establish
    a MITRE ATT&CK technique.
    """

    if alert_type == "High Connection Volume":
        return UNKNOWN_MAPPING.copy()

    mapping = MITRE_MAPPING.get(alert_type)

    if not mapping:
        return UNKNOWN_MAPPING.copy()

    return mapping.copy()
