
from app.services.mitre_mapper import map_alert


def explain_alert(alert):

    mitre = map_alert(
        alert["alert_type"],
        alert.get("evidence"),
    )

    if mitre["technique"] == "Unknown":
        summary = (
            f"ThreatCopilot detected {alert['alert_type']} "
            f"from {alert['source_ip']}. "
            "The available evidence is insufficient to assign "
            "a specific MITRE ATT&CK technique."
        )
    else:
        summary = (
            f"ThreatCopilot detected {alert['alert_type']} "
            f"from {alert['source_ip']}. "
            f"The activity is classified as "
            f"{mitre['technique']} ({mitre['name']}) "
            f"under the {mitre['tactic']} tactic."
        )

    return {
        "alert_type": alert["alert_type"],
        "severity": alert["severity"],
        "mitre_id": mitre["technique"],
        "mitre_name": mitre["name"],
        "tactic": mitre["tactic"],
        "summary": summary,
        "recommendation": [
            "Review the owning process if process attribution is available.",
            "Check destination reputation.",
            "Investigate related network activity.",
        ],
    }
