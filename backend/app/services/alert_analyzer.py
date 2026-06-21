from app.services.mitre_mapper import map_alert


def explain_alert(alert):

    mitre = map_alert(
        alert["alert_type"]
    )

    return {

        "alert_type": alert["alert_type"],

        "severity": alert["severity"],

        "mitre_id": mitre["technique"],

        "mitre_name": mitre["name"],

        "tactic": mitre["tactic"],

        "summary":
        f"ThreatCopilot detected "
        f"{alert['alert_type']} "
        f"from {alert['source_ip']}.",

        "recommendation": [

            "Review the owning process",

            "Check destination reputation",

            "Investigate related network activity"

        ]
    }