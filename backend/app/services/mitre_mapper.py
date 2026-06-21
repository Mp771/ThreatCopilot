MITRE_MAPPING = {

    "High Connection Volume": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery"
    },

    "Port Scan": {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery"
    },

    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    }

}


def map_alert(alert_type):

    return MITRE_MAPPING.get(
        alert_type,
        {
            "technique": "Unknown",
            "name": "Unknown",
            "tactic": "Unknown"
        }
    )