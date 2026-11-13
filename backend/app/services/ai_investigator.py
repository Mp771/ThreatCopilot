def generate_summary(alert, mitre, evidence):

    return (
        f"The source IP {alert['source_ip']} generated "
        f"{evidence['connection_count']} network connections, "
        f"exceeding the configured threshold.\n\n"
        f"This activity maps to MITRE ATT&CK "
        f"{mitre['id']} ({mitre['name']}) "
        f"under the {mitre['tactic']} tactic.\n\n"
        f"The host communicated with "
        f"{evidence['unique_destinations']} unique destinations.\n\n"
        f"Recommended analyst actions include reviewing "
        f"associated processes, validating destination "
        f"reputation, and correlating related events."
    )