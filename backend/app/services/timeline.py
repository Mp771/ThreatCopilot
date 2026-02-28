def build_timeline(events):
    timeline = []

    for e in events:
        timeline.append({
            "time": e.get("timestamp"),
            "event": e.get("event_type"),
            "ip": e.get("source_ip"),
            "mitre": e.get("mitre_technique")
        })

    timeline.sort(key=lambda x: x["time"])
    return timeline