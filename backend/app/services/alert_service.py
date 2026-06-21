from app.db.postgres import get_connection

def save_alert(alert):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO alerts
        (
            severity,
            alert_type,
            source_ip,
            description,
            connection_count
        )
        VALUES (%s,%s,%s,%s,%s)
        """,
        (
            alert["severity"],
            alert["alert_type"],
            alert["source_ip"],
            alert["description"],
            alert["connection_count"]
        )
    )

    conn.commit()

    cur.close()
    conn.close()