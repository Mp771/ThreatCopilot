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


def get_alert_by_id(alert_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            id,
            severity,
            alert_type,
            source_ip,
            description,
            created_at,
            connection_count
        FROM alerts
        WHERE id = %s
        """,
        (alert_id,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "severity": row[1],
        "alert_type": row[2],
        "source_ip": row[3],
        "description": row[4],
        "created_at": row[5],
        "connection_count": row[6]
    }