from app.db.postgres import get_connection


def save_alert(alert):

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO alerts
            (
                severity,
                alert_type,
                source_ip,
                destination_ip,
                description,
                connection_count,
                window_start,
                window_end
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                alert["severity"],
                alert["alert_type"],
                alert["source_ip"],
                alert.get("destination_ip"),
                alert["description"],
                alert["connection_count"],
                alert.get("window_start"),
                alert.get("window_end"),
            )
        )

        alert_id = cur.fetchone()[0]
        conn.commit()
        return alert_id

    except Exception:
        conn.rollback()
        raise

    finally:
        cur.close()
        conn.close()

def get_alert_by_id(alert_id):
    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT
                id,
                severity,
                alert_type,
                source_ip,
                description,
                created_at,
                connection_count,
                destination_ip,
                window_start,
                window_end
            FROM alerts
            WHERE id = %s
            """,
            (alert_id,)
        )

        row = cur.fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "severity": row[1],
            "alert_type": row[2],
            "source_ip": row[3],
            "description": row[4],
            "created_at": row[5],
            "connection_count": row[6],
            "destination_ip": row[7],
            "window_start": row[8],
            "window_end": row[9],
        }

    finally:
        cur.close()
        conn.close()
