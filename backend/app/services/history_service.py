import json
from app.db.postgres import get_connection


def save_investigation(query, summary, events):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO investigations (query, summary, events)
        VALUES (%s, %s, %s)
        """,
        (query, summary, json.dumps(events))
    )

    conn.commit()
    cur.close()
    conn.close()


def get_investigations(limit=20):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, query, summary, created_at
        FROM investigations
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,)
    )

    rows = cur.fetchall()

    cur.close()
    conn.close()

    investigations = []

    for r in rows:
        investigations.append({
            "id": r[0],
            "query": r[1],
            "summary": r[2],
            "created_at": r[3]
        })

    return investigations


def get_investigation_by_id(investigation_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT query, summary, events
        FROM investigations
        WHERE id = %s
        """,
        (investigation_id,)
    )

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return None

    return {
        "query": row[0],
        "summary": row[1],
        "events": row[2]
    }