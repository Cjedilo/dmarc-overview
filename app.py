import os

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, render_template

load_dotenv()

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "dmarc")
DB_USER = os.environ.get("DB_USER", "dmarc")
DB_PASSWORD = os.environ["DB_PASSWORD"]


def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


@app.route("/")
def index():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    count(DISTINCT ar.id) AS total_reports,
                    coalesce(sum(rec.count), 0) AS total_messages,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned_messages
                FROM dmarc.aggregate_reports ar
                LEFT JOIN dmarc.aggregate_records rec ON rec.report_id = ar.id
                """
            )
            summary = cur.fetchone()

            cur.execute(
                """
                SELECT
                    ar.org_name,
                    ar.domain,
                    ar.date_begin,
                    ar.date_end,
                    coalesce(sum(rec.count), 0) AS total_count,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned_count,
                    coalesce(sum(rec.count) FILTER (WHERE rec.disposition = 'quarantine'), 0) AS quarantined_count,
                    coalesce(sum(rec.count) FILTER (WHERE rec.disposition = 'reject'), 0) AS rejected_count
                FROM dmarc.aggregate_reports ar
                LEFT JOIN dmarc.aggregate_records rec ON rec.report_id = ar.id
                GROUP BY ar.id
                ORDER BY ar.date_begin DESC
                LIMIT 100
                """
            )
            reports = cur.fetchall()
    finally:
        conn.close()

    return render_template("index.html", summary=summary, reports=reports)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
