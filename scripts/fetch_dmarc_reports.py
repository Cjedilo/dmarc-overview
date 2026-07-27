#!/usr/bin/env python3
"""Cron job: haal DMARC aggregate reports op via IMAP en sla ze op in Postgres.

Bedoeld om elk uur te draaien. Gebruikt parsedmarc om mail te lezen, bijlagen
(.gz/.zip/.xml) te decoderen en te parsen. Verwerkte mail wordt door
parsedmarc automatisch verplaatst naar {archive_folder}/Aggregate (of
.../Invalid bij een kapot rapport), zodat een volgende run nooit dezelfde
mail opnieuw ziet.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone

import psycopg2
from dotenv import load_dotenv
from mailsuite.mailbox import IMAPConnection
from parsedmarc import get_dmarc_reports_from_mailbox
from parsedmarc.types import AggregateReport, FailureReport, ParsingResults, SMTPTLSReport

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("fetch_dmarc_reports")

IMAP_HOST = os.environ["IMAP_HOST"]
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
IMAP_USER = os.environ["IMAP_USER"]
IMAP_PASSWORD = os.environ["IMAP_PASSWORD"]
IMAP_REPORTS_FOLDER = os.environ.get("IMAP_REPORTS_FOLDER", "INBOX")
IMAP_ARCHIVE_FOLDER = os.environ.get("IMAP_ARCHIVE_FOLDER", "Processed")

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "dmarc")
DB_USER = os.environ.get("DB_USER", "dmarc")
DB_PASSWORD = os.environ["DB_PASSWORD"]

# Zet op "false" zodra de server (192.168.93.11) uitgaand internet heeft en je
# reverse-DNS/land-verrijking van bron-IP's wilt; anders blijven die kolommen NULL.
DMARC_OFFLINE = os.environ.get("DMARC_OFFLINE", "true").lower() != "false"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dmarc.aggregate_reports (
    id BIGSERIAL PRIMARY KEY,
    org_name TEXT NOT NULL,
    org_email TEXT,
    org_extra_contact_info TEXT,
    report_id TEXT NOT NULL,
    date_begin TIMESTAMPTZ NOT NULL,
    date_end TIMESTAMPTZ NOT NULL,
    domain TEXT NOT NULL,
    adkim TEXT,
    aspf TEXT,
    policy_p TEXT,
    policy_sp TEXT,
    policy_pct TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_name, report_id)
);

CREATE TABLE IF NOT EXISTS dmarc.aggregate_records (
    id BIGSERIAL PRIMARY KEY,
    report_id BIGINT NOT NULL REFERENCES dmarc.aggregate_reports (id) ON DELETE CASCADE,
    source_ip INET NOT NULL,
    source_country TEXT,
    source_reverse_dns TEXT,
    count INTEGER NOT NULL,
    disposition TEXT NOT NULL,
    dkim_aligned BOOLEAN NOT NULL,
    spf_aligned BOOLEAN NOT NULL,
    dmarc_aligned BOOLEAN NOT NULL,
    policy_dkim_result TEXT,
    policy_spf_result TEXT,
    header_from TEXT,
    envelope_from TEXT,
    envelope_to TEXT,
    interval_begin TIMESTAMPTZ NOT NULL,
    interval_end TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS dmarc.aggregate_record_dkim_results (
    id BIGSERIAL PRIMARY KEY,
    record_id BIGINT NOT NULL REFERENCES dmarc.aggregate_records (id) ON DELETE CASCADE,
    domain TEXT,
    selector TEXT,
    result TEXT
);

CREATE TABLE IF NOT EXISTS dmarc.aggregate_record_spf_results (
    id BIGSERIAL PRIMARY KEY,
    record_id BIGINT NOT NULL REFERENCES dmarc.aggregate_records (id) ON DELETE CASCADE,
    domain TEXT,
    scope TEXT,
    result TEXT
);

CREATE TABLE IF NOT EXISTS dmarc.smtp_tls_reports (
    id BIGSERIAL PRIMARY KEY,
    organization_name TEXT NOT NULL,
    report_id TEXT NOT NULL,
    date_begin TIMESTAMPTZ NOT NULL,
    date_end TIMESTAMPTZ NOT NULL,
    contact_info TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_name, report_id)
);

CREATE TABLE IF NOT EXISTS dmarc.smtp_tls_policies (
    id BIGSERIAL PRIMARY KEY,
    report_id BIGINT NOT NULL REFERENCES dmarc.smtp_tls_reports (id) ON DELETE CASCADE,
    policy_domain TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    successful_session_count INTEGER NOT NULL,
    failed_session_count INTEGER NOT NULL,
    policy_strings TEXT[],
    mx_host_patterns TEXT[]
);

CREATE TABLE IF NOT EXISTS dmarc.smtp_tls_failure_details (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES dmarc.smtp_tls_policies (id) ON DELETE CASCADE,
    result_type TEXT NOT NULL,
    failed_session_count INTEGER NOT NULL,
    sending_mta_ip TEXT,
    receiving_ip TEXT,
    receiving_mx_hostname TEXT,
    receiving_mx_helo TEXT,
    additional_info_uri TEXT,
    failure_reason_code TEXT
);

-- Lichte tracker voor forensic/failure (ruf) reports: alleen technische
-- kenmerken, geen mail-inhoud/headers/derde-partij-adressen (privacygevoelig).
-- Doel is puur zichtbaar maken OF en hoe vaak deze binnenkomen.
CREATE TABLE IF NOT EXISTS dmarc.failure_reports_seen (
    id BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    arrival_date_utc TIMESTAMPTZ,
    reported_domain TEXT,
    source_ip INET,
    delivery_result TEXT,
    auth_failure TEXT[],
    authentication_mechanisms TEXT[],
    dkim_domain TEXT
);
"""


def get_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def ensure_schema(conn: psycopg2.extensions.connection) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
    conn.commit()


def _parse_naive_local(timestamp: str) -> datetime:
    # parsedmarc geeft "YYYY-MM-DD HH:MM:SS" terug in de systeem-tijdzone van
    # de machine die parsed (niet per se UTC). astimezone() zonder argument
    # plakt daar de juiste lokale tzinfo op, zodat psycopg2 het absolute
    # moment correct doorgeeft ongeacht de timezone-instelling van Postgres.
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").astimezone()


def _parse_naive_utc(timestamp: str) -> datetime:
    # arrival_date_utc is door parsedmarc al naar UTC omgerekend; de string
    # zelf draagt alleen geen tzinfo, dus hier UTC direct plakken (niet
    # astimezone() gebruiken, dat zou lokale tijd aannemen).
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def store_aggregate_report(cur, report: AggregateReport) -> None:
    metadata = report["report_metadata"]
    policy = report["policy_published"]

    cur.execute(
        """
        INSERT INTO dmarc.aggregate_reports
            (org_name, org_email, org_extra_contact_info, report_id,
             date_begin, date_end, domain, adkim, aspf,
             policy_p, policy_sp, policy_pct)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (org_name, report_id) DO NOTHING
        RETURNING id
        """,
        (
            metadata["org_name"],
            metadata["org_email"],
            metadata["org_extra_contact_info"],
            metadata["report_id"],
            _parse_naive_local(metadata["begin_date"]),
            _parse_naive_local(metadata["end_date"]),
            policy["domain"],
            policy["adkim"],
            policy["aspf"],
            policy["p"],
            policy["sp"],
            policy["pct"],
        ),
    )
    row = cur.fetchone()
    if row is None:
        logger.info(
            "Report %s van %s bestaat al, records overslaan",
            metadata["report_id"],
            metadata["org_name"],
        )
        return
    report_db_id = row[0]

    for record in report["records"]:
        source = record["source"]
        alignment = record["alignment"]
        policy_evaluated = record["policy_evaluated"]
        identifiers = record["identifiers"]

        cur.execute(
            """
            INSERT INTO dmarc.aggregate_records
                (report_id, source_ip, source_country, source_reverse_dns,
                 count, disposition, dkim_aligned, spf_aligned, dmarc_aligned,
                 policy_dkim_result, policy_spf_result,
                 header_from, envelope_from, envelope_to,
                 interval_begin, interval_end)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                report_db_id,
                source["ip_address"],
                source["country"],
                source["reverse_dns"],
                record["count"],
                policy_evaluated["disposition"],
                alignment["dkim"],
                alignment["spf"],
                alignment["dmarc"],
                policy_evaluated["dkim"],
                policy_evaluated["spf"],
                identifiers["header_from"],
                identifiers["envelope_from"],
                identifiers["envelope_to"],
                _parse_naive_local(record["interval_begin"]),
                _parse_naive_local(record["interval_end"]),
            ),
        )
        record_db_id = cur.fetchone()[0]

        for dkim_result in record["auth_results"]["dkim"]:
            cur.execute(
                """
                INSERT INTO dmarc.aggregate_record_dkim_results
                    (record_id, domain, selector, result)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    record_db_id,
                    dkim_result["domain"],
                    dkim_result["selector"],
                    dkim_result["result"],
                ),
            )

        for spf_result in record["auth_results"]["spf"]:
            cur.execute(
                """
                INSERT INTO dmarc.aggregate_record_spf_results
                    (record_id, domain, scope, result)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    record_db_id,
                    spf_result["domain"],
                    spf_result["scope"],
                    spf_result["result"],
                ),
            )


def store_smtp_tls_report(cur, report: SMTPTLSReport) -> None:
    contact_info = report["contact_info"]
    if isinstance(contact_info, list):
        contact_info = ", ".join(contact_info)

    cur.execute(
        """
        INSERT INTO dmarc.smtp_tls_reports
            (organization_name, report_id, date_begin, date_end, contact_info)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (organization_name, report_id) DO NOTHING
        RETURNING id
        """,
        (
            report["organization_name"],
            report["report_id"],
            report["begin_date"],
            report["end_date"],
            contact_info,
        ),
    )
    row = cur.fetchone()
    if row is None:
        logger.info(
            "TLS-RPT report %s van %s bestaat al, policies overslaan",
            report["report_id"],
            report["organization_name"],
        )
        return
    report_db_id = row[0]

    for policy in report["policies"]:
        cur.execute(
            """
            INSERT INTO dmarc.smtp_tls_policies
                (report_id, policy_domain, policy_type,
                 successful_session_count, failed_session_count,
                 policy_strings, mx_host_patterns)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                report_db_id,
                policy["policy_domain"],
                policy["policy_type"],
                policy["successful_session_count"],
                policy["failed_session_count"],
                policy.get("policy_strings"),
                policy.get("mx_host_patterns"),
            ),
        )
        policy_db_id = cur.fetchone()[0]

        for failure in policy.get("failure_details", []):
            cur.execute(
                """
                INSERT INTO dmarc.smtp_tls_failure_details
                    (policy_id, result_type, failed_session_count,
                     sending_mta_ip, receiving_ip, receiving_mx_hostname,
                     receiving_mx_helo, additional_info_uri, failure_reason_code)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy_db_id,
                    failure["result_type"],
                    failure["failed_session_count"],
                    failure.get("sending_mta_ip"),
                    failure.get("receiving_ip"),
                    failure.get("receiving_mx_hostname"),
                    failure.get("receiving_mx_helo"),
                    failure.get("additional_info_uri"),
                    failure.get("failure_reason_code"),
                ),
            )


def store_failure_report_summary(cur, report: FailureReport) -> None:
    source = report["source"]
    cur.execute(
        """
        INSERT INTO dmarc.failure_reports_seen
            (arrival_date_utc, reported_domain, source_ip, delivery_result,
             auth_failure, authentication_mechanisms, dkim_domain)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            _parse_naive_utc(report["arrival_date_utc"]),
            report["reported_domain"],
            source["ip_address"],
            report["delivery_result"],
            report["auth_failure"],
            report["authentication_mechanisms"],
            report["dkim_domain"],
        ),
    )


def make_save_callback(conn: psycopg2.extensions.connection):
    def save_callback(batch: ParsingResults) -> bool:
        try:
            with conn.cursor() as cur:
                for report in batch["aggregate_reports"]:
                    store_aggregate_report(cur, report)
                for report in batch["smtp_tls_reports"]:
                    store_smtp_tls_report(cur, report)
                for report in batch["failure_reports"]:
                    store_failure_report_summary(cur, report)
            conn.commit()
        except Exception:
            conn.rollback()
            logger.exception("Opslaan van batch mislukt, wordt volgende run opnieuw geprobeerd")
            return False
        if batch["aggregate_reports"]:
            logger.info("%d aggregate report(s) opgeslagen", len(batch["aggregate_reports"]))
        if batch["smtp_tls_reports"]:
            logger.info("%d TLS-RPT report(s) opgeslagen", len(batch["smtp_tls_reports"]))
        if batch["failure_reports"]:
            logger.info("%d failure report(s) gezien (alleen samenvatting bewaard)", len(batch["failure_reports"]))
        return True

    return save_callback


def main() -> int:
    conn = get_connection()
    try:
        ensure_schema(conn)

        mailbox = IMAPConnection(
            host=IMAP_HOST,
            user=IMAP_USER,
            password=IMAP_PASSWORD,
            port=IMAP_PORT,
            ssl=True,
        )

        results = get_dmarc_reports_from_mailbox(
            mailbox,
            reports_folder=IMAP_REPORTS_FOLDER,
            archive_folder=IMAP_ARCHIVE_FOLDER,
            offline=DMARC_OFFLINE,
            save_callback=make_save_callback(conn),
        )

        logger.info(
            "Run klaar: %d aggregate, %d failure, %d smtp_tls reports gezien",
            len(results["aggregate_reports"]),
            len(results["failure_reports"]),
            len(results["smtp_tls_reports"]),
        )
    except Exception:
        logger.exception("DMARC fetch run mislukt")
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
