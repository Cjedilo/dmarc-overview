#!/usr/bin/env python3
"""Cron job: parse this mail server's own Postfix/Dovecot logs for
security-relevant events and store them in Postgres (on the DB/web server).

Runs ON the mail server itself (where the logs live), and connects out to
Postgres over the network — the reverse direction of fetch_dmarc_reports.py,
which runs on the DB server and connects out to IMAP.

Re-parses the current log file plus the most recently rotated one on every
run (cheap: a few MB), relying on a hash-of-the-raw-line uniqueness
constraint per table to make re-runs a no-op for lines already stored. This
avoids fragile byte-offset/rotation-tracking state.

Covers four event categories:
  - failed IMAP/POP3 logins (Dovecot)
  - failed SMTP AUTH (Postfix smtpd/submission, credential brute-forcing)
  - rejects WE give (Postfix smtpd "reject:" lines: RBL blocks, malformed
    HELO relay probes, etc.)
  - rejects WE receive (Postfix smtp "status=bounced": our own outbound
    mail refused by someone else's server)
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import logging
import os
import re
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fetch_mail_security_events")

MAIL_LOG_DIR = Path(os.environ.get("MAIL_LOG_DIR", "/var/log"))
MAIL_LOG_BASENAME = os.environ.get("MAIL_LOG_BASENAME", "mail.log")

DB_HOST = os.environ["MAILSEC_DB_HOST"]
DB_PORT = int(os.environ.get("MAILSEC_DB_PORT", "5432"))
DB_NAME = os.environ.get("MAILSEC_DB_NAME", "dmarc")
DB_USER = os.environ.get("MAILSEC_DB_USER", "mailsec")
DB_PASSWORD = os.environ["MAILSEC_DB_PASSWORD"]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS mailsec.auth_failures (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    service TEXT NOT NULL,
    username TEXT,
    source_ip INET,
    source_host TEXT,
    method TEXT,
    detail TEXT,
    raw_line TEXT NOT NULL,
    line_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS mailsec.rejects_given (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    stage TEXT,
    source_ip INET,
    source_host TEXT,
    smtp_code TEXT,
    enhanced_code TEXT,
    reason TEXT,
    mail_from TEXT,
    rcpt_to TEXT,
    helo TEXT,
    raw_line TEXT NOT NULL,
    line_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS mailsec.rejects_received (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    queue_id TEXT,
    mail_to TEXT,
    orig_to TEXT,
    relay TEXT,
    dsn_code TEXT,
    reason TEXT,
    raw_line TEXT NOT NULL,
    line_hash TEXT NOT NULL UNIQUE
);
"""

SYSLOG_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ (?P<rest>.*)$")

DOVECOT_RE = re.compile(
    r"dovecot: (?P<login_type>imap-login|pop3-login): Disconnected: Connection closed "
    r"\(auth failed, \d+ attempts? in \d+ secs\): "
    r"user=<(?P<user>[^>]*)>, (?:method=(?P<method>\S+), )?rip=(?P<rip>[0-9a-fA-F.:]+)"
)

SMTP_AUTH_RE = re.compile(
    r"postfix/(?P<service>smtpd|submission/smtpd)\[\d+\]: warning: "
    r"(?P<client_host>\S+)\[(?P<client_ip>[0-9a-fA-F.:]+)\]: "
    r"SASL (?P<method>\S+) authentication failed(?::\s*(?P<reason>.*))?$"
)

# RCPT-stage rejects (postfix/smtpd): RBL blocks, malformed HELO relay probes, etc.
REJECT_HEAD_RE = re.compile(
    r"postfix/smtpd\[\d+\]: (?P<queue>\S+): reject: (?P<stage>\w+) from "
    r"(?P<client_host>\S+)\[(?P<client_ip>[0-9a-fA-F.:]+)\]: "
    r"(?P<smtp_code>\d+) (?P<enhanced_code>[\d.]+) (?P<reason>.*)$"
)
# Content-stage rejects (postfix/cleanup): header/body filter rules on already-queued mail.
CLEANUP_REJECT_RE = re.compile(
    r"postfix/cleanup\[\d+\]: (?P<queue>\S+): reject: (?P<stage>\w+) .* from "
    r"(?P<client_host>\S+)\[(?P<client_ip>[0-9a-fA-F.:]+)\]; "
    r".*?: (?P<smtp_code>[\d.]+) \"(?P<reason>[^\"]*)\"\s*$"
)
MAIL_FROM_RE = re.compile(r"\bfrom=<([^>]*)>")
RCPT_TO_RE = re.compile(r"\bto=<([^>]*)>")
HELO_RE = re.compile(r"\bhelo=<?([^>\s]*)>?")

BOUNCED_RE = re.compile(
    r"postfix/smtp\[\d+\]: (?P<queue>\S+): to=<(?P<to>[^>]*)>"
    r"(?:, orig_to=<(?P<orig_to>[^>]*)>)?, relay=(?P<relay>\S+), "
    r"delay=(?P<delay>[\d.]+), delays=(?P<delays>\S+), dsn=(?P<dsn>\S+), "
    r"status=bounced \((?P<reason>.*)\)$"
)


def _parse_syslog_ts(text: str, reference: datetime.datetime) -> datetime.datetime | None:
    try:
        dt = datetime.datetime.strptime(f"{reference.year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    if dt > reference + datetime.timedelta(days=1):
        dt = dt.replace(year=dt.year - 1)
    # Naive local time (raw syslog) -> attach this machine's actual local
    # tzinfo, same reasoning as fetch_dmarc_reports.py's _parse_naive_local.
    return dt.astimezone()


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()


def parse_line(ts: datetime.datetime, rest: str, raw_line: str):
    m = DOVECOT_RE.search(rest)
    if m:
        service = "imap" if m["login_type"] == "imap-login" else "pop3"
        return "auth_failures", {
            "occurred_at": ts,
            "service": service,
            "username": m["user"] or None,
            "source_ip": m["rip"],
            "source_host": None,
            "method": m["method"],
            "detail": None,
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    m = SMTP_AUTH_RE.search(rest)
    if m:
        service = "submission_auth" if m["service"] == "submission/smtpd" else "smtp_auth"
        return "auth_failures", {
            "occurred_at": ts,
            "service": service,
            "username": None,
            "source_ip": m["client_ip"],
            "source_host": m["client_host"],
            "method": m["method"],
            "detail": (m["reason"] or None),
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    m = REJECT_HEAD_RE.search(rest)
    if m:
        reason_full = m["reason"]
        mail_from = MAIL_FROM_RE.search(reason_full)
        rcpt_to = RCPT_TO_RE.search(reason_full)
        helo = HELO_RE.search(reason_full)
        reason_clean = re.split(r";\s*from=<", reason_full)[0]
        return "rejects_given", {
            "occurred_at": ts,
            "stage": m["stage"],
            "source_ip": m["client_ip"],
            "source_host": m["client_host"],
            "smtp_code": m["smtp_code"],
            "enhanced_code": m["enhanced_code"],
            "reason": reason_clean,
            "mail_from": mail_from.group(1) if mail_from else None,
            "rcpt_to": rcpt_to.group(1) if rcpt_to else None,
            "helo": helo.group(1) if helo else None,
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    m = CLEANUP_REJECT_RE.search(rest)
    if m:
        mail_from = MAIL_FROM_RE.search(rest)
        rcpt_to = RCPT_TO_RE.search(rest)
        helo = HELO_RE.search(rest)
        return "rejects_given", {
            "occurred_at": ts,
            "stage": m["stage"],
            "source_ip": m["client_ip"],
            "source_host": m["client_host"],
            "smtp_code": None,
            "enhanced_code": m["smtp_code"],
            "reason": m["reason"],
            "mail_from": mail_from.group(1) if mail_from else None,
            "rcpt_to": rcpt_to.group(1) if rcpt_to else None,
            "helo": helo.group(1) if helo else None,
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    m = BOUNCED_RE.search(rest)
    if m:
        return "rejects_received", {
            "occurred_at": ts,
            "queue_id": m["queue"],
            "mail_to": m["to"],
            "orig_to": m["orig_to"],
            "relay": m["relay"],
            "dsn_code": m["dsn"],
            "reason": m["reason"],
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    return None, None


def iter_log_lines(backfill: bool):
    files = [MAIL_LOG_DIR / MAIL_LOG_BASENAME, MAIL_LOG_DIR / f"{MAIL_LOG_BASENAME}.1"]
    if backfill:
        files += sorted(MAIL_LOG_DIR.glob(f"{MAIL_LOG_BASENAME}.*.gz"))

    for path in files:
        if not path.exists():
            continue
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", errors="replace") as f:
            yield from f


def get_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )


def ensure_schema(conn: psycopg2.extensions.connection) -> None:
    with conn.cursor() as cur:
        cur.execute(SCHEMA_SQL)
    conn.commit()


INSERT_SQL = {
    "auth_failures": """
        INSERT INTO mailsec.auth_failures
            (occurred_at, service, username, source_ip, source_host, method, detail, raw_line, line_hash)
        VALUES (%(occurred_at)s, %(service)s, %(username)s, %(source_ip)s, %(source_host)s,
                %(method)s, %(detail)s, %(raw_line)s, %(line_hash)s)
        ON CONFLICT (line_hash) DO NOTHING
    """,
    "rejects_given": """
        INSERT INTO mailsec.rejects_given
            (occurred_at, stage, source_ip, source_host, smtp_code, enhanced_code,
             reason, mail_from, rcpt_to, helo, raw_line, line_hash)
        VALUES (%(occurred_at)s, %(stage)s, %(source_ip)s, %(source_host)s, %(smtp_code)s,
                %(enhanced_code)s, %(reason)s, %(mail_from)s, %(rcpt_to)s, %(helo)s,
                %(raw_line)s, %(line_hash)s)
        ON CONFLICT (line_hash) DO NOTHING
    """,
    "rejects_received": """
        INSERT INTO mailsec.rejects_received
            (occurred_at, queue_id, mail_to, orig_to, relay, dsn_code, reason, raw_line, line_hash)
        VALUES (%(occurred_at)s, %(queue_id)s, %(mail_to)s, %(orig_to)s, %(relay)s,
                %(dsn_code)s, %(reason)s, %(raw_line)s, %(line_hash)s)
        ON CONFLICT (line_hash) DO NOTHING
    """,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Also read all rotated .gz log files (not just the current + previous one).",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    reference = datetime.datetime.now()

    counts = {"auth_failures": 0, "rejects_given": 0, "rejects_received": 0}
    skipped = 0

    conn = get_connection()
    try:
        ensure_schema(conn)
        with conn.cursor() as cur:
            for raw_line in iter_log_lines(backfill=args.backfill):
                raw_line = raw_line.rstrip("\n")
                head = SYSLOG_TS_RE.match(raw_line)
                if not head:
                    continue
                ts = _parse_syslog_ts(head["ts"], reference)
                if ts is None:
                    continue
                table, row = parse_line(ts, head["rest"], raw_line)
                if table is None:
                    continue
                cur.execute(INSERT_SQL[table], row)
                if cur.rowcount:
                    counts[table] += 1
                else:
                    skipped += 1
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Mail security log ingestion failed")
        return 1
    finally:
        conn.close()

    logger.info(
        "Done: %d auth failures, %d rejects given, %d rejects received stored "
        "(%d lines already seen, skipped)",
        counts["auth_failures"],
        counts["rejects_given"],
        counts["rejects_received"],
        skipped,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
