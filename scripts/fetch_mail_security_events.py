#!/usr/bin/env python3
"""Cron job: parse this mail server's own Postfix/Dovecot/rspamd logs for
security-relevant events and store them in Postgres (on the DB/web server).

Runs ON the mail server itself (where the logs live), and connects out to
Postgres over the network — the reverse direction of fetch_dmarc_reports.py,
which runs on the DB server and connects out to IMAP.

Re-parses the current log file plus the most recently rotated one on every
run (cheap: a few MB), relying on a hash-of-the-raw-line uniqueness
constraint per table to make re-runs a no-op for lines already stored. This
avoids fragile byte-offset/rotation-tracking state.

Covers six event categories:
  - failed IMAP/POP3 logins (Dovecot)
  - failed SMTP AUTH (Postfix smtpd/submission, credential brute-forcing)
  - rejects WE give (Postfix smtpd "reject:" lines: RBL blocks, malformed
    HELO relay probes, etc.)
  - rejects WE receive (Postfix smtp "status=bounced": our own outbound
    mail refused by someone else's server)
  - incoming SMTP client IPs (Postfix smtpd "client=" lines) — kept only to
    resolve the source IP for a queue-id, joined against DMARC results below
  - rspamd's per-message DMARC verdict (DMARC_* symbols in its task log line,
    /var/log/rspamd/rspamd.log; bas needs to be in group _rspamd to read it).
    All actions are set to 999 in /etc/rspamd/local.d/actions.conf, so a
    "fail" here means the message was marked, not rejected.
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
RSPAMD_LOG_DIR = Path(os.environ.get("RSPAMD_LOG_DIR", "/var/log/rspamd"))
RSPAMD_LOG_BASENAME = os.environ.get("RSPAMD_LOG_BASENAME", "rspamd.log")

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

CREATE TABLE IF NOT EXISTS mailsec.smtp_clients (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    queue_id TEXT NOT NULL,
    source_ip INET,
    source_host TEXT,
    raw_line TEXT NOT NULL,
    line_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS smtp_clients_queue_id_idx ON mailsec.smtp_clients (queue_id);

CREATE TABLE IF NOT EXISTS mailsec.dmarc_results (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    queue_id TEXT NOT NULL,
    component TEXT NOT NULL,
    scope TEXT,
    domain TEXT,
    result TEXT,
    raw_line TEXT NOT NULL,
    line_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS dmarc_results_queue_id_idx ON mailsec.dmarc_results (queue_id);
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
    r".*?: (?P<smtp_code>[\d.]+) \"?(?P<reason>.*?)\"?\s*$"
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

# Gives us the source IP for a queue-id, to join against rspamd's DMARC verdict below.
SMTPD_CLIENT_RE = re.compile(
    r"postfix/smtpd\[\d+\]: (?P<queue>\S+): client=(?P<client_host>\S+)\[(?P<client_ip>[0-9a-fA-F.:]+)\]"
)

# rspamd logs one line per scanned message, with its own (non-syslog) timestamp:
# "2026-10-21 13:53:39 #798494(normal) <e5ce44>; task; rspamd_task_write_log:
#  id: <...>, qid: <7BD582200BB>, ip: ..., (default: F (no action): [0.23/999.00]
#  [...,DMARC_POLICY_ALLOW(-0.50){breiwebshop.nl;reject;},...]), ..."
RSPAMD_TASK_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .*?rspamd_task_write_log: "
    r".*?\bqid: <(?P<queue>[^>]+)>"
)
# Options are "{domain;policy;}" on allow, "{domain : reason;policy;}" on failures.
RSPAMD_DMARC_RE = re.compile(r"\bDMARC_(?P<symbol>[A-Z_]+)\([-\d.]+\)\{(?P<options>[^}]*)\}")
RSPAMD_DMARC_RESULTS = {
    "POLICY_ALLOW": "pass",
    "POLICY_ALLOW_WITH_FAILURES": "pass",
    "POLICY_REJECT": "fail",
    "POLICY_QUARANTINE": "fail",
    "POLICY_SOFTFAIL": "fail",
    "NA": "none",
    "DNSFAIL": "temperror",
    "BAD_POLICY": "permerror",
}


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

    m = SMTPD_CLIENT_RE.search(rest)
    if m:
        return "smtp_clients", {
            "occurred_at": ts,
            "queue_id": m["queue"],
            "source_ip": m["client_ip"],
            "source_host": m["client_host"],
            "raw_line": raw_line,
            "line_hash": _line_hash(raw_line),
        }

    return None, None


def parse_rspamd_line(raw_line: str):
    m = RSPAMD_TASK_RE.match(raw_line)
    if not m:
        return None, None
    # A line can carry more than one DMARC symbol, e.g. an option-less
    # DMARC_POLICY_ALLOW_WITH_FAILURES{} next to DMARC_POLICY_ALLOW{domain;policy;}.
    symbols = list(RSPAMD_DMARC_RE.finditer(raw_line))
    if not symbols:
        return None, None
    results = [RSPAMD_DMARC_RESULTS.get(s["symbol"], s["symbol"].lower()) for s in symbols]
    with_options = next((s for s in symbols if s["options"]), symbols[0])
    options = [o for o in with_options["options"].split(";") if o]
    domain = options[0].split(" : ")[0].strip() if options else None
    return "dmarc_results", {
        # Naive local time, same as the syslog timestamps.
        "occurred_at": datetime.datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").astimezone(),
        "queue_id": m["queue"],
        "component": "dmarc",
        "scope": options[1] if len(options) > 1 else None,
        "domain": domain or None,
        "result": "fail" if "fail" in results else results[0],
        "raw_line": raw_line,
        "line_hash": _line_hash(raw_line),
    }


def iter_log_lines(log_dir: Path, basename: str, backfill: bool):
    files = [log_dir / basename, log_dir / f"{basename}.1"]
    if backfill:
        files += sorted(log_dir.glob(f"{basename}.*.gz"))

    for path in files:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            f = opener(path, "rt", errors="replace")
        except FileNotFoundError:
            continue
        except PermissionError:
            logger.warning("Cannot read %s, skipping", path)
            continue
        with f:
            yield from f


def iter_parsed(backfill: bool, reference: datetime.datetime):
    for raw_line in iter_log_lines(MAIL_LOG_DIR, MAIL_LOG_BASENAME, backfill):
        raw_line = raw_line.rstrip("\n")
        head = SYSLOG_TS_RE.match(raw_line)
        if not head:
            continue
        ts = _parse_syslog_ts(head["ts"], reference)
        if ts is None:
            continue
        yield parse_line(ts, head["rest"], raw_line)

    for raw_line in iter_log_lines(RSPAMD_LOG_DIR, RSPAMD_LOG_BASENAME, backfill):
        yield parse_rspamd_line(raw_line.rstrip("\n"))


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
    "smtp_clients": """
        INSERT INTO mailsec.smtp_clients
            (occurred_at, queue_id, source_ip, source_host, raw_line, line_hash)
        VALUES (%(occurred_at)s, %(queue_id)s, %(source_ip)s, %(source_host)s,
                %(raw_line)s, %(line_hash)s)
        ON CONFLICT (line_hash) DO NOTHING
    """,
    "dmarc_results": """
        INSERT INTO mailsec.dmarc_results
            (occurred_at, queue_id, component, scope, domain, result, raw_line, line_hash)
        VALUES (%(occurred_at)s, %(queue_id)s, %(component)s, %(scope)s, %(domain)s,
                %(result)s, %(raw_line)s, %(line_hash)s)
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

    counts = {
        "auth_failures": 0,
        "rejects_given": 0,
        "rejects_received": 0,
        "smtp_clients": 0,
        "dmarc_results": 0,
    }
    skipped = 0
    failed = 0

    conn = get_connection()
    try:
        ensure_schema(conn)
        with conn.cursor() as cur:
            for table, row in iter_parsed(args.backfill, reference):
                if table is None:
                    continue
                # One bad line (e.g. a value Postgres won't accept) must not
                # roll back the whole run: it would be re-read, and fail
                # again, on every run until the log rotates away.
                cur.execute("SAVEPOINT line")
                try:
                    cur.execute(INSERT_SQL[table], row)
                    stored = cur.rowcount
                except psycopg2.DataError:
                    cur.execute("ROLLBACK TO SAVEPOINT line")
                    logger.warning("Could not store line, skipping: %s", row["raw_line"])
                    failed += 1
                    continue
                cur.execute("RELEASE SAVEPOINT line")
                if stored:
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
        "Done: %d auth failures, %d rejects given, %d rejects received, "
        "%d smtp clients, %d dmarc results stored (%d lines already seen, skipped; %d failed)",
        counts["auth_failures"],
        counts["rejects_given"],
        counts["rejects_received"],
        counts["smtp_clients"],
        counts["dmarc_results"],
        skipped,
        failed,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
