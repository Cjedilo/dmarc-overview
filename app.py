import datetime
import math
import os

import dns.exception
import dns.resolver
import dns.reversename
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, render_template, request

load_dotenv()

TREND_PLOT_HEIGHT_PX = 200

AUTH_SERVICE_LABELS = {
    "imap": "IMAP",
    "pop3": "POP3",
    "smtp_auth": "SMTP",
    "submission_auth": "Submission",
}

app = Flask(__name__)


class PrefixMiddleware:
    """Makes url_for() emit /dmarc/... links when Apache reverse-proxies this
    app under that subpath. Apache sends X-Forwarded-Prefix: /dmarc (see the
    vhost config); without this, every internal link would resolve against
    the domain root and 404, since Flask has no idea it isn't mounted at /.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        prefix = environ.get("HTTP_X_FORWARDED_PREFIX", "")
        if prefix:
            environ["SCRIPT_NAME"] = prefix
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith(prefix):
                environ["PATH_INFO"] = path_info[len(prefix):]
        return self.wsgi_app(environ, start_response)


app.wsgi_app = PrefixMiddleware(app.wsgi_app)

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "dmarc")
DB_USER = os.environ.get("DB_USER", "dmarc")
DB_PASSWORD = os.environ["DB_PASSWORD"]

MAILSEC_DB_HOST = os.environ.get("MAILSEC_DB_HOST", "localhost")
MAILSEC_DB_PORT = int(os.environ.get("MAILSEC_DB_PORT", "5432"))
MAILSEC_DB_NAME = os.environ.get("MAILSEC_DB_NAME", "dmarc")
MAILSEC_DB_USER = os.environ.get("MAILSEC_DB_USER", "mailsec")
MAILSEC_DB_PASSWORD = os.environ["MAILSEC_DB_PASSWORD"]

MONITORED_DOMAIN = os.environ.get("MONITORED_DOMAIN", "appelo.nl")


def _txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


def _parse_tags(record):
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def get_domain_status(domain):
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted((r.preference, str(r.exchange).rstrip(".")) for r in mx_answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        mx_records = []

    spf_records = [r for r in _txt_records(domain) if r.lower().startswith("v=spf1")]

    dmarc_records = _txt_records(f"_dmarc.{domain}")
    dmarc_tags = _parse_tags(dmarc_records[0]) if dmarc_records else None

    tlsrpt_records = _txt_records(f"_smtp._tls.{domain}")

    return {
        "domain": domain,
        "mx_records": mx_records,
        "spf_record": spf_records[0] if spf_records else None,
        "dmarc_record": dmarc_records[0] if dmarc_records else None,
        "dmarc_tags": dmarc_tags,
        "tlsrpt_record": tlsrpt_records[0] if tlsrpt_records else None,
    }


def get_seen_dkim_selectors(cur, domain):
    # DKIM records live at {selector}._domainkey.{domain}, but the selector name
    # is chosen freely and can't be looked up directly. The only place we see it
    # is in the aggregate reports already received — but note: whoever sends that
    # report (or the message itself) can put anything there, so this is a list of
    # *candidates*, not confirmed appelo.nl settings.
    cur.execute(
        """
        SELECT DISTINCT selector
        FROM dmarc.aggregate_record_dkim_results
        WHERE domain = %s AND selector IS NOT NULL
        ORDER BY selector
        """,
        (domain,),
    )
    return [row["selector"] for row in cur.fetchall()]


def get_confirmed_dkim_records(domain, selectors):
    # Only selectors that *currently* have a real record in DNS are a confirmed
    # setting of appelo.nl's own. A selector that no longer resolves could just as
    # well have been a made-up claim by a spoofer (see aggregate_record_dkim_results)
    # — that doesn't belong under "settings".
    confirmed = []
    for selector in selectors:
        records = _txt_records(f"{selector}._domainkey.{domain}")
        if records:
            confirmed.append(
                {"selector": selector, "record": records[0], "tags": _parse_tags(records[0])}
            )
    return confirmed


def _spf_all_qualifier(spf_record):
    for token in spf_record.split():
        if token.lower().endswith("all"):
            return token[:-3] or "+"
    return None


def build_plain_summary(status):
    lines = []

    if status["mx_records"]:
        hosts = ", ".join(host for _, host in status["mx_records"])
        lines.append(f"Incoming mail for {status['domain']} is delivered to: {hosts}.")
    else:
        lines.append("No MX record found — this domain cannot receive mail.")

    if status["spf_record"]:
        qualifier = _spf_all_qualifier(status["spf_record"])
        outcome = {
            "-": "hard rejected by SPF itself",
            "~": "marked as suspicious (soft-fail), but not rejected by SPF itself",
            "?": "evaluated as neutral by SPF itself",
            "+": "implicitly allowed (very unusual and unsafe)",
        }.get(qualifier, "not defined")
        lines.append(
            "Mail that doesn't come from the listed server(s)/IP(s) in the SPF record is " + outcome + "."
        )
    else:
        lines.append("No SPF record — there is no list of allowed sending servers.")

    if status["dkim_records"]:
        selectors = ", ".join(d["selector"] for d in status["dkim_records"])
        lines.append("DKIM key(s) published for selector(s): " + selectors + ".")
    else:
        lines.append("No confirmed DKIM key found in DNS.")

    if status["dmarc_tags"]:
        p = status["dmarc_tags"].get("p", "none")
        policy_text = {
            "reject": "fully rejected",
            "quarantine": "treated as spam/quarantined",
            "none": "let through as-is (monitoring only, not enforced)",
        }.get(p, p)
        lines.append(
            "Messages that aren't aligned on either SPF or DKIM are " + policy_text + "."
        )
        rua = status["dmarc_tags"].get("rua", "-")
        ruf = status["dmarc_tags"].get("ruf")
        report_line = f"Summary reports go to {rua}"
        if ruf:
            report_line += f", individual failure reports (per failed message) go to {ruf}"
        lines.append(report_line + ".")
    else:
        lines.append("No DMARC record — there is no enforceable policy against spoofing of this domain.")

    if status["tlsrpt_record"]:
        lines.append(
            "There is also reporting on failed secure (TLS) connections to the mail server."
        )

    return lines


def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def get_mailsec_connection():
    # Separate role from the dmarc one on purpose (least privilege): this
    # data comes from the mail server's own logs, not DMARC reports.
    return psycopg2.connect(
        host=MAILSEC_DB_HOST,
        port=MAILSEC_DB_PORT,
        dbname=MAILSEC_DB_NAME,
        user=MAILSEC_DB_USER,
        password=MAILSEC_DB_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def get_domain_overview(cur):
    """appelo.nl's own settings and their meaning — no usage/abuse data."""
    domain_status = get_domain_status(MONITORED_DOMAIN)
    selectors = get_seen_dkim_selectors(cur, MONITORED_DOMAIN)
    domain_status["dkim_records"] = get_confirmed_dkim_records(MONITORED_DOMAIN, selectors)
    domain_status["plain_summary"] = build_plain_summary(domain_status)
    return domain_status


def _country_flag(code):
    # ISO 3166-1 alpha-2 -> flag emoji, built from Unicode regional indicator
    # symbols (each letter A-Z maps to one). No icon library/CDN needed.
    if not code or len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + (ord(c) - ord("A"))) for c in code.upper())


def explain_failure(record):
    reasons = []
    if not record["spf_aligned"]:
        reasons.append(f"SPF {record['policy_spf_result'] or 'failed'} (not aligned)")
    if not record["dkim_aligned"]:
        reasons.append(f"DKIM {record['policy_dkim_result'] or 'failed'} (not aligned)")
    reason_text = " and ".join(reasons) if reasons else "unknown reason"

    outcome = {
        "reject": "rejected",
        "quarantine": "quarantined/marked as spam",
        "none": "let through (monitoring only)",
    }.get(record["disposition"], record["disposition"])

    return f"{reason_text} → message was {outcome}."


REPORTS_PER_PAGE = 50


@app.route("/")
def index():
    page = max(1, request.args.get("page", 1, type=int))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

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

            total_pages = max(1, math.ceil(summary["total_reports"] / REPORTS_PER_PAGE))
            page = min(page, total_pages)

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
                LIMIT %s OFFSET %s
                """,
                (REPORTS_PER_PAGE, (page - 1) * REPORTS_PER_PAGE),
            )
            reports = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "index.html",
        active_page="data",
        domain_status=domain_status,
        summary=summary,
        reports=reports,
        page=page,
        total_pages=total_pages,
    )


@app.route("/flagged")
def flagged():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            cur.execute(
                """
                SELECT
                    ar.org_name,
                    rec.source_ip,
                    rec.source_country,
                    rec.count,
                    rec.disposition,
                    rec.spf_aligned,
                    rec.dkim_aligned,
                    rec.policy_spf_result,
                    rec.policy_dkim_result,
                    rec.header_from,
                    rec.envelope_from,
                    rec.interval_begin,
                    (
                        SELECT string_agg(
                            coalesce(por.type, '?') ||
                                CASE WHEN por.comment IS NOT NULL THEN ' (' || por.comment || ')' ELSE '' END,
                            '; '
                        )
                        FROM dmarc.aggregate_record_policy_override_reasons por
                        WHERE por.record_id = rec.id
                    ) AS override_reason
                FROM dmarc.aggregate_records rec
                JOIN dmarc.aggregate_reports ar ON ar.id = rec.report_id
                WHERE NOT rec.dmarc_aligned
                ORDER BY rec.interval_begin DESC
                LIMIT 200
                """
            )
            flagged_records = cur.fetchall()
            for record in flagged_records:
                record["reason"] = explain_failure(record)
                record["flag"] = _country_flag(record["source_country"])
    finally:
        conn.close()

    return render_template(
        "flagged.html",
        active_page="flagged",
        domain_status=domain_status,
        flagged_records=flagged_records,
    )


def _nice_axis_max(value):
    # Round up to a clean number for the y-axis top: 39 -> 40, 139 -> 200.
    if value <= 0:
        return 10
    magnitude = 10 ** (len(str(int(value))) - 1)
    return math.ceil(value / magnitude) * magnitude


def _scale_bars(entries):
    # Adds total/*_h (pixel height) keys to each entry in place, sharing one
    # axis scale across all of them, and returns the y-axis tick values.
    axis_max = _nice_axis_max(max((e["aligned"] + e["quarantine"] + e["reject"] for e in entries), default=0))
    for e in entries:
        e["total"] = e["aligned"] + e["quarantine"] + e["reject"]
        e["aligned_h"] = round(e["aligned"] / axis_max * TREND_PLOT_HEIGHT_PX)
        e["quarantine_h"] = round(e["quarantine"] / axis_max * TREND_PLOT_HEIGHT_PX)
        e["reject_h"] = round(e["reject"] / axis_max * TREND_PLOT_HEIGHT_PX)
    tick_count = 5
    return [round(axis_max * i / (tick_count - 1)) for i in reversed(range(tick_count))]


def _daily_range(month_param):
    """Always spans exactly 31 days. With no month selected: the last 31 days
    ending today. With a selected month: that whole month, padded backward
    with days from the previous month if it has fewer than 31 days, so the
    chart is always the same width regardless of which month is picked."""
    first_of_month = None
    if month_param:
        try:
            year, month = (int(p) for p in month_param.split("-"))
            first_of_month = datetime.date(year, month, 1)
        except (ValueError, TypeError):
            first_of_month = None

    if first_of_month is None:
        end = datetime.date.today()
        start = end - datetime.timedelta(days=30)
        return start, end, "Last 31 days", None

    if first_of_month.month == 12:
        first_of_next = datetime.date(first_of_month.year + 1, 1, 1)
    else:
        first_of_next = datetime.date(first_of_month.year, first_of_month.month + 1, 1)
    end = first_of_next - datetime.timedelta(days=1)
    days_in_month = (end - first_of_month).days + 1
    start = first_of_month - datetime.timedelta(days=max(0, 31 - days_in_month))

    if start.strftime("%Y-%m") == end.strftime("%Y-%m"):
        label = end.strftime("%B %Y")
    else:
        label = f"{start.strftime('%B %Y')} – {end.strftime('%B %Y')}"
    return start, end, label, first_of_month.strftime("%Y-%m")


@app.route("/trend")
def trend():
    daily_start, daily_end, daily_label, active_month = _daily_range(request.args.get("month"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            cur.execute(
                """
                SELECT
                    date_trunc('month', rec.interval_begin)::date AS period,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'reject'
                    ), 0) AS reject
                FROM dmarc.aggregate_records rec
                GROUP BY period
                ORDER BY period
                """
            )
            month_rows = cur.fetchall()

            cur.execute(
                """
                SELECT
                    d::date AS day,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'reject'
                    ), 0) AS reject
                FROM generate_series(%(start)s::date, %(end)s::date, interval '1 day') AS d
                LEFT JOIN dmarc.aggregate_records rec ON rec.interval_begin::date = d::date
                GROUP BY d::date
                ORDER BY d::date
                """,
                {"start": daily_start, "end": daily_end},
            )
            day_rows = cur.fetchall()
    finally:
        conn.close()

    month_bars = [
        {
            "label": r["period"].strftime("%b %Y"),
            "month_key": r["period"].strftime("%Y-%m"),
            "aligned": r["aligned"],
            "quarantine": r["quarantine"],
            "reject": r["reject"],
        }
        for r in month_rows
    ]
    month_y_ticks = _scale_bars(month_bars)

    day_bars = [
        {
            "label": str(r["day"].day),
            "full_label": r["day"].strftime("%d %b %Y"),
            "aligned": r["aligned"],
            "quarantine": r["quarantine"],
            "reject": r["reject"],
        }
        for r in day_rows
    ]
    day_y_ticks = _scale_bars(day_bars)

    return render_template(
        "trend.html",
        active_page="trend",
        domain_status=domain_status,
        month_bars=month_bars,
        month_y_ticks=month_y_ticks,
        active_month=active_month,
        day_bars=day_bars,
        day_y_ticks=day_y_ticks,
        daily_label=daily_label,
        plot_height=TREND_PLOT_HEIGHT_PX,
    )


@app.route("/sources")
def sources():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            cur.execute(
                """
                SELECT
                    source_ip,
                    max(source_country) AS source_country,
                    max(source_reverse_dns) AS source_reverse_dns,
                    sum(count) AS total,
                    coalesce(sum(count) FILTER (WHERE dmarc_aligned), 0) AS aligned,
                    coalesce(sum(count) FILTER (
                        WHERE NOT dmarc_aligned AND disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(count) FILTER (
                        WHERE NOT dmarc_aligned AND disposition = 'reject'
                    ), 0) AS reject,
                    min(interval_begin) AS first_seen,
                    max(interval_begin) AS last_seen
                FROM dmarc.aggregate_records
                GROUP BY source_ip
                ORDER BY total DESC
                LIMIT 50
                """
            )
            source_rows = cur.fetchall()
    finally:
        conn.close()

    for r in source_rows:
        r["flag"] = _country_flag(r["source_country"])
        r["aligned_pct"] = round(100 * r["aligned"] / r["total"]) if r["total"] else 0

    return render_template(
        "sources.html",
        active_page="sources",
        domain_status=domain_status,
        source_rows=source_rows,
    )


def _reverse_dns(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return str(answers[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException, ValueError):
        return None


def _country_for_ip(ip):
    # Team Cymru's free IP-to-ASN/country DNS service — same DNS-lookup
    # mechanism already used elsewhere in this file, no API key/library needed.
    try:
        rev = dns.reversename.from_address(ip).to_text()
        if rev.endswith(".ip6.arpa."):
            query_name = rev[: -len(".ip6.arpa.")] + ".origin6.asn.cymru.com"
        else:
            query_name = rev[: -len(".in-addr.arpa.")] + ".origin.asn.cymru.com"
        answers = dns.resolver.resolve(query_name, "TXT")
        txt = "".join(s.decode() for s in answers[0].strings)
        parts = [p.strip() for p in txt.split("|")]
        return parts[2] if len(parts) > 2 else None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException, ValueError):
        return None


@app.route("/security")
def security():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)
    finally:
        conn.close()

    mailsec_conn = get_mailsec_connection()
    try:
        with mailsec_conn.cursor() as cur:
            cur.execute(
                """
                SELECT 'auth_failures' AS tbl, count(*) AS n FROM mailsec.auth_failures
                UNION ALL SELECT 'rejects_given', count(*) FROM mailsec.rejects_given
                UNION ALL SELECT 'rejects_received', count(*) FROM mailsec.rejects_received
                """
            )
            totals = {r["tbl"]: r["n"] for r in cur.fetchall()}

            cur.execute(
                """
                SELECT
                    source_ip,
                    count(*) AS attempts,
                    count(DISTINCT username) AS distinct_usernames,
                    array_agg(DISTINCT service ORDER BY service) AS services,
                    min(occurred_at) AS first_seen,
                    max(occurred_at) AS last_seen
                FROM mailsec.auth_failures
                GROUP BY source_ip
                ORDER BY attempts DESC
                LIMIT 30
                """
            )
            auth_sources = cur.fetchall()
            for r in auth_sources:
                r["services"] = ", ".join(AUTH_SERVICE_LABELS.get(s, s) for s in r["services"])
                ip = str(r["source_ip"])
                r["country"] = _country_for_ip(ip)
                r["flag"] = _country_flag(r["country"])
                r["reverse_dns"] = _reverse_dns(ip)

            cur.execute(
                """
                SELECT occurred_at, source_ip, source_host, smtp_code, enhanced_code,
                       reason, mail_from, rcpt_to, helo
                FROM mailsec.rejects_given
                ORDER BY occurred_at DESC
                LIMIT 200
                """
            )
            rejects_given = cur.fetchall()

            cur.execute(
                """
                SELECT occurred_at, mail_to, orig_to, relay, dsn_code, reason
                FROM mailsec.rejects_received
                ORDER BY occurred_at DESC
                LIMIT 200
                """
            )
            rejects_received = cur.fetchall()
    finally:
        mailsec_conn.close()

    return render_template(
        "security.html",
        active_page="security",
        domain_status=domain_status,
        totals=totals,
        auth_sources=auth_sources,
        rejects_given=rejects_given,
        rejects_received=rejects_received,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
