import datetime
import functools
import hashlib
import ipaddress
import math
import os
import re
import secrets
import time

import dns.exception
import dns.resolver
import dns.reversename
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.routing import BaseConverter
from werkzeug.security import check_password_hash, generate_password_hash

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

# The first domain is our own: its pages are public and it has the extra pages
# (TLS reports, mail security). The others only get the DMARC report pages,
# each behind its own password.
MONITORED_DOMAINS = [
    d.strip().lower().rstrip(".")
    for d in os.environ.get("MONITORED_DOMAINS", os.environ.get("MONITORED_DOMAIN", "appelo.nl")).split(",")
    if d.strip()
]
MONITORED_DOMAIN = MONITORED_DOMAINS[0]
# Initial passwords, "voorbeeld.nl=<hash>,ander.nl=<hash>", hashes from
# scripts/hash_domain_password.py. Once a password is changed on the Password
# page, the one in dmarc.domain_passwords wins. A domain with neither can only
# be opened from our own network.
DOMAIN_PASSWORDS = {
    domain.strip().lower(): hashed.strip()
    for domain, _, hashed in (
        pair.partition("=") for pair in os.environ.get("DOMAIN_PASSWORDS", "").split(",")
    )
    if hashed.strip()
}

app.secret_key = os.environ.get("SECRET_KEY")
if len(MONITORED_DOMAINS) > 1 and not app.secret_key:
    raise RuntimeError("More than one domain in MONITORED_DOMAINS, so SECRET_KEY is needed for the login cookie")
app.config.update(
    # Other apps on appelo.nl may use Flask's default "session" cookie too.
    SESSION_COOKIE_NAME="dmarc_session",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() != "false",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=30),
)
# Fixed "Gebruiker X" letters for known users on the security page, e.g.
# "bas@appelo.nl=B,cecile@appelo.nl=C". Everyone else gets the next free letter.
FIXED_PSEUDONYMS = dict(
    pair.strip().lower().rsplit("=", 1)
    for pair in os.environ.get("FIXED_PSEUDONYMS", "").split(",")
    if "=" in pair
)

# Our own network: only from here is the security page (mail server logs)
# visible, and every domain's pages without a password. Everyone else gets a
# 404 / the login page and no menu links. Comma-separated networks.
SECURITY_ALLOWED_NETWORKS = [
    ipaddress.ip_network(net.strip())
    for net in os.environ.get(
        "SECURITY_ALLOWED_NETWORKS",
        "192.168.93.0/24,45.142.232.176/32,2a10:3781:5551:1::/64",
    ).split(",")
    if net.strip()
]
# Apache on this host reverse-proxies to us, so every request comes from here;
# only then is X-Forwarded-For trusted (anyone else could just set it).
TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def _client_ip():
    addr = request.remote_addr
    if addr in TRUSTED_PROXIES:
        # mod_proxy appends the address it got the request from as the last
        # entry; anything before that was supplied by the client.
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            addr = forwarded.split(",")[-1].strip()
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    # An IPv4 client on a dual-stack socket shows up as ::ffff:a.b.c.d.
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def from_own_network():
    ip = _client_ip()
    return ip is not None and any(ip in net for net in SECURITY_ALLOWED_NETWORKS)


# Everything below looks things up in DNS synchronously, per request. A short
# lifetime caps the worst case for a slow/unresponsive nameserver.
DNS_LOOKUP_TIMEOUT = 2  # seconds
# How long the domain's own DNS settings (header) are cached, and how long
# per-IP reverse DNS/country lookups are.
DOMAIN_STATUS_TTL = 3600
IP_LOOKUP_TTL = 86400
# DKIM selectors come from received aggregate reports, which anyone can send
# us — cap how many get looked up so fake reports can't slow every page down.
MAX_DKIM_SELECTORS = 20


def ttl_cache(seconds, maxsize=1024):
    """Like functools.lru_cache, but entries expire — so a lookup that failed
    once (e.g. a timeout) isn't remembered until the next restart."""

    def decorator(func):
        cache = {}

        @functools.wraps(func)
        def wrapper(*args):
            now = time.monotonic()
            hit = cache.get(args)
            if hit and now - hit[0] < seconds:
                return hit[1]
            value = func(*args)
            if len(cache) >= maxsize:
                cache.clear()
            cache[args] = (now, value)
            return value

        return wrapper

    return decorator


def _txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=DNS_LOOKUP_TIMEOUT)
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
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=DNS_LOOKUP_TIMEOUT)
        mx_records = sorted((r.preference, str(r.exchange).rstrip(".")) for r in mx_answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        mx_records = []

    spf_records = [r for r in _txt_records(domain) if r.lower().startswith("v=spf1")]

    dmarc_records = [r for r in _txt_records(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    dmarc_tags = _parse_tags(dmarc_records[0]) if dmarc_records else None

    tlsrpt_records = _txt_records(f"_smtp._tls.{domain}")

    return {
        "domain": domain,
        "mx_records": mx_records,
        "spf_record": spf_records[0] if spf_records else None,
        "dmarc_record": dmarc_records[0] if dmarc_records else None,
        "dmarc_tags": dmarc_tags,
        "dmarc_policy": _dmarc_policy(dmarc_tags),
        "tlsrpt_record": tlsrpt_records[0] if tlsrpt_records else None,
    }


def _dmarc_policy(tags):
    """(p, pct, level) for a parsed DMARC record — level is the badge colour
    ("good"/"warn"/"bad"): only p=reject applied to all mail counts as good."""
    if tags is None:
        return None
    p = tags.get("p", "none").lower()
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100
    if p == "reject" and pct == 100:
        level = "good"
    elif p in ("reject", "quarantine") and pct > 0:
        level = "warn"
    else:
        level = "bad"
    return {"p": p, "pct": pct, "level": level}


def get_seen_dkim_selectors(cur, domain):
    # DKIM records live at {selector}._domainkey.{domain}, but the selector name
    # is chosen freely and can't be looked up directly. The only place we see it
    # is in the aggregate reports already received — but note: whoever sends that
    # report (or the message itself) can put anything there, so this is a list of
    # *candidates*, not confirmed appelo.nl settings.
    cur.execute(
        """
        SELECT selector
        FROM dmarc.aggregate_record_dkim_results
        WHERE domain = %s AND selector IS NOT NULL
        GROUP BY selector
        ORDER BY max(id) DESC
        LIMIT %s
        """,
        (domain, MAX_DKIM_SELECTORS),
    )
    return sorted(row["selector"] for row in cur.fetchall())


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


SPF_ALL_RE = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


def _spf_all_qualifier(spf_record):
    for token in spf_record.split():
        m = SPF_ALL_RE.match(token)
        if m:
            return m[1] or "+"
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
        policy = status["dmarc_policy"]
        policy_text = {
            "reject": "fully rejected",
            "quarantine": "treated as spam/quarantined",
            "none": "let through as-is (monitoring only, not enforced)",
        }.get(policy["p"], policy["p"])
        if policy["p"] != "none" and policy["pct"] < 100:
            policy_text = f"{policy_text} — but only {policy['pct']}% of them, the rest is let through"
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
    """The current domain's own settings and their meaning — no usage/abuse data."""
    domain = current_domain()
    selectors = get_seen_dkim_selectors(cur, domain)
    return _domain_overview(domain, tuple(selectors))


@ttl_cache(DOMAIN_STATUS_TTL)
def _domain_overview(domain, selectors):
    domain_status = get_domain_status(domain)
    domain_status["dkim_records"] = get_confirmed_dkim_records(domain, selectors)
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


@app.template_filter("pct_status")
def pct_status(pct):
    """Badge/tile colour for an "aligned %" — the same thresholds everywhere."""
    if pct is None:
        return ""
    if pct >= 95:
        return "good"
    if pct >= 80:
        return "warn"
    return "bad"


ROWS_PER_PAGE = 50

# Period filter shared by every table page (not /trend, which has its own
# month/day navigation). Key -> (label, days back; None = everything).
PERIODS = {
    "7d": ("Last 7 days", 7),
    "30d": ("Last 30 days", 30),
    "365d": ("Last 12 months", 365),
    "all": ("All time", None),
}
DEFAULT_PERIOD = "30d"


class DomainConverter(BaseConverter):
    # Needs a dot, so /security and the old /trend etc. never match it.
    regex = r"(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+"

    def to_python(self, value):
        return value.lower()


app.url_map.converters["domain"] = DomainConverter

# Pages only our own domain has.
PRIMARY_ONLY_ENDPOINTS = {"tls_reports"}


def current_domain():
    # Pages outside /<domain>/ (the security page) are about our own domain.
    return g.get("domain", MONITORED_DOMAIN)


@app.url_value_preprocessor
def _pull_domain(endpoint, values):
    if values and "domain" in values:
        g.domain = values.pop("domain")


@app.url_defaults
def _add_domain(endpoint, values):
    if "domain" not in values and app.url_map.is_endpoint_expecting(endpoint, "domain"):
        values["domain"] = current_domain()


PASSWORDS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dmarc.domain_passwords (
    domain TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""
_passwords_table_ready = False


def _passwords_cursor(conn):
    global _passwords_table_ready
    cur = conn.cursor()
    if not _passwords_table_ready:
        cur.execute(PASSWORDS_SCHEMA_SQL)
        _passwords_table_ready = True
    return cur


def get_password_hash(domain):
    """The domain's current password hash, or None if it can't be logged in to.
    Looked up per request rather than cached: another gunicorn worker may
    have just changed it."""
    if domain not in MONITORED_DOMAINS or domain == MONITORED_DOMAIN:
        return None
    cache = g.setdefault("password_hashes", {})
    if domain not in cache:
        conn = get_connection()
        try:
            with _passwords_cursor(conn) as cur:
                cur.execute("SELECT password_hash FROM dmarc.domain_passwords WHERE domain = %s", (domain,))
                row = cur.fetchone()
            conn.commit()
        finally:
            conn.close()
        cache[domain] = row["password_hash"] if row else DOMAIN_PASSWORDS.get(domain)
    return cache[domain]


def set_password(domain, password):
    hashed = generate_password_hash(password)
    conn = get_connection()
    try:
        with _passwords_cursor(conn) as cur:
            cur.execute(
                """
                INSERT INTO dmarc.domain_passwords (domain, password_hash) VALUES (%s, %s)
                ON CONFLICT (domain) DO UPDATE SET password_hash = EXCLUDED.password_hash, changed_at = now()
                """,
                (domain, hashed),
            )
        conn.commit()
    finally:
        conn.close()
    g.setdefault("password_hashes", {})[domain] = hashed


def _password_tag(domain):
    # Stored in the (signed, not encrypted) session cookie instead of a plain
    # "logged in" flag, so changing a domain's password logs everyone out.
    hashed = get_password_hash(domain)
    return hashlib.sha256(hashed.encode()).hexdigest()[:16] if hashed else None


def is_logged_in(domain):
    tag = _password_tag(domain)
    return tag is not None and session.get("unlocked", {}).get(domain) == tag


def _remember_login(domain):
    session.permanent = True
    session["unlocked"] = {**session.get("unlocked", {}), domain: _password_tag(domain)}


def can_open(domain):
    if domain == MONITORED_DOMAIN:
        return True
    if domain in MONITORED_DOMAINS and from_own_network():
        return True
    return is_logged_in(domain)


@app.before_request
def _check_csrf():
    # Our own network gets in on its IP address alone, so without this any
    # site its users visit could post forms here in their name.
    if request.method == "POST":
        token = session.get("csrf")
        if not token or not secrets.compare_digest(token, request.form.get("csrf", "")):
            abort(400)


@app.template_global()
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def _check_domain_access():
    domain = g.get("domain")
    if domain is None or domain == MONITORED_DOMAIN or request.endpoint in ("login", "logout"):
        return None
    if request.endpoint in PRIMARY_ONLY_ENDPOINTS:
        abort(404)
    # Unknown domains end up at the login page too, so it doesn't tell which
    # domains are monitored.
    if not can_open(domain):
        return redirect(url_for("login"))
    return None


@app.context_processor
def inject_periods():
    domain = current_domain()
    own_network = from_own_network()
    return {
        "periods": PERIODS,
        "domain": domain,
        "is_primary_domain": domain == MONITORED_DOMAIN,
        "can_see_security": domain == MONITORED_DOMAIN and own_network,
        "all_domains": MONITORED_DOMAINS if own_network and len(MONITORED_DOMAINS) > 1 else [],
        # Not via is_logged_in(): that's a database lookup, and this runs for
        # every page; a stale entry only means a Log out button that does nothing.
        "logged_in": domain in session.get("unlocked", {}),
    }


def _period_from_request():
    """(period key, start of that period, or None for all time)."""
    key = request.args.get("period", DEFAULT_PERIOD)
    if key not in PERIODS:
        key = DEFAULT_PERIOD
    days = PERIODS[key][1]
    if days is None:
        return key, None
    return key, datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)


def _since(column):
    # SQL condition for the period filter; expects a %(since)s parameter.
    return f"(%(since)s::timestamptz IS NULL OR {column} >= %(since)s)"


def _for_domain(column):
    """SQL condition: `column` is the current domain or one of its subdomains,
    but not a subdomain that is monitored as a domain of its own. Expects the
    parameters from _domain_params()."""
    def matches(d):
        return f"(lower({column}) = {d} OR right(lower({column}), length({d}) + 1) = '.' || {d})"
    return (
        f"({matches('%(domain)s')} AND NOT EXISTS ("
        f"SELECT 1 FROM unnest(%(own_subdomains)s::text[]) s WHERE {matches('s')}))"
    )


def _domain_params():
    domain = current_domain()
    return {
        "domain": domain,
        "own_subdomains": [d for d in MONITORED_DOMAINS if d.endswith("." + domain)],
    }


def _paginated(cur, sql, params, page_param="page"):
    """Runs `sql` (dict params, no LIMIT/OFFSET of its own) for the page number
    in request arg `page_param`. Returns (rows, pager); pager is what the
    pager() macro in _macros.html needs."""
    cur.execute(f"SELECT count(*) AS n FROM ({sql}) t", params)
    total = cur.fetchone()["n"]
    total_pages = max(1, math.ceil(total / ROWS_PER_PAGE))
    page = min(max(1, request.args.get(page_param, 1, type=int)), total_pages)
    cur.execute(
        f"{sql} LIMIT %(_limit)s OFFSET %(_offset)s",
        {**params, "_limit": ROWS_PER_PAGE, "_offset": (page - 1) * ROWS_PER_PAGE},
    )
    pager = {
        "param": page_param,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "first": (page - 1) * ROWS_PER_PAGE + 1 if total else 0,
        "last": min(page * ROWS_PER_PAGE, total),
    }
    return cur.fetchall(), pager


@app.template_global()
def url_with(param, value, anchor=None):
    """The current page's URL with one query arg changed (e.g. a page number),
    keeping the others (period, other tables' page numbers)."""
    args = request.args.to_dict()
    args[param] = value
    return url_for(request.endpoint, _anchor=anchor, **args)


_DUMMY_PASSWORD_HASH = generate_password_hash("not anyone's password")


@app.route("/<domain:domain>/login", methods=["GET", "POST"])
def login():
    domain = g.domain
    if can_open(domain):
        return redirect(url_for("trend"))

    error = None
    if request.method == "POST":
        hashed = get_password_hash(domain)
        # Unknown domains are checked against a dummy hash, so they take
        # just as long to fail.
        if check_password_hash(hashed or _DUMMY_PASSWORD_HASH, request.form.get("password", "")) and hashed:
            _remember_login(domain)
            return redirect(url_for("trend"))
        # Slows down guessing.
        time.sleep(1)
        error = "Wrong password."

    return render_template("login.html", error=error), 401 if error else 200


@app.route("/<domain:domain>/logout", methods=["POST"])
def logout():
    unlocked = dict(session.get("unlocked", {}))
    unlocked.pop(g.domain, None)
    session["unlocked"] = unlocked
    return redirect(url_for("login"))


MIN_PASSWORD_LENGTH = 10


@app.route("/<domain:domain>/password", methods=["GET", "POST"])
def password():
    domain = g.domain
    if domain == MONITORED_DOMAIN:
        abort(404)
    # From our own network a password can be set without knowing the current
    # one: that's how to give a domain its first password, or reset it.
    needs_current = not from_own_network()

    error = None
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        if needs_current and not check_password_hash(get_password_hash(domain) or _DUMMY_PASSWORD_HASH, current):
            time.sleep(1)
            error = "The current password is wrong."
        elif len(new) < MIN_PASSWORD_LENGTH:
            error = f"The new password needs at least {MIN_PASSWORD_LENGTH} characters."
        elif new != request.form.get("repeat", ""):
            error = "The new passwords don't match."
        else:
            set_password(domain, new)
            # Everyone else is logged out by the new password; not whoever changed it.
            if needs_current:
                _remember_login(domain)
            return redirect(url_for("password", changed=1))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)
    finally:
        conn.close()

    return render_template(
        "password.html",
        active_page="password",
        domain_status=domain_status,
        needs_current=needs_current,
        has_password=get_password_hash(domain) is not None,
        min_length=MIN_PASSWORD_LENGTH,
        error=error,
        changed=request.args.get("changed") == "1",
    ), 400 if error else 200


# Everything used to live at the root, for our own domain only; keep those
# links/bookmarks working.
@app.route("/")
@app.route("/<any(trend, reports, flagged, sources, tls):page>")
def old_url(page="trend"):
    endpoint = {"tls": "tls_reports"}.get(page, page)
    return redirect(url_for(endpoint, domain=MONITORED_DOMAIN, **request.args.to_dict()))


@app.route("/<domain:domain>/reports")
def reports():
    period, since = _period_from_request()
    params = {"since": since, **_domain_params()}

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            cur.execute(
                f"""
                SELECT
                    count(DISTINCT ar.id) AS total_reports,
                    coalesce(sum(rec.count), 0) AS total_messages,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned_messages
                FROM dmarc.aggregate_reports ar
                LEFT JOIN dmarc.aggregate_records rec ON rec.report_id = ar.id
                WHERE {_since("ar.date_begin")} AND {_for_domain("ar.domain")}
                """,
                params,
            )
            summary = cur.fetchone()

            reports, pager = _paginated(
                cur,
                f"""
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
                WHERE {_since("ar.date_begin")} AND {_for_domain("ar.domain")}
                GROUP BY ar.id
                ORDER BY ar.date_begin DESC, ar.id DESC
                """,
                params,
            )
    finally:
        conn.close()

    return render_template(
        "index.html",
        active_page="data",
        period=period,
        domain_status=domain_status,
        summary=summary,
        reports=reports,
        pager=pager,
    )


@app.route("/<domain:domain>/flagged")
def flagged():
    period, since = _period_from_request()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            flagged_records, pager = _paginated(
                cur,
                f"""
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
                WHERE NOT rec.dmarc_aligned AND {_since("rec.interval_begin")} AND {_for_domain("ar.domain")}
                ORDER BY rec.interval_begin DESC, rec.id DESC
                """,
                {"since": since, **_domain_params()},
            )
            for record in flagged_records:
                record["reason"] = explain_failure(record)
                record["flag"] = _country_flag(record["source_country"])
    finally:
        conn.close()

    return render_template(
        "flagged.html",
        active_page="flagged",
        period=period,
        domain_status=domain_status,
        flagged_records=flagged_records,
        pager=pager,
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
    for e in entries:
        e["total"] = e["aligned"] + e["let_through"] + e["quarantine"] + e["reject"]
    axis_max = _nice_axis_max(max((e["total"] for e in entries), default=0))
    for e in entries:
        for key in ("aligned", "let_through", "quarantine", "reject"):
            e[f"{key}_h"] = round(e[key] / axis_max * TREND_PLOT_HEIGHT_PX)
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


# A domain's landing page.
@app.route("/<domain:domain>/")
def trend():
    daily_start, daily_end, daily_label, active_month = _daily_range(request.args.get("month"))

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            cur.execute(
                f"""
                SELECT
                    date_trunc('month', rec.interval_begin)::date AS period,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'reject'
                    ), 0) AS reject,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition NOT IN ('quarantine', 'reject')
                    ), 0) AS let_through
                FROM dmarc.aggregate_records rec
                JOIN dmarc.aggregate_reports ar ON ar.id = rec.report_id
                WHERE {_for_domain("ar.domain")}
                GROUP BY period
                ORDER BY period
                """,
                _domain_params(),
            )
            month_rows = cur.fetchall()

            cur.execute(
                f"""
                SELECT
                    d::date AS day,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'reject'
                    ), 0) AS reject,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition NOT IN ('quarantine', 'reject')
                    ), 0) AS let_through
                FROM generate_series(%(start)s::date, %(end)s::date, interval '1 day') AS d
                LEFT JOIN (
                    dmarc.aggregate_records rec
                    JOIN dmarc.aggregate_reports ar ON ar.id = rec.report_id AND {_for_domain("ar.domain")}
                ) ON rec.interval_begin::date = d::date
                GROUP BY d::date
                ORDER BY d::date
                """,
                {"start": daily_start, "end": daily_end, **_domain_params()},
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
            "let_through": r["let_through"],
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
            "let_through": r["let_through"],
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


@app.route("/<domain:domain>/sources")
def sources():
    period, since = _period_from_request()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            source_rows, pager = _paginated(
                cur,
                f"""
                SELECT
                    rec.source_ip,
                    max(rec.source_country) AS source_country,
                    max(rec.source_reverse_dns) AS source_reverse_dns,
                    sum(rec.count) AS total,
                    coalesce(sum(rec.count) FILTER (WHERE rec.dmarc_aligned), 0) AS aligned,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'quarantine'
                    ), 0) AS quarantine,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition = 'reject'
                    ), 0) AS reject,
                    coalesce(sum(rec.count) FILTER (
                        WHERE NOT rec.dmarc_aligned AND rec.disposition NOT IN ('quarantine', 'reject')
                    ), 0) AS let_through,
                    min(rec.interval_begin) AS first_seen,
                    max(rec.interval_begin) AS last_seen
                FROM dmarc.aggregate_records rec
                JOIN dmarc.aggregate_reports ar ON ar.id = rec.report_id
                WHERE {_since("rec.interval_begin")} AND {_for_domain("ar.domain")}
                GROUP BY rec.source_ip
                ORDER BY total DESC, rec.source_ip
                """,
                {"since": since, **_domain_params()},
            )
    finally:
        conn.close()

    for r in source_rows:
        r["flag"] = _country_flag(r["source_country"])
        r["aligned_pct"] = round(100 * r["aligned"] / r["total"]) if r["total"] else 0

    return render_template(
        "sources.html",
        active_page="sources",
        period=period,
        domain_status=domain_status,
        source_rows=source_rows,
        pager=pager,
    )


# The security page does these lookups per distinct source IP — caching means
# the same repeat-offender IPs (which show up on every page load) don't get
# looked up again and again.
@ttl_cache(IP_LOOKUP_TTL)
def _reverse_dns(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", lifetime=DNS_LOOKUP_TIMEOUT)
        return str(answers[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException, ValueError):
        return None


@ttl_cache(IP_LOOKUP_TTL)
def _country_for_ip(ip):
    # Team Cymru's free IP-to-ASN/country DNS service — same DNS-lookup
    # mechanism already used elsewhere in this file, no API key/library needed.
    try:
        rev = dns.reversename.from_address(ip).to_text()
        if rev.endswith(".ip6.arpa."):
            query_name = rev[: -len(".ip6.arpa.")] + ".origin6.asn.cymru.com"
        else:
            query_name = rev[: -len(".in-addr.arpa.")] + ".origin.asn.cymru.com"
        answers = dns.resolver.resolve(query_name, "TXT", lifetime=DNS_LOOKUP_TIMEOUT)
        txt = "".join(s.decode() for s in answers[0].strings)
        parts = [p.strip() for p in txt.split("|")]
        return parts[2] if len(parts) > 2 else None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException, ValueError):
        return None


EMAIL_RE = re.compile(r"[\w.+=-]+@[\w-]+(?:\.[\w-]+)+")
# Forwarding/SRS-style addresses embed the original address at the end of
# their local part: colander+caf_=bas=appelo.nl@gmail.com is Gmail's address
# for mail forwarded from bas@appelo.nl.
EMBEDDED_ADDRESS_RE = re.compile(r"([^-+=_]+)=([\w-]+(?:\.[\w-]+)+)$")


def _is_own_domain(domain):
    return domain == MONITORED_DOMAIN or domain.endswith("." + MONITORED_DOMAIN)


def _own_address(address):
    """(own address, via) for the @MONITORED_DOMAIN address behind `address`:
    itself (via None), or the one a forwarding address embeds (via is the
    forwarder's name, e.g. "gmail"). (None, None) if it isn't one of ours."""
    local, _, domain = address.lower().rpartition("@")
    m = EMBEDDED_ADDRESS_RE.search(local)
    if m and _is_own_domain(m[2]):
        return f"{m[1]}@{m[2]}", domain.split(".")[-2] if "." in domain else domain
    if _is_own_domain(domain):
        return f"{local}@{domain}", None
    return None, None


def _letters(n):
    # 0 -> A, 25 -> Z, 26 -> AA, like spreadsheet columns.
    out = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        out = chr(ord("A") + rem) + out
    return out


class AddressPseudonyms:
    """Replaces our own users' addresses on the (public) security page with
    "Gebruiker A", "Gebruiker B", ... Letters are handed out in order of first
    appearance in the mailsec tables, so they stay the same between page loads.
    Anyone else's address is reduced to its domain ("…@example.com"): it says
    who our users correspond with.

    Kept per worker and only fed rows newer than the last refresh, instead of
    re-reading the whole history on every page load.
    """

    def __init__(self):
        self.labels = {address: f"Gebruiker {letters.upper()}" for address, letters in FIXED_PSEUDONYMS.items()}
        self.next_index = 0
        self.seen_until = None

    def refresh(self, cur):
        # >= rather than >: rows sharing the last timestamp get fed again,
        # which is harmless since labelling an address twice is a no-op.
        cur.execute(
            """
            SELECT * FROM (
                SELECT occurred_at, 0 AS src, id, mail_from AS a, rcpt_to AS b, reason
                FROM mailsec.rejects_given
                UNION ALL
                SELECT occurred_at, 1, id, orig_to, mail_to, reason
                FROM mailsec.rejects_received
            ) t
            WHERE %(since)s::timestamptz IS NULL OR occurred_at >= %(since)s
            ORDER BY occurred_at, src, id
            """,
            {"since": self.seen_until},
        )
        for r in cur.fetchall():
            for value in (r["a"], r["b"], r["reason"]):
                self.mask(value)
            self.seen_until = r["occurred_at"]

    def label(self, address):
        own, via = _own_address(address)
        if own is None:
            return None
        if own not in self.labels:
            taken = set(self.labels.values())
            while f"Gebruiker {_letters(self.next_index)}" in taken:
                self.next_index += 1
            self.labels[own] = f"Gebruiker {_letters(self.next_index)}"
            self.next_index += 1
        return f"{self.labels[own]} (via {via})" if via else self.labels[own]

    def mask(self, text):
        if not text:
            return text
        return EMAIL_RE.sub(lambda m: self.label(m[0]) or "…@" + m[0].rpartition("@")[2], text)


_pseudonyms = AddressPseudonyms()


def _add_ip_details(rows):
    for r in rows:
        ip = str(r["source_ip"]) if r["source_ip"] else None
        r["country"] = _country_for_ip(ip) if ip else None
        r["flag"] = _country_flag(r["country"])
        r["reverse_dns"] = _reverse_dns(ip) if ip else None


@app.route("/security")
def security():
    if not from_own_network():
        abort(404)
    period, since = _period_from_request()
    params = {"since": since}

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
                f"""
                SELECT 'auth_failures' AS tbl, count(*) AS n FROM mailsec.auth_failures
                    WHERE {_since("occurred_at")}
                UNION ALL SELECT 'rejects_given', count(*) FROM mailsec.rejects_given
                    WHERE {_since("occurred_at")}
                UNION ALL SELECT 'rejects_received', count(*) FROM mailsec.rejects_received
                    WHERE {_since("occurred_at")}
                UNION ALL SELECT 'dmarc_dkim_marked', count(*) FROM mailsec.dmarc_results
                    WHERE component = 'dmarc' AND result = 'fail' AND {_since("occurred_at")}
                """,
                params,
            )
            totals = {r["tbl"]: r["n"] for r in cur.fetchall()}

            auth_sources, auth_pager = _paginated(
                cur,
                f"""
                SELECT
                    source_ip,
                    count(*) AS attempts,
                    count(DISTINCT username) AS distinct_usernames,
                    array_agg(DISTINCT service ORDER BY service) AS services,
                    min(occurred_at) AS first_seen,
                    max(occurred_at) AS last_seen
                FROM mailsec.auth_failures
                WHERE {_since("occurred_at")}
                GROUP BY source_ip
                ORDER BY attempts DESC, source_ip
                """,
                params,
                page_param="auth_page",
            )
            for r in auth_sources:
                r["services"] = ", ".join(AUTH_SERVICE_LABELS.get(s, s) for s in r["services"])
            _add_ip_details(auth_sources)

            rejects_given, given_pager = _paginated(
                cur,
                f"""
                SELECT occurred_at, source_ip, source_host, smtp_code, enhanced_code,
                       reason, mail_from, rcpt_to, helo
                FROM mailsec.rejects_given
                WHERE {_since("occurred_at")}
                ORDER BY occurred_at DESC, id DESC
                """,
                params,
                page_param="given_page",
            )

            rejects_received, received_pager = _paginated(
                cur,
                f"""
                SELECT occurred_at, mail_to, orig_to, relay, dsn_code, reason
                FROM mailsec.rejects_received
                WHERE {_since("occurred_at")}
                ORDER BY occurred_at DESC, id DESC
                """,
                params,
                page_param="received_page",
            )

            pseudonyms = _pseudonyms
            pseudonyms.refresh(cur)
            for r in rejects_given:
                for key in ("mail_from", "rcpt_to", "reason"):
                    r[key] = pseudonyms.mask(r[key])
            for r in rejects_received:
                # Forwarded mail: the destination is the user's own private
                # address elsewhere (e.g. their Gmail), so hide that too.
                if r["orig_to"] and r["mail_to"] and pseudonyms.label(r["orig_to"]) \
                        and not pseudonyms.label(r["mail_to"]):
                    r["mail_to"] = f"{pseudonyms.label(r['orig_to'])} (forward)"
                for key in ("mail_to", "orig_to", "reason"):
                    r[key] = pseudonyms.mask(r[key])

            dmarc_fail_sources, marked_pager = _paginated(
                cur,
                f"""
                SELECT
                    c.source_ip,
                    count(*) AS total,
                    array_agg(DISTINCT d.domain ORDER BY d.domain) AS domains,
                    min(d.occurred_at) AS first_seen,
                    max(d.occurred_at) AS last_seen
                FROM mailsec.dmarc_results d
                LEFT JOIN LATERAL (
                    SELECT source_ip
                    FROM mailsec.smtp_clients sc
                    WHERE sc.queue_id = d.queue_id
                    ORDER BY abs(extract(epoch FROM sc.occurred_at - d.occurred_at))
                    LIMIT 1
                ) c ON true
                WHERE d.component = 'dmarc' AND d.result = 'fail' AND {_since("d.occurred_at")}
                GROUP BY c.source_ip
                ORDER BY total DESC, c.source_ip
                """,
                params,
                page_param="marked_page",
            )
            _add_ip_details(dmarc_fail_sources)
    finally:
        mailsec_conn.close()

    return render_template(
        "security.html",
        active_page="security",
        period=period,
        domain_status=domain_status,
        totals=totals,
        auth_sources=auth_sources,
        auth_pager=auth_pager,
        rejects_given=rejects_given,
        given_pager=given_pager,
        rejects_received=rejects_received,
        received_pager=received_pager,
        dmarc_fail_sources=dmarc_fail_sources,
        marked_pager=marked_pager,
    )


@app.route("/<domain:domain>/tls")
def tls_reports():
    period, since = _period_from_request()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            domain_status = get_domain_overview(cur)

            policy_rows, pager = _paginated(
                cur,
                f"""
                SELECT
                    r.organization_name,
                    r.date_begin,
                    r.date_end,
                    p.policy_domain,
                    p.policy_type,
                    p.successful_session_count,
                    p.failed_session_count,
                    (
                        SELECT string_agg(
                            fd.result_type || ' (' || fd.failed_session_count || 'x' ||
                                CASE WHEN fd.receiving_mx_hostname IS NOT NULL
                                     THEN ' at ' || fd.receiving_mx_hostname ELSE '' END ||
                                CASE WHEN fd.sending_mta_ip IS NOT NULL
                                     THEN ' from ' || fd.sending_mta_ip ELSE '' END ||
                                ')',
                            '; '
                        )
                        FROM dmarc.smtp_tls_failure_details fd
                        WHERE fd.policy_id = p.id
                    ) AS failure_summary
                FROM dmarc.smtp_tls_policies p
                JOIN dmarc.smtp_tls_reports r ON r.id = p.report_id
                WHERE {_since("r.date_end")} AND {_for_domain("p.policy_domain")}
                ORDER BY r.date_end DESC, r.organization_name, p.id
                """,
                {"since": since, **_domain_params()},
            )
    finally:
        conn.close()

    for p in policy_rows:
        total = p["successful_session_count"] + p["failed_session_count"]
        p["total"] = total
        p["failure_rate_pct"] = round(100 * p["failed_session_count"] / total) if total else 0

    return render_template(
        "tls.html",
        active_page="tls",
        period=period,
        domain_status=domain_status,
        policy_rows=policy_rows,
        pager=pager,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
