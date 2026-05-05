"""
Web Application Firewall (WAF) Middleware
Inspects all incoming requests for common attack patterns before they reach any route.

References:
- OWASP Top 10 A03:2021 - Injection
  https://owasp.org/Top10/A03_2021-Injection/
- OWASP SQL Injection Prevention Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cross Site Scripting Prevention Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP Core Rule Set (CRS) - pattern inspiration
  https://coreruleset.org/
- OWASP Path Traversal
  https://owasp.org/www-community/attacks/Path_Traversal
"""

import re
from flask import request, jsonify
from models import SecurityLog
from extensions import db


# SQL injection patterns
# Based on OWASP CRS SQL injection rules
# Reference: https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
SQL_PATTERNS = [
    r"(\b(union)\b.{0,20}\b(select)\b)",            # UNION SELECT attacks
    r"(\b(select)\b.{0,20}\b(from)\b)",             # SELECT FROM
    r"(\b(insert)\b.{0,20}\b(into)\b)",             # INSERT INTO
    r"(\b(update)\b.{0,20}\b(set)\b)",              # UPDATE SET
    r"(\b(delete)\b.{0,20}\b(from)\b)",             # DELETE FROM
    r"(\b(drop)\b.{0,20}\b(table|database)\b)",     # DROP TABLE / DATABASE
    r"(--|#)",                                        # SQL comment sequences
    r"(\bor\b\s+['\"\d].*?=.*?['\"\d])",            # OR '1'='1 or OR 1=1 bypass
    r"(\band\b\s+['\"\d].*?=.*?['\"\d])",           # AND '1'='1' or AND 1=1 bypass
    r"(\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\b)", # time-based blind SQLi
    r"(xp_cmdshell|sp_executesql)",                  # MSSQL command execution
    r"(load_file\s*\(|into\s+outfile|into\s+dumpfile)", # file read/write via SQL
]

# XSS patterns
# Reference: OWASP XSS Prevention Cheat Sheet
# https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
XSS_PATTERNS = [
    r"<\s*script[\s\S]*?>",                          # <script> tag injection
    r"<\/\s*script\s*>",                             # closing script tag
    r"javascript\s*:",                                # javascript: URI scheme
    r"on(error|load|click|mouseover|focus)\s*=",    # inline event handlers
    r"<\s*iframe",                                    # iframe injection
    r"<\s*img[^>]+onerror",                          # img onerror XSS
    r"(alert|confirm|prompt)\s*\(",                  # common XSS test payloads
    r"document\s*\.\s*(cookie|write|location)",      # DOM-based XSS
    r"eval\s*\(",                                     # eval() injection
]

# Path traversal patterns
# Reference: OWASP Path Traversal
# https://owasp.org/www-community/attacks/Path_Traversal
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",           # ../
    r"\.\.\\",          # ..\
    r"%2e%2e%2f",       # URL encoded ../
    r"%2e%2e/",         # partially encoded ../
    r"\.\.%2f",         # partially encoded ../
]

# compile all patterns once at startup for performance
COMPILED_SQL  = [re.compile(p, re.IGNORECASE) for p in SQL_PATTERNS]
COMPILED_XSS  = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]
COMPILED_PATH = [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]


def check_value(value):
    """Check a single string value against all WAF pattern lists. Returns threat type or None."""
    if not isinstance(value, str):
        return None

    for pattern in COMPILED_SQL:
        if pattern.search(value):
            return 'sql_injection'

    for pattern in COMPILED_XSS:
        if pattern.search(value):
            return 'xss_attempt'

    for pattern in COMPILED_PATH:
        if pattern.search(value):
            return 'path_traversal'

    return None


def inspect_request():
    """
    Pull all user-supplied data from the request and run it through the WAF.
    Checks query string params, form data, and JSON body.
    Returns (threat_type, field_name, value) or (None, None, None)
    """
    to_check = []

    # query string parameters
    for key, val in request.args.items():
        to_check.append((f'querystring:{key}', val))

    # form data
    for key, val in request.form.items():
        to_check.append((f'form:{key}', val))

    # JSON body - most of our API uses this
    if request.is_json:
        try:
            body = request.get_json(silent=True) or {}
            for key, val in body.items():
                if isinstance(val, str):
                    to_check.append((f'json:{key}', val))
        except Exception:
            pass

    for field, value in to_check:
        threat = check_value(value)
        if threat:
            return threat, field, value

    return None, None, None


def register_waf(app):
    """Attach the WAF as a before_request hook on the Flask app."""

    @app.before_request
    def waf_check():
        # skip OPTIONS (CORS preflight) - no user data in these
        if request.method == 'OPTIONS':
            return

        # skip the honeypot routes - we want to receive attacker input there
        if request.path in ('/admin-panel', '/wp-admin', '/wp-login.php', '/.env', '/phpmyadmin'):
            return

        threat, field, value = inspect_request()

        if threat:
            # log the blocked attack to the security logs
            try:
                entry = SecurityLog(
                    event_type=f'waf_blocked',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')[:300],
                    endpoint=request.path,
                    payload=f'[{threat}] Field: {field} | Value: {str(value)[:300]}',
                )
                db.session.add(entry)
                db.session.commit()
            except Exception:
                db.session.rollback()

            # return generic 403 - don't reveal what was detected
            return jsonify({
                'success': False,
                'message': 'Request blocked by security filter'
            }), 403
