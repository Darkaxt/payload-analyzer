"""Build a standalone, offline HTML incident report from a payload_analyzer JSON report.

Usage: python -I report_builder.py INPUT.json[.pax|.gz] -o REPORT.html [--ioc-top N]
       [--abuseipdb] [--ip-intel CACHE.json]

Only units whose effective_category is one of CATEGORIES (rce, file_access, sqli, xss, ssrf)
contribute attack content; all other units appear only as aggregate counts and as
"related crawling" (non-attack requests from attacking source IPs). All report data is embedded as XOR+base64 JSON and decoded by
inline JavaScript at load time; payload text is rendered with textContent only. Output is
deterministic for a given input (and IP-intel cache).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paxio  # noqa: E402
from payload_analyzer import _DATA as _SQL_DATA  # noqa: E402

_ERROR_CHANNEL = re.compile(_SQL_DATA['error_channel'], re.I)

# Determined attack categories in priority order: (key, label, badge colour; white text >= 4.5:1).
CATEGORIES = (
    ('rce', 'Remote command execution', '#b3261e'),
    ('file_access', 'File access', '#9a4f00'),
    ('sqli', 'SQL injection', '#3554a5'),
    ('xss', 'Cross-site scripting', '#2e7d32'),
    ('ssrf', 'Server-side request forgery', '#6a1b9a'),
)
ATTACK = tuple(c[0] for c in CATEGORIES)
LABELS = {c[0]: c[1] for c in CATEGORIES}
XOR_KEY = bytes(range(0x31, 0x31 + 29))
MAX_VALUE = 4000
PHASE_GAP_S = 2 * 3600
MAX_EXAMPLE = 300

# Evolution lanes per category, in the order an attack usually progresses.
LANES = {
    'sqli': ('syntax / boolean probing', 'column count', 'metadata enumeration', 'data extraction / inference'),
    'rce': ('template / recon probing', 'command execution', 'callback / download', 'file write'),
    'file_access': ('direct file read', 'path traversal', 'wrapper / scheme read', 'remote UNC path'),
    'xss': ('script injection',),
    'ssrf': ('internal / external URL request',),
}
_LANE_RULES = {
    'sqli': (('order_by_column_count', 1), ('union_select', 1), ('metadata_enumeration', 2),
             ('dictionary_query', 2), ('privilege_enumeration', 2), ('boolean_blind', 3),
             ('raw_select', 3), ('out_of_band', 3)),
    'rce': (('template_expression', 0), ('os_command_recon', 0), ('out_of_band', 2), ('download', 2),
            ('file_write', 3)),
    'file_access': (('path_traversal', 1), ('file_scheme', 2), ('wrapper', 2), ('unc_remote', 3)),
}

_IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])')
_URL = re.compile(r'\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s\'"<>()`]+')
_EMAIL = re.compile(r'\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b')
_UNC = re.compile(r'(?<![\w:\\])\\\\[A-Za-z0-9_.$-]+\\[^\s\'"<>|]+')

# DBMS dialect markers (pattern pieces are concatenated; matched on upper-cased text).
_DBMS = (
    ('Oracle', re.compile(r'\b(?:ALL|DBA|USER)_[A-Z_$]+\b|\bV\$[A-Z_]+|\bFROM\s+' + 'DUAL\\b|\\bSYS_' + r'CONTEXT\b'
                          r'|\bROWNUM\b|\bUTL_[A-Z_]+|\bDBMS_[A-Z_]+|\bNVL\s*\(|\bTO_CHAR\s*\(')),
    ('SQL Server', re.compile(r'\bSYS\.(?:OBJECTS|TABLES|COLUMNS|DATABASES)\b|\bWAIT' + r'FOR\s+DELAY\b|\bXP_[A-Z_]+'
                              r'|@@SERVERNAME|\bDB_NAME\s*\(|\bSYSOBJECTS\b|\bMASTER\.\.')),
    ('MySQL', re.compile(r'\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bLOAD_' + r'FILE\s*\(|\bGROUP_CONCAT\s*\(|\bDATABASE\s*\(\s*\)')),
    ('PostgreSQL', re.compile(r'\bPG_[A-Z_]+|\bCURRENT_DATABASE\s*\(|::TEXT\b')),
    ('ANSI information_schema', re.compile(r'\bINFORMATION_' + r'SCHEMA\b')),
)
_HINT_NAMES = {'oracle': 'Oracle', 'sql server': 'SQL Server', 'mssql': 'SQL Server', 'mysql': 'MySQL',
               'postgresql': 'PostgreSQL', 'postgres': 'PostgreSQL'}
_DICT = re.compile(r'^(?:[A-Z0-9_$]+\.)?(?:(?:ALL|DBA|USER|ROLE|SESSION)_|V\$|PG_)|^INFORMATION_' + r'SCHEMA\.|^SYS\.'
                   r'|^(?:DUAL|SYSOBJECTS|SYSCOLUMNS)$')
_FILTER = re.compile(r"\b(TABLE_NAME|OWNER|COLUMN_NAME|TABLE_SCHEMA|USERNAME|GRANTEE|OBJECT_NAME|GRANTED_ROLE|PRIVILEGE)"
                     r"\s*(?:=|LIKE|IN\s*\()\s*('(?:[^']{1,80})'(?:\s*,\s*'[^']{1,80}')*)", re.I)
_SESSION_VALUES = {'USER', 'CURRENT_USER', 'SESSION_USER', 'SYSTEM_USER', 'BANNER'}
_SQL_WORDS = {'AND', 'OR', 'IN', 'NOT', 'IS', 'LIKE', 'BETWEEN', 'EXISTS', 'SELECT', 'FROM', 'WHERE', 'NULL'}
_CMP = re.compile(r'\s*(>=|<=|<>|!=|=|>|<)\s*(\d{1,6})')


def parse_ts(text):
    if not text:
        return None
    t = str(text).strip()
    if len(t) > 10 and t[10] == 'T':
        t = t[:10] + ' ' + t[11:]
    if t.endswith(' UTC'):
        t = t[:-4]
    t = t.rstrip('Z')
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M'):
        try:
            return int(datetime.strptime(t[:26], fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def load_report(path):
    with paxio.open_text_in(path) as fh:
        return json.load(fh)


def short(uid):
    uid = str(uid or '')
    return uid.split('_', 1)[-1][:12] if uid else ''


def clip(text, n):
    text = ' '.join(str(text).split())
    return text if len(text) <= n else text[:n - 1] + '\u2026'


# ---------------------------------------------------------------- IOC extraction
_LOOPBACK = ('127.', '0.0.0.0', 'localhost', '::1')
_NOT_HOSTS = {'users', 'windows', 'program files', 'programdata', 'temp', 'system32', 'inetpub'}
_FILE_EXT = {'txt', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'ini', 'log', 'conf', 'cfg', 'xml', 'json', 'jsp',
             'php', 'asp', 'aspx', 'html', 'htm', 'js', 'exe', 'dll', 'bat', 'sh', 'zip', 'tmp', 'abc'}


# Host names written in free text (SQL string literals, database links, compared values...): a dotted name
# whose last label is a well-known generic TLD, or a two-letter country code with at least three labels, so
# schema.table, package.function and object.property names are not taken as hosts.
_HOST_TLD = {'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io', 'cloud', 'local', 'lan', 'corp',
             'internal', 'intra', 'intranet', 'arpa', 'invalid', 'example', 'test', 'localdomain'}
_TEXT_HOST = re.compile(r'(?<![\w$.-])((?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,})(?![\w$(.-])')


def text_hosts(text):
    out = set()
    for m in _TEXT_HOST.finditer(text):
        host = m.group(1).lower()
        labels = host.split('.')
        tld = labels[-1]
        if tld in _HOST_TLD or (len(tld) == 2 and len(labels) >= 3):
            out.add(host)
    return out


def _positions(text, sub):
    i = text.find(sub)
    while i >= 0:
        yield i
        i = text.find(sub, i + 1)


def _ioc_host(value):
    m = re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@]*@)?\[?([^/:\]?#]+)', value)
    return (m.group(1) if m else value).lower()


def _plausible_host(host):
    if _IPV4.fullmatch(host) or ':' in host:
        return True
    labels = host.split('.')
    return (len(labels) >= 2 and all(re.fullmatch(r'[a-z0-9_-]+', x) for x in labels)
            and labels[-1].isalpha() and labels[-1] not in _FILE_EXT)


def _keep(kind, value):
    if not value:
        return False
    if kind == 'url':
        if value.lower().startswith('file:'):
            return False
        host = _ioc_host(value)
    else:
        host = value.lower().lstrip('\\')
    if host.startswith(_LOOPBACK) or host in _NOT_HOSTS:
        return False
    return _plausible_host(host) if kind == 'host' else True


def main_entity(ioc):
    """Graph node for an indicator: the site or IP of a URL / UNC path, otherwise the value itself.
    None when no usable host remains (unparsable URL, loopback behind a userinfo trick...)."""
    kind, value = ioc
    if kind == 'email' and _IPV4.fullmatch(value.rsplit('@', 1)[-1]):
        kind = 'host'  # user@IP is a URL userinfo trick, not a mailbox
    if kind in ('url', 'unc', 'host', 'ip'):
        if kind == 'url' and not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]', value):
            return None
        host = _ioc_host(value) if kind == 'url' else value.lower().lstrip('\\').split('\\', 1)[0]
        host = host.rsplit('@', 1)[-1].strip('[]')
        kind = 'ip' if _IPV4.fullmatch(host) or ':' in host else 'host'
        if not re.search(r'[a-z0-9]', host) or not _keep(kind, host):
            return None
        return kind, host
    return kind, value


def target_entity(site, path):
    """Graph node for a target: the file name of the requested path (the site for the root path)."""
    parts = [x for x in str(path or '').split('/') if x]
    return parts[-1] if parts else (str(site or '') or '/')


def unit_iocs(unit, analysis):
    """External attacker indicators only; generic probe paths stay with techniques."""
    found = set()
    art = analysis.get('artifacts') or {}
    for v in art.get('urls') or []:
        found.add(('url', str(v)))
    for v in art.get('hosts') or []:
        found.add(('ip' if _IPV4.fullmatch(str(v)) else 'host', str(v)))
    text = str(unit.get('final_decoded_value') or '')
    for v in [str(x) for x in art.get('file_paths') or []] + _UNC.findall(text):
        if v.startswith('\\\\'):
            found.add(('unc', '\\\\' + v[2:].split('\\', 1)[0]))
    for rx, kind in ((_URL, 'url'), (_EMAIL, 'email'), (_IPV4, 'ip')):
        for m in rx.findall(text):
            found.add((kind, m.rstrip('.,;')))
    mail_domains = {v.rsplit('@', 1)[-1].lower() for k, v in found if k == 'email'}
    for h in text_hosts(text) - mail_domains:
        found.add(('host', h))
    if (unit.get('effective_category') or analysis.get('category')) == 'sqli':
        # In SQL, object@host outside a string literal is a database link: the host is the network
        # artifact, not a mailbox. An address inside quotes ('a@b.example') stays an email.
        for k, v in list(found):
            if k == 'email' and any(text[max(0, i - 1):i] not in ("'", '"') for i in _positions(text, v)):
                found.discard((k, v))
                found.add(('host', v.rsplit('@', 1)[-1].lower()))
    return {(k, v) for k, v in found if _keep(k, v)}


# Infrastructure type behind an address, from AbuseIPDB's usage type and Tor flag. It describes the network
# the address belongs to; a hosting or ISP address can still be a proxy or VPN exit (not established here).
_INFRA = (
    ('data center', 'hosting / datacenter'), ('web hosting', 'hosting / datacenter'),
    ('content delivery', 'CDN'), ('search engine', 'search engine crawler'),
    ('mobile', 'mobile carrier'), ('fixed line', 'residential / fixed-line ISP'),
    ('university', 'organisation network'), ('library', 'organisation network'),
    ('government', 'organisation network'), ('military', 'organisation network'),
    ('commercial', 'organisation network'), ('organization', 'organisation network'),
    ('reserved', 'reserved / private'),
)
INFRA_NOTE = {
    'Tor exit': 'anonymising relay: the real origin is hidden',
    'hosting / datacenter': 'rented server or VPS; commonly used as proxy or VPN exit',
    'residential / fixed-line ISP': 'home or office line; may also be a residential proxy',
    'mobile carrier': 'mobile network, usually shared (carrier NAT)',
    'CDN': 'content delivery network edge',
    'search engine crawler': 'search engine crawler network',
    'organisation network': 'company, public body or school network',
    'reserved / private': 'reserved or private range',
    'unknown': 'no usage type available',
}


def infra_type(info):
    if info.get('isTor'):
        return 'Tor exit'
    usage = str(info.get('usageType') or '').lower()
    for key, label in _INFRA:
        if key in usage:
            return label
    return 'unknown'


def intel_entry(info, roles):
    """Reduce one cached AbuseIPDB record to the fields shown in the report."""
    if info.get('error'):
        return {'error': str(info['error']), 'roles': list(roles)}
    return {'score': info.get('abuseConfidenceScore'), 'country': info.get('countryCode'),
            'isp': info.get('isp'), 'usage': info.get('usageType'), 'domain': info.get('domain'),
            'reports': info.get('totalReports'), 'users': info.get('numDistinctUsers'),
            'last': info.get('lastReportedAt'), 'tor': bool(info.get('isTor')), 'roles': list(roles),
            'infra': infra_type(info)}


# ---------------------------------------------------------------- SQL helpers
def _balanced(text, start):
    """Return index just past the parenthesis group opening at text[start] == '(' (or -1)."""
    depth, quote = 0, None
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch in '\'"':
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _split_args(inner):
    out, depth, cur, quote = [], 0, '', None
    for ch in inner:
        if quote:
            quote = None if ch == quote else quote
        elif ch in '\'"':
            quote = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
            continue
        cur += ch
    out.append(cur)
    return [a.strip() for a in out]


def _strip_parens(expr):
    expr = expr.strip()
    while expr.startswith('(') and _balanced(expr, 0) == len(expr):
        expr = expr[1:-1].strip()
    return expr


def _inference_comparison(text, end):
    """Allow redundant parentheses between a measured expression and its comparison."""
    if end < 0:
        return None
    closing = re.match(r'\s*\)*\s*', text[end:])
    return _CMP.match(text, end + closing.end())


def extract_inference(text):
    """Find blind-inference comparisons: (kind, expression, position, operator, threshold)."""
    found = []
    for m in re.finditer(r'\b(ASCII|UNICODE|ORD)\s*\(', text, re.I):
        end = _balanced(text, m.end() - 1)
        if end < 0:
            continue
        inner = text[m.end():end - 1].strip()
        sm = re.match(r'(SUBSTR|SUBSTRING|MID)\s*\(', inner, re.I)
        cmp_ = _CMP.match(text, end)
        if not sm or not cmp_:
            continue
        args = _split_args(inner[sm.end():_balanced(inner, sm.end() - 1) - 1])
        if len(args) >= 2 and args[1].isdigit():
            found.append(('char', clip(_strip_parens(args[0]), MAX_VALUE), int(args[1]), cmp_.group(1), int(cmp_.group(2))))
    for m in re.finditer(r'\b(LENGTH|LEN|CHAR_LENGTH)\s*\(', text, re.I):
        end = _balanced(text, m.end() - 1)
        cmp_ = _inference_comparison(text, end)
        if cmp_:
            found.append(('length', clip(_strip_parens(text[m.end():end - 1]), MAX_VALUE), 0, cmp_.group(1),
                          int(cmp_.group(2))))
    for m in re.finditer(r'\(\s*SELECT\s+COUNT\s*\(', text, re.I):
        end = _balanced(text, m.start())
        cmp_ = _inference_comparison(text, end)
        if cmp_:
            found.append(('count', clip(_strip_parens(text[m.start():end]), MAX_VALUE), 0, cmp_.group(1),
                          int(cmp_.group(2))))
    return found


def _sql_mask(text):
    """Mask comments only: a leading breakout quote need not be balanced."""
    return re.sub(r"--[^\r\n]*|/\*.*?\*/", lambda m: ' ' * len(m.group()), text, flags=re.S)


def extract_error_channel(text, expressions=False):
    """Return error functions and submitted nonconstant expressions, not observed results."""
    if not _ERROR_CHANNEL.search(text):
        return []
    masked = _sql_mask(text)
    found = []
    for call in _ERROR_CHANNEL.finditer(masked):
        end = _balanced(masked, call.end() - 1)
        if end < 0:
            continue
        name = text[call.start():call.end() - 1].strip()
        if name.upper() in ('CAST', 'CONVERT'):
            args = masked[call.end():end - 1]
            if not re.search(r'\b(?:AS\s+|^\s*)(?:INT(?:EGER)?|SIGNED|UNSIGNED|NUMERIC|DECIMAL)\b', args, re.I):
                continue
        queries = []
        # Only the call's own arguments have a known quote context.
        inner = re.sub(r"'(?:''|[^'])*'", lambda m: ' ' * len(m.group()), masked[call.end():end - 1])
        for sub in re.finditer(r'\(\s*SELECT\b', inner, re.I):
            start = call.end() + sub.start()
            stop = _balanced(masked, start)
            if stop < 0 or stop > end or any(a <= start < b for a, b in queries):
                continue
            queries.append((start, stop))
        submitted = [text[a + 1:b - 1] for a, b in queries]
        if not queries:
            for arg in _split_args(text[call.end():end - 1]):
                expr = _strip_parens(arg)
                constant = re.sub(r"'(?:''|[^'])*'|\bNULL\b|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", '', expr, flags=re.I)
                if re.search(r'[A-Za-z_$\"]', constant):
                    submitted.append(expr)
        if submitted:
            found.append((text[call.start():end] if expressions else name, submitted))
    return found


def error_channel_details(text, calls=None):
    """One deterministic entry per payload, retaining every submitted subquery."""
    if calls is None:
        calls = extract_error_channel(text)
    queries = [q for _, qs in calls for q in qs]
    objects, selectors = [], []
    for q in queries:
        objects.extend(m.group(1) for m in re.finditer(r'\b(?:FROM|JOIN)\s+([\w.$`"\[\]]+)', q, re.I))
        selectors.extend(m.group().strip() for m in re.finditer(
            r'\b(?:ROWNUM|R)\s*(?:<=|>=|=|<|>)\s*\d+|\b(?:OFFSET|LIMIT|TOP)\s*\(?\s*\d+(?:\s*,\s*\d+)?\)?(?:\s+OFFSET\s+\d+)?|'
            r"\bWHERE\s+[^()]+?(?=\b(?:ORDER\s+BY|GROUP\s+BY|LIMIT|OFFSET)\b|$)", q, re.I))
    return (', '.join(dict.fromkeys(n for n, _ in calls)), '\n\n'.join(queries),
            ', '.join(dict.fromkeys(objects)), '; '.join(dict.fromkeys(selectors)))


def derive_bounds(seq):
    """Bounds implied by an attacker's threshold sequence [(op, n), ...] in chronological order.

    Assumes adaptive (binary-search style) probing: a higher next threshold after "> n" means
    the condition held. Returns (lo, hi, consistent)."""
    lo, hi = 0, 1 << 20
    for (op, n), (_, nxt) in zip(seq, seq[1:]):
        if nxt == n:
            continue
        up = nxt > n
        if op in ('>', '>='):
            if up:
                lo = max(lo, n + 1 if op == '>' else n)
            else:
                hi = min(hi, n if op == '>' else n - 1)
        elif op in ('<', '<='):
            if up:
                lo = max(lo, n if op == '<' else n + 1)
            else:
                hi = min(hi, n - 1 if op == '<' else n)
    if seq and seq[-1][0] == '=' and lo <= seq[-1][1] <= hi:
        lo = hi = seq[-1][1]
    return lo, (None if hi == 1 << 20 else hi), lo <= (hi if hi is not None else lo)


def comparison_steps(seq):
    """Compact threshold sequence: '63\u2191 95\u2193 ... 65?'. The arrow is the direction of the attacker's
    next threshold (\u2191 higher, \u2193 lower); the answer to the last comparison is not in the log ('?')."""
    out = []
    for i, (op, n) in enumerate(seq):
        nxt = seq[i + 1][1] if i + 1 < len(seq) else None
        mark = '?' if nxt is None else ('' if nxt == n else ('\u2191' if nxt > n else '\u2193'))
        out.append(('' if op == '>' else op) + str(n) + mark)
    return ' '.join(out)


def char_candidates(lo, hi, ok):
    """Printable characters inside the derived bounds: one char, '[ab]' for up to four, '\u00b7' otherwise."""
    if not ok:
        return '!'
    if hi is None or not 32 <= lo <= hi < 127 or hi - lo > 3:
        return '\u00b7'
    return chr(lo) if lo == hi else '[' + ''.join(chr(x) for x in range(lo, hi + 1)) + ']'


_LITERAL = re.compile(r"^(?:SELECT\s+)?'([^']*)'$", re.I)


# ---------------------------------------------------------------- file-access helpers
def file_target(path):
    p = str(path)
    for _ in range(3):
        if '%' not in p:
            break
        p = unquote(p)
    p = p.replace('\\', '/')
    wrapper = ''
    m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]{1,15}):(?://)?', p)
    if m:
        wrapper, p = m.group(1).lower(), p[m.end():]
    unc = ''
    if p.startswith('//'):
        unc = p[2:].split('/', 1)[0]
    depth = len(re.findall(r'\.\.(?:/|$)', p))
    t = re.sub(r'^(?:\.{1,2}/|/)+', '/', re.sub(r'/+', '/', p.replace('/./', '/')))
    t = re.sub(r'(?:/\.\.)+(?=/|$)', '', t)
    if re.fullmatch(r'/?[a-zA-Z]:?', t) or t in ('', '/'):
        t = '(traversal only)'
    if re.match(r'^/?[a-zA-Z]:/', t) or 'windows/' in t.lower():
        osname = 'Windows'
    elif unc:
        osname = 'UNC'
    else:
        osname = 'Unix-like'
    return osname, t.lstrip('/') if osname == 'Windows' else t, depth, wrapper, unc


# Probing vs exploitation attempt (payload content only; says nothing about the outcome).
PHASES = ('probing', 'enumeration', 'extraction', 'exploitation')
# Commands whose only purpose is to show that execution happens (markers, delays, identity, callbacks).
_PROBE_PROGRAMS = {'sleep', 'echo', 'printf', 'ping', 'nslookup', 'dig', 'host', 'id', 'who' + 'ami', 'uname',
                   'hostname', 'expr', 'true', 'false', 'timeout', 'pwd', 'ver', 'set', 'type', 'cmd', 'sh', 'bash',
                   'ipconfig', 'ifconfig', 'dir', 'ls', 'date', 'time', 'netstat', 'findstr', 'grep', 'systeminfo',
                   'time.sleep', 'if'}
# Commands that act on the host or network (delete, fetch, read, copy, interpreters, persistence).
_ACTION_PROGRAMS = {'rm', 'del', 'rmdir', 'rd', 'erase', 'curl', 'wget', 'cat', 'tee', 'more', 'copy', 'move', 'mv',
                    'cp', 'chmod', 'chown', 'nc', 'ncat', 'power' + 'shell', 'pwsh', 'python', 'python3', 'perl', 'php',
                    'java', 'bits' + 'admin', 'cert' + 'util', 'scp', 'ftp', 'tftp', 'mkdir', 'reg', 'sc', 'schtasks',
                    'crontab', 'useradd', 'kill', 'taskkill', 'tar', 'unzip', 'base64', 'xcopy', 'robocopy', 'mshta',
                    'rundll32', 'regsvr32', 'wmic', 'type', 'head', 'tail', 'touch', 'dd', 'openssl'}
_ACTION_RULES = ('derby_export', 'file_read', 'web_shell')
# Canary files read to confirm a traversal works.
_CANARY_FILES = {'pass' + 'wd', 'group', 'hosts', 'issue', 'win' + '.ini', 'system.ini', 'boot.ini', 'hostname',
                 'version', 'os-release', 'lsb-release',
                 # bare directories: traversal depth probes
                 'etc', 'windows', 'system32', 'tmp', 'proc', 'boot', 'var', 'usr'}
# SELECT lists that only test existence or column count (COUNT(*), constants, NULL), not stored values.
_PROBE_SELECT = re.compile(r"^(?:COUNT\s*\(\s*(?:\*|1)\s*\)|NULL|-?\d+|'[^']*'|\s|,)+$")
_SELECT_FROM = re.compile(r'\bSELECT\s+(.*?)\s+FROM\s+([A-Z0-9_$.`"\[\]]+)', re.S)
_FROM = re.compile(r'\bFROM\s+([A-Z0-9_$.`"\[\]]+)')
_SQL_EXPLOIT = re.compile(r'\bINTO\s+(?:OUT|DUMP)' + r'FILE\b|\bLOAD_' + r'FILE\s*\(|\bXP_CMD' + r'SHELL\b|\bUTL_' + r'HTTP\b|\bCOPY\b.+\bPROGRAM\b')
_XSS_EXPLOIT = re.compile(r'document\s*\.\s*cookie|localStorage|sessionStorage|\bfetch\s*\(|XMLHttpRequest|'
                          r'\.src\s*=|src\s*=\s*["\']?(?:https?:)?//|location(?:\.href)?\s*=|\beval\s*\(|\batob\s*\(|'
                          r'new\s+Image\b|navigator\.sendBeacon', re.I)
_METADATA_HOSTS = ('169.254.169.254', 'metadata.google.internal', '100.100.100.200', 'fd00:ec2::254', '169.254.170.2')


def _size_measurement(expr):
    """Count/size aggregates, including wrappers, rather than stored values."""
    expr = _strip_parens(expr.strip())
    match = re.match(r'(COUNT|LENGTH|LEN|CHAR_LENGTH|MAX|MIN|NVL|COALESCE)\s*\(', expr, re.I)
    if not match or _balanced(expr, match.end() - 1) != len(expr):
        return False
    args = _split_args(expr[match.end():-1])
    if match.group(1).upper() in ('COUNT', 'LENGTH', 'LEN', 'CHAR_LENGTH'):
        return not re.search(r'\bSELECT\b', expr, re.I)
    return bool(args) and _size_measurement(args[0]) and all(
        _size_measurement(arg) or re.fullmatch(r"(?:NULL|[+-]?\d+(?:\.\d+)?|'(?:''|[^'])*')", arg, re.I)
        for arg in args[1:])


def phase_of(cat, lane, rules, analysis, text, error_calls=None):
    """'probing' (tests whether the injection point reacts, fingerprints, enumerates) or 'exploitation'
    (tries to read stored data or non-canary files, run non-diagnostic commands, download/write files,
    steal browser data or reach metadata services)."""
    art = analysis.get('artifacts') or {}
    up = text.upper()
    if cat == 'sqli':
        if error_calls is None:
            error_calls = extract_error_channel(text)
        if _SQL_EXPLOIT.search(up):
            return 'extraction'
        phases = []
        inference = extract_inference(text)
        # A measured scalar subquery is not a returned stored value. Scope the
        # channel before inspecting SELECTs nested inside it.
        spans = []
        for call in re.finditer(r'\b(?:ASCII|UNICODE|ORD|LENGTH|LEN|CHAR_LENGTH)\s*\(', text, re.I):
            end = _balanced(text, call.end() - 1)
            cmp_ = _inference_comparison(text, end)
            if cmp_ and extract_inference(text[call.start():cmp_.end()]):
                spans.append((call.start(), cmp_.end()))
        # Null predicates test existence, including balanced function calls and
        # scalar subqueries; do not mistake their inner SELECT for a returned value.
        for expr in re.finditer(r'\b[\w@$]+(?:\.[\w$]+)*\s*\(|\(', text):
            end = _balanced(text, expr.end() - 1)
            null = re.match(r'\s+IS\s+(?:NOT\s+)?NULL\b', text[end:], re.I) if end > 0 else None
            if null:
                spans.append((expr.start(), end + null.end()))
        remaining = ''.join(' ' if any(a <= i < b for a, b in spans) else ch
                            for i, ch in enumerate(text))
        existence = not error_calls and not re.search(r'\bUNION\b', up) and bool(re.search(
            r'\bEXISTS\s*\(|\bSELECT\s+(?:COUNT\s*\(\s*(?:\*|1)\s*\)|1)\s+FROM\b[^;]*?\)\s*(?:>|>=|=|<|<=|!=|<>)\s*[01](?![\d.])|\b1\s*=\s*\(\s*SELECT\s+1\s+FROM\b', up))
        # Look ahead so a scalar SELECT nested in an outer SELECT is considered too.
        for match in re.finditer(r'(?=\bSELECT\s+(.*?)\s+FROM\s+([A-Z0-9_$.`"\[\]]+))', up, re.S):
            if any(a <= match.start() < b for a, b in spans):
                continue
            cols, table = match.group(1).strip(), match.group(2).strip('`"[]')
            if 'SELECT' in cols:
                continue
            if cols.startswith('DISTINCT '):
                cols = cols[9:]
            if cols == '1' and re.search(r'\bIN\s*\(\s*$', up[:match.start()]):
                continue
            if existence and (_PROBE_SELECT.fullmatch(cols) or re.search(r'\bEXISTS\s*\(', up)):
                continue
            target = inference_target('SELECT ' + cols + ' FROM ' + table)
            measured = _size_measurement(cols)
            credential = (table in ('SYS.USER$', 'DBA_USERS', 'SYS.DBA_USERS', 'SYS.SQL_LOGINS')
                          and re.search(r'\b(?:PASSWORD|SPARE4|PASSWORD_HASH)\b', cols))
            if credential and not measured:
                phases.append('extraction')
                continue
            if target.startswith('stored data:'):
                phases.append('enumeration' if measured or _PROBE_SELECT.fullmatch(cols) else 'extraction')
            elif table in ('DUAL', 'SYSIBM.SYSDUMMY1'):
                if not _PROBE_SELECT.fullmatch(cols):
                    phases.append('enumeration')
            else:
                phases.append('enumeration')
        for kind, expr, _, _, threshold in inference:
            if re.fullmatch(r"(?:SELECT\s+)?(?:'(?:''|[^'])*'|[+-]?\d+(?:\.\d+)?|NULL)", _strip_parens(expr), re.I):
                continue
            if (existence and kind == 'count') or (threshold in (0, 1) and not error_calls):
                continue
            target = inference_target(expr)
            if target.startswith('stored data:'):
                phases.append('enumeration' if kind in ('length', 'count') else 'extraction')
            elif target != 'other expression':
                phases.append('enumeration')
        if 'extraction' in phases:
            return 'extraction'
        if existence and not phases:
            return 'probing'
        remaining = re.sub(r'(?:@@\w+|\b(?:USER|CURRENT_USER|SESSION_USER|VERSION))\s+IS\s+(?:NOT\s+)?NULL\b', '', remaining, flags=re.I)
        if phases or error_calls or re.search(r'\b(?:USER|CURRENT_USER|SYS_CONTEXT|VERSION)\b|@@\w+', remaining, re.I):
            return 'enumeration'
        return 'probing'
    if cat == 'rce':
        if 'rce.database_code_execution' in rules:
            calls = list(re.finditer(r'\bDBMS_' + r'JAVA(?:_TEST)?\s*\.\s*(RUNJAVA|FUNCALL|SET_OUTPUT_TO_JAVA)\s*\(', text, re.I))
            for match in calls:
                end = _balanced(text, match.end() - 1)
                args = _split_args(text[match.end():end - 1]) if end > 0 else []
                if args and (len(args) > 1 or re.search(r'\s', args[0].strip("'\" "))):
                    return 'exploitation'
            if re.search(r"\b(?:job_action|program_action)\s*=>\s*'[^']+'|\bJAVA\s+SOURCE\b", text, re.I):
                return 'exploitation'
            if re.search(r'\bselect\s*=\s*[\"\'][^\"\']*:[\w.-]+\s*\([^)]*[^\s()]', text, re.I):
                return 'exploitation'
            return 'probing'
        if lane == 'file write':
            return 'exploitation'
        if lane == 'callback / download':
            return 'exploitation' if any('download' in r for r in rules) else 'probing'
        if lane == 'command execution':
            progs = [str(seg.get('program') or '').lower().strip('()"\'`;|&/ ').rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
                     for seg in analysis.get('shell_segments') or []]
            progs = {x[:-4] if x.endswith('.exe') else x for x in progs}
            # Exploitation needs a recognised action (delete, fetch, read, copy, interpreter...) or a
            # file-writing export; markers, identity checks and unparsed fragments stay probing.
            if progs & _ACTION_PROGRAMS or any(f in r for r in rules for f in _ACTION_RULES):
                return 'exploitation'
            return 'probing'
        return 'probing'
    if cat == 'file_access':
        names = []
        for fp in [str(x) for x in art.get('file_paths') or []] or [text]:
            t = file_target(fp)[1]
            names.append(t.rstrip('/').rsplit('/', 1)[-1].lower() if t != '(traversal only)' else '')
        return 'probing' if all(n in _CANARY_FILES or not n for n in names) else 'exploitation'
    if cat == 'xss':
        return 'exploitation' if _XSS_EXPLOIT.search(text) else 'probing'
    if cat == 'ssrf':
        low = text.lower()
        if any(h in low for h in _METADATA_HOSTS) or re.search(r'\b(?:file|gopher|dict|ldap)://', low):
            return 'exploitation'
        return 'probing'
    return 'probing'


def lane_of(cat, rules):
    if cat == 'rce' and 'rce.database_code_execution' in rules:
        return 'command execution'
    lanes = LANES.get(cat, ('payload',))
    probes = ('template_expression', 'os_command_recon')
    best = 1 if cat == 'rce' and (not rules or any(not any(f in r for f in probes) for r in rules)) else 0
    for r in rules:
        for frag, idx in _LANE_RULES.get(cat, ()):
            if frag in r:
                best = max(best, idx)
    return lanes[min(best, len(lanes) - 1)]


def injected_sections(unit, analysis):
    """Evidence-scoped excerpts, computed once for each displayed attack unit."""
    nodes = unit.get('decoding_nodes') or []
    by_id = {n['node_id']: n for n in nodes}
    quotes = defaultdict(list)
    errors = set()
    for technique in analysis.get('techniques') or []:
        if str(technique.get('rule_id', '')).split('.', 1)[0] not in ATTACK:
            continue
        for evidence in technique.get('evidence') or []:
            nid, quote = evidence.get('node_id'), evidence.get('quote')
            if nid in by_id and quote and quote in by_id[nid].get('value', ''):
                if quote not in quotes[nid]:
                    quotes[nid].append(quote)
                if technique.get('rule_id') == 'sqli.error_based':
                    errors.add(nid)
    result, seen = [], set()
    plain_ancestors = set()
    for leaf in nodes:
        if leaf.get("transform") == "json_leaf_extract" and leaf["node_id"] in quotes:
            parent = leaf.get("parent_node_id")
            visited = set()
            while parent in by_id and parent not in visited:
                visited.add(parent)
                plain_ancestors.add(parent)
                parent = by_id[parent].get("parent_node_id")
    whole = str(unit.get('final_decoded_value') or unit.get('url_decoded_value') or '')

    class Number(str):
        pass

    def leaves(value, path=''):
        if isinstance(value, dict):
            for key, child in value.items():
                route = (path + '.' + key if re.fullmatch(r'[A-Za-z_$][\w$]*', key)
                         else path + '[' + json.dumps(key, ensure_ascii=False) + ']')
                yield from leaves(child, route.lstrip('.'))
        elif isinstance(value, list):
            for i, child in enumerate(value):
                yield from leaves(child, path + '[' + str(i) + ']')
        elif isinstance(value, str):
            if not isinstance(value, Number):
                try:
                    nested = json.loads(value, parse_int=Number, parse_float=Number)
                except (ValueError, TypeError, RecursionError):
                    nested = None
                if isinstance(nested, (dict, list)):
                    yield from leaves(nested, path)
                    return
            yield path, str(value)

    for node in sorted(nodes, key=lambda n: (n.get('transform') != 'json_leaf_extract', n['node_id'])):
        nid = node['node_id']
        if nid not in quotes:
            continue
        text = node['value']
        chain, visited, current = [], set(), node
        documents = []
        while current is not None and current['node_id'] not in visited:
            visited.add(current['node_id'])
            chain.append(str(current.get('transform') or current['node_id']))
            try:
                document = json.loads(current['value'], parse_int=Number, parse_float=Number)
                if isinstance(document, (dict, list)):
                    documents.append(list(leaves(document)))
            except (ValueError, TypeError, RecursionError):
                pass
            current = by_id.get(current.get('parent_node_id'))
        layer = ' -> '.join(reversed(chain)) if node.get('parent_node_id') is not None else ''
        selected = []
        for document in documents:
            selected = [(path, value) for path, value in document
                        if any(q in value for q in quotes[nid])]
            if selected:
                break
        if not selected and nid in plain_ancestors:
            continue
        if not selected and nid in errors:
            selected = [('', call) for call, _ in extract_error_channel(text, expressions=True)
                        if any(q in call for q in quotes[nid])]
        if not selected:
            try:
                parsed = json.loads(text)
            except (ValueError, TypeError, RecursionError):
                parsed = None
            if isinstance(parsed, (dict, list)) or nid in plain_ancestors:
                continue
            first = min(i for q in quotes[nid] for i in _positions(text, q))
            breakout = next((i for i, ch in enumerate(text[:first + 1])
                             if ch in "'\"`;|&$()<>{}"), None)
            start = first if breakout is None else breakout
            if breakout is None:
                while start and not text[start - 1].isspace():
                    start -= 1
                while start < len(text) and text[start].isspace():
                    start += 1
            section = text[start:]
            if section.strip().strip("[]{}") == text.strip().strip("[]{}"):
                continue
            selected = [('', section)]
        for path, value in selected:
            if nid in errors and not path:
                calls = extract_error_channel(value, expressions=True)
                if calls:
                    value = '\n\n'.join(dict.fromkeys(call for call, _ in calls))
            rendered = (path + ': ' if path else '') + value
            if rendered == whole or rendered in seen:
                continue
            seen.add(rendered)
            result.append({'text': rendered, 'layer': layer})
    return result


# ---------------------------------------------------------------- model
def build_model(report, ioc_top=40, intel=None):
    meta = report.get('meta') or {}
    units = report.get('units') or []
    unrelated = Counter()
    rows, raw_units, events, tech_names = [], [], Counter(), {}
    ioc_units = defaultdict(set)
    ioc_rules = defaultdict(Counter)
    ioc_targets = defaultdict(Counter)
    src_ips = Counter()
    src_targets = defaultdict(lambda: defaultdict(set))
    activity = []  # (ts, is_attack, requests, ips)
    for unit in units:
        cat = unit.get('effective_category')
        if cat not in ATTACK:
            unrelated[str(cat)] += 1
            for occ in unit.get('occurrences') or []:
                act = occ.get('activity') or {}
                ts = parse_ts(act.get('first_seen') or unit.get('first_seen'))
                if ts is not None:
                    activity.append((ts, 0, int(act.get('request_count') or 1), tuple(act.get('source_ips') or ())))
            continue
        analysis = unit.get('analysis') or {}
        for t in analysis.get('techniques') or []:
            if t.get('rule_id') and t.get('name'):
                tech_names.setdefault(t['rule_id'], t['name'])
        raw_units.append((unit, analysis))

    # Dominant technique per parameter, used to describe inferred related payloads.
    dom = defaultdict(Counter)
    for unit, analysis in raw_units:
        for occ in unit.get('occurrences') or []:
            tg = occ.get('target') or {}
            for r in analysis.get('rule_ids') or []:
                dom[(tg.get('site'), tg.get('uri_path'), unit.get('parameter_name'), unit.get('effective_category'))][r] += 1

    for unit, analysis in raw_units:
        cat = unit['effective_category']
        rules = sorted(analysis.get('rule_ids') or [])
        own = analysis.get('category') or ''
        occs = unit.get('occurrences') or []
        targets, ips, reqs, statuses, lines = set(), set(), 0, set(), []
        first_ts = None
        for occ in occs:
            tg = occ.get('target') or {}
            targets.add((str(tg.get('site') or ''), str(tg.get('uri_path') or '')))
            act = occ.get('activity') or {}
            n = int(act.get('request_count') or 1)
            reqs += n
            ips.update(str(ip) for ip in act.get('source_ips') or [])
            statuses.update(str(s) for s in act.get('statuses') or [])
            lines.append(int(occ.get('source_jsonl_line') or 0))
            ts = parse_ts(act.get('first_seen') or unit.get('first_seen'))
            if ts is not None:
                first_ts = ts if first_ts is None else min(first_ts, ts)
                activity.append((ts, 1, n, tuple(act.get('source_ips') or ())))
        targets = sorted(targets) or [('', '')]
        related = ''
        if not rules:
            c = Counter()
            for s, p in targets:
                c.update(dom.get((s, p, unit.get('parameter_name'), cat), {}))
            top = sorted(c.items(), key=lambda x: (-x[1], x[0]))
            related = 'related:' + (top[0][0] if top else cat)
            if related not in tech_names:
                base = tech_names.get(top[0][0], top[0][0]) if top else LABELS[cat]
                tech_names[related] = 'related to ' + base + ' payloads on the same parameter'
        eff_rules = rules or [related]
        lane_rules = rules or ([related[8:]] if related[8:] in tech_names else [])
        primary = eff_rules[0]
        value = str(unit.get('final_decoded_value') or unit.get('url_decoded_value') or '')
        error_calls = extract_error_channel(value, expressions=True) if cat == 'sqli' else []
        lane = lane_of(cat, lane_rules)
        phase = phase_of(cat, lane, eff_rules, analysis, value, error_calls)
        if cat == 'sqli' and phase in ('enumeration', 'extraction'):
            lane = LANES['sqli'][2 if phase == 'enumeration' else 3]
        for occ in occs:
            tg = occ.get('target') or {}
            act = occ.get('activity') or {}
            ts = parse_ts(act.get('first_seen') or unit.get('first_seen'))
            if ts is not None:
                src = ', '.join(sorted(str(ip) for ip in act.get('source_ips') or [])) or 'unknown'
                events[(ts // 60 * 60, cat, primary, str(tg.get('site') or '') + str(tg.get('uri_path') or ''), src, phase,
                        short(unit.get('unit_id')))] += int(act.get('request_count') or 1)
        uid = short(unit.get('unit_id'))
        for ip in ips:
            src_ips[ip] += reqs
            for s_, p_ in targets:
                src_targets[ip][target_entity(s_, p_)].add(uid)
        rows.append({
            'id': uid, 'cat': cat, 'own': own, 'related': bool(related),
            'site': targets[0][0], 'path': targets[0][1], 'ntargets': len(targets),
            'param': str(unit.get('parameter_name') or ''), 'rules': eff_rules,
            'summary': str(analysis.get('summary') or ''),
            'first': str(unit.get('first_seen') or ''), 'last': str(unit.get('last_seen') or ''),
            'ts': first_ts or 0, 'count': reqs, 'ips': sorted(ips), 'statuses': sorted(statuses),
            'value': value, 'truncated': False, 'injected': injected_sections(unit, analysis),
            'lane': lane, 'phase': phase, '_line': min(lines) if lines else 0,
            '_analysis': analysis, '_targets': targets, '_full': value, '_error_calls': error_calls,
        })
        for ioc in sorted({main_entity(i) for i in unit_iocs(unit, analysis)} - {None}):
            ioc_units[ioc].add(uid)
            for r in eff_rules:
                ioc_rules[ioc][r] += 1
            for t in {target_entity(s, p) for s, p in targets}:
                ioc_targets[ioc][t] += 1
    rows.sort(key=lambda r: (r['first'], r['cat'], r['site'], r['path'], r['param'], r['id']))

    # [minute, category, technique, target, requests, source IPs, phase, [[payload id, requests], ...]]
    ev_ids = defaultdict(Counter)
    for k, n in events.items():
        ev_ids[k[:6]][k[6]] += n
    ev = sorted([k[0], k[1], k[2], k[3], sum(c.values()), k[4], k[5], sorted([u, n] for u, n in c.items())]
                for k, c in ev_ids.items())
    phases = []
    for e in ev:
        if not phases or e[0] - phases[-1]['end'] > PHASE_GAP_S:
            phases.append({'start': e[0], 'end': e[0], 'cats': Counter(), 'rules': Counter(), 'targets': set()})
        ph = phases[-1]
        ph['end'] = e[0]
        ph['cats'][e[1]] += e[4]
        ph['rules'][e[2]] += e[4]
        ph['targets'].add(e[3])
    phases = [{'start': p['start'], 'end': p['end'] + 59, 'cats': dict(sorted(p['cats'].items())),
               'rules': sorted(p['rules'].items(), key=lambda x: (-x[1], x[0]))[:5],
               'targets': len(p['targets'])} for p in phases]

    campaigns, evolution = build_evolution(rows)
    graph = build_graph(rows, ioc_units, ioc_rules, ioc_targets, src_targets, ioc_top)
    for r in rows:
        for k in [k for k in r if k.startswith('_')]:
            del r[k]

    cat_counts = {c: sum(1 for r in rows if r['cat'] == c) for c in ATTACK}
    req_counts = {c: sum(r['count'] for r in rows if r['cat'] == c) for c in ATTACK}
    model = {
        'meta': {k: meta.get(k) for k in ('generated_at', 'analyzer_version', 'rule_catalogue_version',
                                            'source_sha256', 'units_total')},
        'labels': LABELS, 'cats': [list(c) for c in CATEGORIES], 'lanes': {k: list(v) for k, v in LANES.items()},
        'tech_names': dict(sorted(tech_names.items())),
        'scope': {
            'first': min((r['first'] for r in rows if r['first']), default=''),
            'last': max((r['last'] for r in rows if r['last']), default=''),
            'sites': sorted({r['site'] for r in rows}),
            'endpoints': len({(r['site'], r['path']) for r in rows}),
            'params': len({(r['site'], r['path'], r['param']) for r in rows}),
            'units': cat_counts, 'requests': req_counts,
            'related': sum(1 for r in rows if r['related']),
            'unrelated': sum(unrelated.values()), 'campaigns': len(campaigns),
            'source_ips': [[ip, n] for ip, n in sorted(src_ips.items(), key=lambda x: (-x[1], x[0]))[:20]],
            'source_ip_total': len(src_ips),
        },
        'phases': phases, 'units': rows, 'events': ev, 'crawl': related_crawling(activity),
        'campaigns': campaigns, 'evo': evolution, 'graph': graph,
    }
    if intel is not None:
        model['intel'] = intel
        model['infra_note'] = INFRA_NOTE
        model['src_all'] = sorted(src_ips)
    return model


def related_crawling(activity):
    """Hourly non-attack requests sent by source IPs that also sent attack payloads (the shadow on the timeline)."""
    attackers = {ip for _, attack, _, ips in activity if attack for ip in ips}
    hours, other = {}, 0
    for ts, attack, n, ips in activity:
        if attack:
            continue
        own = attackers.intersection(ips)
        if not own:
            other += n
            continue
        h = hours.setdefault(ts // 3600 * 3600, [0, Counter()])
        h[0] += n
        for ip in sorted(own):
            h[1][ip] += n
    return {'hours': [[t, n, sorted(ips), [ips[i] for i in sorted(ips)]] for t, (n, ips) in sorted(hours.items())],
            'requests': sum(h[0] for h in hours.values()), 'other_requests': other}


def _merge_campaigns(rows):
    """Campaign = site+path+parameter; merged with others on the same site that were worked on by
    exactly the same source IPs within two hours of each other (activity windows chained)."""
    keys = defaultdict(list)
    for i, r in enumerate(rows):
        keys[(r['site'], r['path'], r['param'])].append(i)
    spans = {k: (min(rows[i]['ts'] for i in v), max(rows[i]['ts'] for i in v)) for k, v in keys.items()}
    groups, open_groups = [], {}
    for k in sorted(keys, key=lambda k: (spans[k][0], k)):
        ipset = frozenset(ip for i in keys[k] for ip in rows[i]['ips'])
        sig = (k[0], ipset)
        g = open_groups.get(sig) if ipset else None
        if g is not None and spans[k][0] - g['last'] <= PHASE_GAP_S:
            g['idx'].extend(keys[k])
            g['last'] = max(g['last'], spans[k][1])
        else:
            g = {'idx': list(keys[k]), 'last': spans[k][1]}
            groups.append(g)
            if ipset:
                open_groups[sig] = g
    return [sorted(g['idx'], key=lambda i: (rows[i]['ts'], rows[i]['_line'], rows[i]['id'])) for g in groups]


def _top(counter, n):
    return [k for k, _ in sorted(counter.items(), key=lambda x: (-x[1], x[0]))[:n]]


def _names(items, n=4):
    items = list(items)
    s = ', '.join(items[:n])
    return s + (' and {} more'.format(len(items) - n) if len(items) > n else '')


def build_evolution(rows):
    groups = sorted(_merge_campaigns(rows), key=lambda g: (rows[g[0]]['ts'], rows[g[0]]['site'], rows[g[0]]['id']))
    campaigns = []
    evo = {k: [] for k in ('dbms', 'objects', 'inference', 'strings', 'commands', 'callbacks', 'rfiles', 'files', 'xss',
                           'ssrf', 'error_channel')}
    for n, g in enumerate(groups, 1):
        cid = 'C{:02d}'.format(n)
        us = [rows[i] for i in g]
        for u in us:
            u['camp'] = cid
        c = analyse_campaign(cid, us)
        campaigns.append(c['card'])
        for k in evo:
            evo[k].extend(c[k])
    return campaigns, evo


def _bump(table, key, ts, n=1, extra=None, uid=None):
    e = table.get(key)
    if e is None:
        e = table[key] = {'first': ts, 'last': ts, 'n': 0, 'x': set(), 'u': set()}
    e['first'], e['last'] = min(e['first'], ts), max(e['last'], ts)
    e['n'] += n
    if uid:
        e['u'].add(uid)
    if extra:
        e['x'].update(extra)
    return e


def _uids(v):
    return sorted(v['u'])


_FINGERPRINT = re.compile(r"^(?:@@\w+|(?:VERSION|USER|CURRENT_USER|SESSION_USER|SYSTEM_USER|DATABASE|SCHEMA|DB_NAME|"
                          r"USER_NAME|CURRENT_DATABASE|CURRENT_SCHEMA)(?:\s*\(\s*\))?|(?:SELECT\s+)?'[^']*'|\d+)$", re.I)
_SCHEMA_ENUM = re.compile(r'\b(?:information_schema|schemata|all_tables|all_tab_columns|user_tables|sysobjects|'
                          r'syscolumns|sqlite_master|pg_catalog|pg_tables|mysql\.)', re.I)


def inference_target(expr):
    """What a blind-inference expression reads: environment fingerprint, schema enumeration or stored data."""
    e = expr.strip()
    if _FINGERPRINT.match(e):
        return 'environment fingerprint'
    if _SCHEMA_ENUM.search(e):
        return 'schema enumeration'
    m = re.search(r'\bFROM\s+([\w.$`"\[\]]+)', e, re.I)
    if m:
        t = m.group(1).strip('`"[]')
        return 'schema enumeration' if _DICT.search(t.upper()) else 'stored data: ' + t
    return 'other expression'


def _rows_out(cid, table, fmt, omitted, name):
    items = sorted(table.items(), key=lambda kv: (kv[1]['first'], str(kv[0])))
    return [[cid] + fmt(k, v) + [_uids(v)] for k, v in items]


def analyse_campaign(cid, us):
    dbms, objects, infer, cmds, cbs, rfiles, files, xss, ssrf = {}, {}, {}, {}, {}, {}, {}, {}, {}
    error_rows = []
    dbms_markers = defaultdict(Counter)
    lanes, examples = Counter(), defaultdict(list)
    example_sections = defaultdict(list)
    for u in us:
        a, text, ts, cat = u['_analysis'], u['_full'], u['ts'], u['cat']
        art = a.get('artifacts') or {}
        up = text.upper()
        lane = cat + '|' + u['lane']
        lanes[(lane, ts // 60 * 60)] += u['count']
        if len(examples[lane]) < 3 and clip(text, MAX_EXAMPLE) not in examples[lane]:
            examples[lane].append(clip(text, MAX_EXAMPLE))
            example_sections[lane].append(u['injected'])
        if cat == 'sqli':
            if u['_error_calls']:
                error_rows.append([cid, ts, u['count'], ', '.join(u['statuses']),
                                   *error_channel_details(text, u['_error_calls']), u['phase'], [u['id']]])
            hint = _HINT_NAMES.get(str(a.get('dbms_hint') or '').lower())
            seen = set()
            if hint:
                seen.add(hint)
                dbms_markers[hint]['analyzer hint'] += 1
            for name, rx in _DBMS:
                for m in rx.findall(up)[:3]:
                    seen.add(name)
                    dbms_markers[name][clip(m, 30)] += 1
            for name in seen:
                _bump(dbms, name, ts, uid=u['id'])
            for o in art.get('db_objects') or []:
                o = str(o)
                kind = ('server variable' if o.startswith('@@') else 'function call' if '(' in o
                        else 'dictionary view' if _DICT.search(o.upper())
                        else 'session value' if o.upper() in _SESSION_VALUES else 'table / view')
                _bump(objects, (kind, o), ts, uid=u['id'])
                if '.' in o and kind != 'dictionary view':
                    _bump(objects, ('schema', o.split('.', 1)[0]), ts, uid=u['id'])
            for f in art.get('functions') or []:
                if str(f).upper() not in _SQL_WORDS:
                    _bump(objects, ('function', str(f).upper()), ts, uid=u['id'])
            for m in _FILTER.finditer(text):
                for lit in re.findall(r"'([^']*)'", m.group(2)):
                    _bump(objects, ('name filter: ' + m.group(1).lower(), lit), ts, uid=u['id'])
            for kind, expr, pos, op, thr in extract_inference(text):
                e = _bump(infer, (kind, expr, pos), ts, uid=u['id'], extra=u['statuses'])
                e.setdefault('seq', []).append((ts, u['_line'], op, thr, u['id']))
        elif cat == 'rce':
            for seg in a.get('shell_segments') or []:
                line = clip(' '.join([str(seg.get('program') or '')] + [str(x) for x in seg.get('arguments') or []]), MAX_VALUE)
                _bump(cmds, (line, str(seg.get('family') or '')), ts, uid=u['id'])
            if not a.get('shell_segments'):
                for cmd in art.get('commands') or []:
                    _bump(cmds, (clip(cmd, MAX_VALUE), ''), ts, uid=u['id'])
            if any('template_expression' in r for r in u['rules']):
                _bump(cmds, (clip(text, MAX_VALUE), 'template expression probe'), ts, uid=u['id'])
            for kind, v in sorted(unit_iocs({'final_decoded_value': text}, a)):
                _bump(cbs, (kind, v), ts, uid=u['id'])
            if any(f in r for r in u['rules'] for f in ('file_write', 'download', 'file_read')):
                for p in art.get('file_paths') or []:
                    how = 'written' if any('file_write' in r for r in u['rules']) else (
                        'downloaded' if any('download' in r for r in u['rules']) else 'read')
                    _bump(rfiles, (clip(p, MAX_VALUE), how), ts, uid=u['id'])
        elif cat == 'file_access':
            paths = [str(p) for p in art.get('file_paths') or []] or [text]
            for p in paths:
                osname, target, depth, wrapper, unc = file_target(p)
                e = _bump(files, (osname, clip(target, MAX_VALUE)), ts, uid=u['id'])
                e['depth'] = max(e.get('depth', 0), depth)
                e.setdefault('wr', set()).update([wrapper] if wrapper else [])
                e.setdefault('unc', set()).update([unc] if unc else [])
        elif cat == 'xss':
            _bump(xss, (u['param'], clip(text, MAX_VALUE)), ts, uid=u['id'], extra=u['rules'])
        elif cat == 'ssrf':
            urls = sorted({str(x) for x in art.get('urls') or []} | set(_URL.findall(text))) or [text]
            for url in urls:
                m = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?', url)
                scheme, host, port = (m.group(1).lower(), m.group(2), m.group(3) or '') if m else ('', '', '')
                _bump(ssrf, (u['param'], clip(url, MAX_VALUE), host, port, scheme), ts, uid=u['id'])
    error_rows.sort(key=lambda r: (r[0], r[1], r[5], r[-1][0]))
    omitted = {}
    out = {
        'error_channel': error_rows,
        'dbms': _rows_out(cid, dbms, lambda k, v: [k, v['n'], v['first'], v['last'],
                                                   ', '.join(_top(dbms_markers[k], 5))], omitted, 'dbms'),
        'objects': _rows_out(cid, objects, lambda k, v: [k[0], k[1], v['first'], v['last'], v['n']], omitted, 'objects'),
        'commands': _rows_out(cid, cmds, lambda k, v: [k[0], k[1], v['first'], v['last'], v['n']], omitted, 'commands'),
        'callbacks': _rows_out(cid, cbs, lambda k, v: [k[0], k[1], v['first'], v['last'], v['n']], omitted, 'callbacks'),
        'rfiles': _rows_out(cid, rfiles, lambda k, v: [k[0], k[1], v['first'], v['last'], v['n']], omitted, 'rfiles'),
        'files': _rows_out(cid, files, lambda k, v: [k[0], k[1], v['depth'], ', '.join(sorted(v['wr'])),
                                                    ', '.join(sorted(v['unc'])), v['first'], v['last'], v['n']],
                           omitted, 'files'),
        'ssrf': _rows_out(cid, ssrf, lambda k, v: [k[0], k[1], k[2], k[3], k[4], v['first'], v['last'], v['n']],
                          omitted, 'ssrf'),
        'xss': _rows_out(cid, xss, lambda k, v: [k[0], k[1], ', '.join(sorted(v['x'])), v['first'], v['last'], v['n']],
                         omitted, 'xss'),
    }
    inf_rows, by_expr = [], defaultdict(dict)
    vals = defaultdict(lambda: {'pos': [], 'n': 0, 'first': None, 'last': None, 'u': set(), 'b': {}})
    for (kind, expr, pos), v in infer.items():
        ordered = sorted(v['seq'])
        seq = [(op, thr) for _, _, op, thr, _ in ordered]
        lo, hi, ok = derive_bounds(seq)
        e = vals[expr]
        e['n'] += len(seq)
        e['first'] = v['first'] if e['first'] is None else min(e['first'], v['first'])
        e['last'] = v['last'] if e['last'] is None else max(e['last'], v['last'])
        e['u'].update(v['u'])
        rng = ('{}'.format(lo) if hi == lo else '{}..{}'.format(lo, '?' if hi is None else hi)) if ok else 'inconsistent'
        cand = char_candidates(lo, hi, ok) if kind == 'char' else rng
        e['pos'].append([(0 if kind == 'length' else 1 if kind == 'count' else 2, pos), kind, pos, cand, rng,
                         comparison_steps(seq), v['first']])
        e['b'][(kind, pos)] = (lo, hi, ok)
        thr = [t for _, t in seq]
        guess = ''
        if kind == 'char' and ok and hi is not None and lo == hi and 32 <= lo < 127:
            guess = chr(lo)
            by_expr[expr][pos] = guess
        elif kind == 'char' and ok and hi is not None and 32 <= lo <= hi < 127 and hi - lo <= 8:
            guess = chr(lo) + '..' + chr(hi)
            by_expr[expr][pos] = '[' + ''.join(chr(x) for x in range(lo, hi + 1)) + ']' if hi - lo <= 2 else '?'
        bound = ('{}'.format(lo) if hi == lo else '{}..{}'.format(lo, hi if hi is not None else '?')) if ok else 'inconsistent'
        inf_rows.append([cid, kind, expr, pos, len(seq), '{}..{}'.format(min(thr), max(thr)), bound, guess,
                         ', '.join(sorted(v['x'])), v['first'], v['last'], inference_target(expr),
                         [[t, op, thr, uid] for t, _, op, thr, uid in ordered], _uids(v)])
    inf_rows.sort(key=lambda r: (r[1], r[2], r[3]))
    strings = []
    for expr, e in sorted(vals.items()):
        cand = {x[2]: x[3] for x in e['pos'] if x[1] == 'char'}
        value = ''.join(cand.get(i, '\u00b7') for i in range(1, max(cand) + 1)) if cand else ''
        length = ', '.join('{} {}'.format(x[1], x[4]) for x in sorted(e['pos']) if x[1] != 'char')
        lit = _LITERAL.match(expr)
        if lit and cand:  # the attacker's own check string: its known characters must sit inside the bounds
            known, bad = lit.group(1), []
            for i in sorted(cand):
                lo, hi, ok = e['b'][('char', i)]
                if i > len(known) or not ok or not lo <= ord(known[i - 1]) <= (lo if hi is None else hi):
                    bad.append(i)
            value += '  (check string {!r}: {})'.format(known, 'every position within bounds' if not bad else
                                                        'outside bounds at ' + ', '.join(map(str, bad)))
        detail = [[x[1], x[2], x[3], x[4], x[5], x[6]] for x in sorted(e['pos'])]
        strings.append([cid, inference_target(expr), expr, value, length, len(cand), e['n'], e['first'], e['last'],
                        sorted(e['u']), None, detail])
    strings.sort(key=lambda r: (r[7], r[2]))
    out['inference'], out['strings'] = inf_rows, strings

    first, last = us[0]['ts'], max(u['ts'] for u in us)
    ips = sorted({ip for u in us for ip in u['ips']})
    params = sorted({u['param'] for u in us})
    paths = sorted({u['path'] for u in us})
    cats = Counter(u['cat'] for u in us)
    card = {
        'id': cid, 'site': us[0]['site'], 'paths': paths, 'params': params, 'ips': ips,
        'first': first, 'last': last, 'units': len(us), 'requests': sum(u['count'] for u in us),
        'cats': {c: cats[c] for c in ATTACK if cats[c]},
        'lanes': sorted([k[0], k[1], n] for k, n in lanes.items()),
        'examples': {k: v for k, v in sorted(examples.items())},
        'example_sections': dict(sorted(example_sections.items())), 'omitted': omitted,
        'narrative': narrative(us, out, ips, params, paths, first, last),
    }
    out['card'] = card
    return out


def _when(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def narrative(us, out, ips, params, paths, first, last):
    src = ('source ' + _names(ips, 3)) if ips else 'unrecorded sources'
    s = ['Between {} and {}, {} sent {} attack payload(s) in {} request(s) to parameter(s) {} on {}{}.'.format(
        _when(first), _when(last), src, len(us), sum(u['count'] for u in us), _names(params, 3),
        us[0]['site'], _names(paths, 3))]
    order = []
    for u in us:
        if u['cat'] not in order:
            order.append(u['cat'])
    for cat in order[:3]:
        cu = [u for u in us if u['cat'] == cat]
        stages = []
        for u in cu:
            if u['lane'] not in stages:
                stages.append(u['lane'])
        if cat == 'sqli':
            views = [r[2] for r in out['objects'] if r[1] == 'dictionary view']
            tables = [r[2] for r in out['objects'] if r[1] == 'table / view']
            names = [r[2] for r in out['objects'] if r[1] in ('name filter: table_name', 'name filter: column_name',
                                                               'name filter: owner', 'name filter: table_schema')]
            dbms = [r[1] for r in out['dbms'] if r[1] != 'ANSI information_schema']
            t = 'SQL injection stages appeared in this order: ' + ' \u2192 '.join(stages)
            if dbms:
                t += ', using {} dialect features'.format(_names(dbms, 2))
            if views:
                t += ', queried {}'.format(_names(sorted(set(views)), 4))
            if tables:
                t += ', referenced tables {}'.format(_names(sorted(set(tables)), 4))
            if names:
                t += ' and filtered on names {}'.format(_names(sorted(set(names)), 4))
            if out['strings']:
                t += '; blind comparisons probed values of {}'.format(_names(sorted({r[2] for r in out['strings']}), 2))
            s.append(t + '.')
        elif cat == 'rce':
            progs = [r[1] for r in out['commands'] if r[2] != 'template expression probe']
            t = 'Command execution payloads (stages: {}) '.format(' \u2192 '.join(stages))
            t += 'invoked {}'.format(_names(progs, 4)) if progs else 'used template-expression probes'
            if out['callbacks']:
                t += ' and referenced external {}'.format(_names([r[2] for r in out['callbacks']], 3))
            s.append(t + '.')
        elif cat == 'file_access':
            fs = [r[2] for r in out['files']]
            depth = max([r[3] for r in out['files']] or [0])
            s.append('File access payloads requested {}{}.'.format(
                _names(fs, 4), ' with traversal depth up to {}'.format(depth) if depth else ''))
        elif cat == 'ssrf':
            s.append('Request-forgery payloads asked the server to fetch {}.'.format(
                _names(sorted({r[3] + (':' + r[4] if r[4] else '') for r in out['ssrf'] if r[3]}), 4) or 'URLs'))
        elif cat == 'xss':
            s.append('{} script injection vector(s) were sent to parameter(s) {}.'.format(
                len(out['xss']), _names(sorted({r[1] for r in out['xss']}), 3)))
    return s[:4]


def build_graph(rows, ioc_units, ioc_rules, ioc_targets, src_targets, ioc_top, max_src=20, max_targets=40):
    """Layered graph: column 0 source IPs, 1 targets, 2 payload indicators, 3 techniques.

    Node: [kind, label, column, payload count, unit row indices]; link: [a, b, weight].
    """
    pos = {r['id']: i for i, r in enumerate(rows)}
    by_rule = defaultdict(set)
    by_target = defaultdict(set)
    for r in rows:
        for s, p in r.get('_targets') or [(r['site'], r['path'])]:
            by_target[target_entity(s, p)].add(r['id'])
        for rule in r['rules']:
            by_rule[rule].add(r['id'])
    ranked = sorted(ioc_units, key=lambda k: (-len(ioc_units[k]), k))[:ioc_top]
    srcs = sorted(src_targets, key=lambda ip: (-sum(len(v) for v in src_targets[ip].values()), ip))[:max_src]
    tw = Counter()
    for ip in srcs:
        for t, ids in src_targets[ip].items():
            tw[t] += len(ids)
    for ioc in ranked:
        for t, n in ioc_targets[ioc].items():
            tw[t] += n
    keep_t = set(sorted(tw, key=lambda t: (-tw[t], t))[:max_targets])
    nodes, links, index = [], [], {}

    def node(key, kind, label, col, ids):
        if key not in index:
            index[key] = len(nodes)
            nodes.append([kind, label, col, len(ids), sorted(pos[i] for i in ids if i in pos)])
        return index[key]

    for ip in srcs:
        a = node('s:' + ip, 'source_ip', ip, 0, set().union(*src_targets[ip].values()))
        for t, tids in sorted(src_targets[ip].items()):
            if t in keep_t:
                links.append([a, node('t:' + t, 'target', t, 1, by_target[t]), len(tids)])
    for ioc in ranked:
        a = node('i:' + ioc[0] + ':' + ioc[1], ioc[0], ioc[1], 2, ioc_units[ioc])
        for t, n in sorted(ioc_targets[ioc].items()):
            if t in keep_t:
                links.append([node('t:' + t, 'target', t, 1, by_target[t]), a, n])
        for r, n in sorted(ioc_rules[ioc].items()):
            links.append([a, node('r:' + r, 'technique', r, 3, by_rule[r]), n])
    # Complete listings behind the (capped) picture: every indicator and every target.
    t_src = defaultdict(set)
    for ip, ts in src_targets.items():
        for t in ts:
            t_src[t].add(ip)
    all_iocs = [[k[0], k[1], len(ioc_units[k]), ', '.join(sorted(ioc_targets[k])),
                 ', '.join(sorted(ioc_rules[k])), sorted(ioc_units[k])]
                for k in sorted(ioc_units, key=lambda k: (-len(ioc_units[k]), k))]
    all_targets = [[t, len(by_target[t]), ', '.join(sorted(t_src[t])), sorted(by_target[t])]
                   for t in sorted(by_target, key=lambda t: (-len(by_target[t]), t))]
    return {'nodes': nodes, 'links': links, 'ioc_total': len(ioc_units), 'top': ioc_top,
            'src_total': len(src_targets), 'all_iocs': all_iocs, 'all_targets': all_targets}


def encode(model):
    raw = json.dumps(model, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    k = XOR_KEY
    out = bytes(b ^ k[i % len(k)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode('ascii')


def decode_html(text):
    """The report data embedded in an HTML report, decoded (the inverse of encode)."""
    m = re.search(r'<script type="application/octet-stream" id="d">([A-Za-z0-9+/=\s]+)<', text)
    if not m:
        raise ValueError('no embedded report data found')
    raw = base64.b64decode(re.sub(r'\s+', '', m.group(1)))
    k = XOR_KEY
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(raw)).decode('utf-8')


def find_text(report, needles, model=None, html_text=None):
    """Where a string occurs: analysis units per effective category, the report model, an existing HTML report."""
    lines = []
    units = report.get('units') or []
    for needle in needles:
        n = needle.casefold()
        per_cat, hits = Counter(), Counter()
        for u in units:
            c = json.dumps(u, ensure_ascii=False).casefold().count(n)
            if c:
                cat = u.get('effective_category') or 'unknown'
                per_cat[cat] += 1
                hits[cat] += c
        lines.append('{!r} in the analysis: {} occurrence(s) in {} unit(s)'.format(
            needle, sum(hits.values()), sum(per_cat.values())))
        for cat in sorted(per_cat, key=lambda c: (-per_cat[c], c)):
            shown = 'shown in the report' if cat in ATTACK else 'not an attack category: counted only'
            lines.append('    {:<14} {:>7} unit(s) {:>8} occurrence(s)  [{}]'.format(cat, per_cat[cat], hits[cat], shown))
        if model is not None:
            lines.append('    in the report data built now: {} occurrence(s)'.format(
                json.dumps(model, ensure_ascii=False).casefold().count(n)))
        if html_text is not None:
            lines.append('    in the existing HTML report (decoded): {} occurrence(s)'.format(
                decode_html(html_text).casefold().count(n)))
    return '\n'.join(lines)


CSS = r"""
:root{--bg:#f6f7f9;--panel:#fff;--fg:#1d2433;--muted:#5b6475;--line:#dde1e7;--line2:#eceef2;--th:#f0f2f5;--sel:#fff6d6;--hover:#f3f7ff;--pre:#f4f5f7;--chip:#7a4d00;--band:#c9ced6;--shadow:#9aa3b2}
@media (prefers-color-scheme:dark){:root{--bg:#12161f;--panel:#1b212c;--fg:#e6eaf0;--muted:#a7b0bf;--line:#2c3443;--line2:#262d3a;--th:#232a36;--sel:#3a3320;--hover:#222b3a;--pre:#151a23;--chip:#ffcc80;--band:#3a4252;--shadow:#06080c}}
body{font:14px/1.45 Segoe UI,Arial,sans-serif;margin:0;color:var(--fg);background:var(--bg)}
header{background:#1d2433;color:#fff;padding:14px 24px}header h1{margin:0;font-size:20px}
nav a{color:#cfd8e8;margin-right:14px;font-size:13px}#focus{width:320px;padding:3px 6px;font-size:13px}.focusbar{background:var(--sel);border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:10px 0}main{padding:8px 24px 40px;max-width:1500px}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 18px;margin:14px 0}
h2{font-size:17px;margin:4px 0 10px}h3{font-size:15px;margin:14px 0 6px}h4{font-size:13.5px;margin:10px 0 4px}
.kpis{display:flex;flex-wrap:wrap;gap:10px}.kpi{border:1px solid var(--line);border-radius:6px;padding:8px 12px;min-width:120px}
.kpi b{display:block;font-size:20px}.kpi .lbl{font-size:12px;color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{border-bottom:1px solid var(--line2);padding:4px 6px;text-align:left;vertical-align:top}
th{cursor:pointer;background:var(--th);position:sticky;top:0;user-select:none}tr.sel{background:var(--sel)}tbody tr:hover{background:var(--hover)}
.tw{max-height:520px;overflow:auto;border:1px solid var(--line2)}.ctl{margin:6px 0;display:flex;gap:8px;align-items:center;font-size:12px;flex-wrap:wrap}
input[type=search],select{padding:4px 6px;background:var(--panel);color:var(--fg);border:1px solid var(--line)}input[type=search]{width:280px}
table.kv th{text-align:left;width:14em;vertical-align:top}table.kv td{white-space:pre-wrap;word-break:break-word}.det{margin:6px 0 14px}
pre,code{font-family:Consolas,monospace}pre{white-space:pre-wrap;word-break:break-all;background:var(--pre);padding:8px;border-radius:4px;max-height:300px;overflow:auto;font-size:12px}
span.tag{display:inline-block;padding:0 6px;border-radius:9px;font-size:11px;color:#fff !important;margin:1px;line-height:17px}
span.tag.phase-extraction{color:#10241a !important}
span.tag.inf{background:#455a64}.chip{font-size:12px;color:var(--chip)}.chip a{color:var(--chip)}
.muted{color:var(--muted);font-size:12px}svg text{font:11px Segoe UI,Arial,sans-serif;fill:var(--fg)}svg text.gl{fill:#e8edf5}
#tip{position:fixed;pointer-events:none;background:#1d2433;color:#fff;padding:4px 8px;font-size:12px;border-radius:4px;display:none;max-width:520px;word-break:break-all;white-space:pre-wrap;z-index:9}
.legend span{margin-right:12px;font-size:12px}.legend i{display:inline-block;width:10px;height:10px;margin-right:4px;border-radius:2px}
details.camp{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:6px 10px}details.camp summary{cursor:pointer;font-weight:600}
.narr{margin:6px 0 4px;padding-left:10px;border-left:3px solid var(--line)}a{color:#4a7bd8}
"""

JS = r"""
'use strict';
const KIND={source_ip:'#ef5350',target:'#90a4ae',ip:'#ba68c8',host:'#26c6da',url:'#66bb6a',email:'#f06292',unc:'#ffb74d',technique:'#5c8df6'};
// Focus mode: keep only payloads related to the text and rebuild every derived view from them.
function focusModel(D,q){q=q.toLowerCase();const keep=new Set(),remap=new Map(),units=[];
D.units.forEach((u,i)=>{const t=(u.value+' '+u.site+' '+u.path+' '+u.param+' '+(u.ips||[]).join(' ')+' '+u.summary).toLowerCase();if(t.includes(q)){keep.add(u.id);remap.set(i,units.length);units.push(u);}});
D.units=units;const CK=D.cats.map(c=>c[0]);const m60=t=>Math.floor(t/60)*60;
D.events=D.events.map(e=>{const k=e[7].filter(x=>keep.has(x[0]));return k.length?[e[0],e[1],e[2],e[3],k.reduce((a,x)=>a+x[1],0),e[5],e[6],k]:null;}).filter(Boolean);
const fip=new Set(units.flatMap(u=>u.ips||[]));D.crawl=Object.assign({},D.crawl,{hours:D.crawl.hours.map(h=>{const i=h[2].map((ip,j)=>[ip,h[3][j]]).filter(x=>fip.has(x[0]));return i.length?[h[0],i.reduce((a,x)=>a+x[1],0),i.map(x=>x[0]),i.map(x=>x[1])]:null;}).filter(Boolean)});
D.crawl.requests=D.crawl.hours.reduce((a,h)=>a+h[1],0);
const ph=[];for(const e of D.events){let p=ph[ph.length-1];if(!p||e[0]-p.end>7200){p={start:e[0],end:e[0],cats:{},r:{},t:new Set()};ph.push(p);}p.end=e[0];p.cats[e[1]]=(p.cats[e[1]]||0)+e[4];p.r[e[2]]=(p.r[e[2]]||0)+e[4];p.t.add(e[3]);}
D.phases=ph.map(p=>({start:p.start,end:p.end+59,cats:p.cats,rules:Object.entries(p.r).sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1)).slice(0,5),targets:p.t.size}));
const s=D.scope,ips=new Set(units.flatMap(u=>u.ips||[]));
s.units=Object.fromEntries(CK.map(c=>[c,units.filter(u=>u.cat===c).length]));s.requests=Object.fromEntries(CK.map(c=>[c,units.filter(u=>u.cat===c).reduce((a,u)=>a+u.count,0)]));
s.sites=[...new Set(units.map(u=>u.site))].sort();s.endpoints=new Set(units.map(u=>u.site+'\u0001'+u.path)).size;s.params=new Set(units.map(u=>u.site+'\u0001'+u.path+'\u0001'+u.param)).size;
s.related=units.filter(u=>u.related).length;s.source_ip_total=ips.size;const sc={};units.forEach(u=>(u.ips||[]).forEach(ip=>{sc[ip]=(sc[ip]||0)+u.count;}));s.source_ips=Object.entries(sc).sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1)).slice(0,20);const fs=units.map(u=>u.first).filter(Boolean).sort(),ls=units.map(u=>u.last).filter(Boolean).sort();s.first=fs[0]||'';s.last=ls[ls.length-1]||'';
const inter=ids=>(ids||[]).filter(x=>keep.has(x));const E=D.evo;
for(const k of Object.keys(E)){E[k]=E[k].filter(r=>{if(k==='inference'){r[12]=r[12].filter(x=>keep.has(x[3]));r[13]=inter(r[13]);r[4]=r[12].length;return r[13].length>0;}
if(k==='error_channel')return r[r.length-1].some(x=>keep.has(x));
if(k==='strings'){r[9]=inter(r[9]);return r[9].length>0;}const i=r.length-1;r[i]=inter(r[i]);if(!r[i].length)return false;const ni=k==='dbms'?2:i-1;if(typeof r[ni]==='number')r[ni]=r[i].length;return true;});}
const byC=new Map();units.forEach(u=>{if(!byC.has(u.camp))byC.set(u.camp,[]);byC.get(u.camp).push(u);});
D.campaigns=D.campaigns.filter(c=>byC.has(c.id)).map(c=>{const us=byC.get(c.id),ln=new Map(),cats={};us.forEach(u=>{const k=u.cat+'|'+u.lane+'\u0001'+m60(u.ts);ln.set(k,(ln.get(k)||0)+u.count);cats[u.cat]=(cats[u.cat]||0)+1;});
return Object.assign({},c,{units:us.length,requests:us.reduce((a,u)=>a+u.count,0),cats,first:Math.min(...us.map(u=>u.ts)),last:Math.max(...us.map(u=>u.ts)),ips:[...new Set(us.flatMap(u=>u.ips||[]))].sort(),
paths:[...new Set(us.map(u=>u.path))].sort(),params:[...new Set(us.map(u=>u.param))].sort(),lanes:[...ln].map(([k,n])=>{const x=k.split('\u0001');return [x[0],+x[1],n];}).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:a[1]-b[1])});});
s.campaigns=D.campaigns.length;
const G=D.graph,nk=[],nmap=new Map();G.nodes.forEach((n,i)=>{const idx=n[4].filter(j=>remap.has(j)).map(j=>remap.get(j));if(idx.length){nmap.set(i,nk.length);nk.push([n[0],n[1],n[2],idx.length,idx]);}});
G.links=G.links.filter(l=>nmap.has(l[0])&&nmap.has(l[1])).map(l=>{const a=nmap.get(l[0]),b=nmap.get(l[1]),sa=new Set(nk[a][4]);return [a,b,nk[b][4].filter(x=>sa.has(x)).length];}).filter(l=>l[2]>0);G.nodes=nk;
G.all_iocs=G.all_iocs.filter(r=>{r[5]=inter(r[5]);r[2]=r[5].length;return r[2]>0;});G.all_targets=G.all_targets.filter(r=>{r[3]=inter(r[3]);r[1]=r[3].length;return r[1]>0;});
G.ioc_total=G.all_iocs.length;G.src_total=new Set(nk.filter(n=>n[0]==='source_ip').map(n=>n[1])).size;}
function decode(){const s=atob(document.getElementById('d').textContent.trim());const k=KEY;const b=new Uint8Array(s.length);
for(let i=0;i<s.length;i++)b[i]=s.charCodeAt(i)^k[i%k.length];return JSON.parse(new TextDecoder('utf-8').decode(b));}
const D=decode();const FOCUS=new URL(location.href).searchParams.get('focus')||'';const TOTAL_UNITS=D.units.length;if(FOCUS)focusModel(D,FOCUS);const CATS=D.cats.map(c=>c[0]);const C=Object.fromEntries(D.cats.map(c=>[c[0],c[2]]));
function el(t,a,...ch){const e=document.createElement(t);if(a)for(const k in a){if(k==='class')e.className=a[k];else if(k.startsWith('on'))e.addEventListener(k.slice(2),a[k]);else e.setAttribute(k,a[k]);}
for(const c of ch){if(c==null)continue;e.appendChild(typeof c==='object'?c:document.createTextNode(String(c)));}return e;}
function sv(t,a){const e=document.createElementNS('http://www.w3.org/2000/svg',t);for(const k in a)e.setAttribute(k,a[k]);return e;}
const tip=document.getElementById('tip');function showTip(ev,t){tip.textContent=t;tip.style.display='block';tip.style.left=(ev.clientX+12)+'px';tip.style.top=(ev.clientY+12)+'px';}
function hideTip(){tip.style.display='none';}
function hover(e,f){e.addEventListener('mousemove',ev=>showTip(ev,f()));e.addEventListener('mouseleave',hideTip);}
const fmt=n=>Number(n).toLocaleString('en-US');const iso=s=>new Date(s*1000).toISOString().replace('T',' ').slice(0,16)+' UTC';
const isoS=s=>s?new Date(s*1000).toISOString().replace('T',' ').slice(0,19):'';
const tname=r=>D.tech_names[r]||r;
const IN=D.intel||null;const ipi=ip=>{const x=IN&&IN[ip];if(!x)return '';if(x.error)return ' [AbuseIPDB: '+x.error+']';return ' ['+(x.infra||'unknown')+(x.isp?' ('+x.isp+')':'')+', '+(x.country||'?')+', AbuseIPDB score '+x.score+', '+fmt(x.reports||0)+' reports]';};
const ipl=a=>a.map(ip=>ip+ipi(ip)).join(', ');const ring=s=>s==null?null:s>=75?'#d32f2f':s>=25?'#fb8c00':s>0?'#fdd835':'#9e9e9e';
const PH={probing:'#b8860b',enumeration:'#3554a5',extraction:'#1baf7a',exploitation:'#c62828'};const PHL={probing:'probing',enumeration:'enumeration',extraction:'extraction',exploitation:'exploitation attempt'};
function phTag(p){return el('span',{class:'tag phase-'+p,style:'background:'+PH[p]},PHL[p]||p);}
function tag(c){return el('span',{class:'tag',style:'background:'+(C[c]||'#555')},D.labels[c]||c);}
function infTag(){return el('span',{class:'tag inf'},'related payload (inferred)');}
const LANEC=(()=>{const m={};for(const c of CATS){const ls=D.lanes[c]||[];ls.forEach((l,i)=>{m[c+'|'+l]=C[c];});}return m;})();
// ---- sortable/filterable table
function table(host,cols,rows,opts){opts=opts||{};let sortI=opts.sort||0,dir=opts.dir||1,q='',cat='',ext=null;let LIM=opts.lim||1000;
const inp=el('input',{type:'search',placeholder:'filter...'});const info=el('span',{class:'muted'});const ctl=el('div',{class:'ctl'},inp);
let sel=null;if(opts.catFilter){sel=el('select',null,el('option',{value:''},'all categories'),...CATS.map(c=>el('option',{value:c},D.labels[c])));ctl.appendChild(sel);sel.addEventListener('change',()=>{cat=sel.value;draw();});}
const chip=el('span',{class:'chip'});ctl.appendChild(info);ctl.appendChild(chip);const tb=el('tbody');const hr=el('tr');
cols.forEach((c,i)=>hr.appendChild(el('th',{onclick:()=>{dir=sortI===i?-dir:1;sortI=i;draw();}},c[0])));
host.appendChild(ctl);host.appendChild(el('div',{class:'tw'},el('table',null,el('thead',null,hr),tb)));
const txt=rows.map(r=>(cols.map(c=>String(c[1](r))).join(' ')+(opts.search?' '+opts.search(r):'')).toLowerCase());
inp.addEventListener('input',()=>{q=inp.value.toLowerCase();draw();});
function idx0(){return rows.filter((_,i)=>(!q||txt[i].includes(q))&&(!cat||rows[i].cat===cat)&&(!ext||ext.has(i))).length;}
function draw(){let idx=rows.map((_,i)=>i).filter(i=>(!q||txt[i].includes(q))&&(!cat||rows[i].cat===cat)&&(!ext||ext.has(i)));const f=cols[sortI][1];
idx.sort((a,b)=>{const x=f(rows[a]),y=f(rows[b]);return (typeof x==='number'&&typeof y==='number'?x-y:String(x).localeCompare(String(y)))*dir||a-b;});
info.replaceChildren(fmt(idx.length)+' rows');if(idx.length>LIM)info.append(' (first '+fmt(LIM)+' shown) ',el('a',{href:'#',onclick:e=>{e.preventDefault();LIM=Infinity;draw();}},'show all'));tb.replaceChildren();
for(const i of idx.slice(0,LIM)){const r=rows[i];const tr=el('tr');for(const c of cols){const v=c[2]?c[2](r):c[1](r);tr.appendChild(el('td',null,v));}
if(opts.onclick)tr.addEventListener('click',()=>{tb.querySelectorAll('tr.sel').forEach(x=>x.classList.remove('sel'));tr.classList.add('sel');opts.onclick(r);});tb.appendChild(tr);}}
draw();const api={search(v){inp.value=v;q=String(v).toLowerCase();draw();return idx0();},filter(set,label){ext=set;chip.replaceChildren();if(set)chip.append('filter: '+label+' ',el('a',{href:'#',onclick:e=>{e.preventDefault();api.filter(null);}},'clear'));draw();}};return api;}
const UIDX=new Map(D.units.map((u,i)=>[u.id,i]));
// Rows may carry hidden extras after the visible columns: [payload ids] and an optional comparison sequence.
function injected(host,sections){for(const section of sections||[]){host.appendChild(el('div',{class:'muted'},'Injected section'+(section.layer?' (layer: '+section.layer+')':'')));host.appendChild(el('pre',null,section.text));}}
function rowDetail(det,heads,r){const ids=r[heads.length]||[],seq=r[heads.length+1],pos=r[heads.length+2];
const kv=el('table',{class:'kv'},el('tbody',null,...heads.map((h,i)=>el('tr',null,el('th',null,h),el('td',null,String(r[i]==null?'':r[i]))))));
det.replaceChildren(el('h4',null,'Selected entry'),kv);
if(seq&&seq.length){det.appendChild(el('div',{class:'muted'},'Comparisons in time order (the threshold sequence the bounds are derived from):'));const t=el('div');det.appendChild(t);
table(t,[['Time',x=>x[0],x=>isoS(x[0])],['Comparison',x=>x[1]+' '+x[2]],['Payload',x=>x[3]]],seq,{sort:0,lim:500});}
if(pos&&pos.length){det.appendChild(el('div',{class:'muted'},'Per position: \u2191/\u2193 = the attacker\'s next threshold went higher/lower, i.e. the previous comparison held/did not hold. The answer to the last comparison of each position is not in the request log (?), so a character usually narrows to two candidates.'));const t=el('div');det.appendChild(t);
table(t,[['Kind',x=>x[0]],['Position',x=>x[1]],['Candidates',x=>x[2]],['Bounds',x=>x[3]],['Comparisons',x=>x[4]],['First',x=>x[5],x=>isoS(x[5])]],pos,{sort:5,lim:1000});}
det.appendChild(el('div',{class:'muted'},fmt(ids.length)+' payload(s) \u2014 ',
el('a',{href:'#s-pay',onclick:()=>PAYTABLE&&PAYTABLE.filter(new Set(ids.map(x=>UIDX.get(x)).filter(x=>x!=null)),'selected evolution entry')},'show them in the payload table')));
for(const id of ids.slice(0,20)){const u=D.units[UIDX.get(id)];if(!u)continue;
det.appendChild(el('div',{class:'muted'},phTag(u.phase),' Unit '+u.id+' | '+u.site+u.path+' param '+u.param+' | '+u.first+' to '+u.last+' | source IPs: '+(ipl(u.ips)||'n/a')+' | statuses '+(u.statuses.join(', ')||'n/a')+' | '+u.count+' request(s)'));
det.appendChild(el('pre',null,u.value+(u.truncated?'\n[value truncated at 4000 characters]':'')));injected(det,u.injected);}
if(ids.length>20)det.appendChild(el('div',{class:'muted'},fmt(ids.length-20)+' more payload(s): use the link above.'));det.scrollIntoView({block:'nearest'});}
function simple(host,heads,rows,sort,dir){if(!rows.length)return;const t=el('div');host.appendChild(t);const det=el('div',{class:'det'});
const click=rows.some(r=>Array.isArray(r[heads.length]));const api=table(t,heads.map((h,i)=>[h,r=>r[i]]),rows,{sort:sort||0,dir:dir||1,lim:500,onclick:click?r=>rowDetail(det,heads,r):null});
host.appendChild(det);return api;}
// ---- executive summary
(function(){const s=D.scope,m=D.meta,box=document.getElementById('exec');
const tot=CATS.reduce((a,c)=>a+s.units[c],0),req=CATS.reduce((a,c)=>a+s.requests[c],0);
const k=el('div',{class:'kpis'});const add=(v,l,t)=>k.appendChild(el('div',{class:'kpi'},t||null,el('b',null,v),el('span',{class:'lbl'},l)));
add(fmt(tot),'attack payloads');add(fmt(req),'attack requests');for(const c of CATS)add(fmt(s.units[c]),'payloads',tag(c));
add(fmt(s.endpoints),'targeted endpoints');add(fmt(s.sites.length),'sites');add(fmt(s.campaigns),'campaigns');add(fmt(s.unrelated),'unrelated actions');
for(const p of ['probing','enumeration','extraction'])add(fmt(D.units.filter(u=>u.cat==='sqli'&&u.phase===p).length),'SQL payloads: '+p,phTag(p));
box.appendChild(k);
const p=[];p.push('Between '+(s.first||'n/a')+' and '+(s.last||'n/a')+', '+fmt(req)+' web requests carried '+fmt(tot)+' distinct payloads identified as attack attempts. ');
p.push('They targeted '+fmt(s.endpoints)+' endpoint(s) ('+fmt(s.params)+' parameter(s)) on '+fmt(s.sites.length)+' site(s): '+s.sites.join(', ')+', grouped into '+fmt(s.campaigns)+' campaign(s). ');
p.push('SQL payload phases: '+['probing','enumeration','extraction'].map(p=>p+' '+fmt(D.units.filter(u=>u.cat==='sqli'&&u.phase===p).length)).join('; ')+'. ');
p.push('By category: '+CATS.map(c=>D.labels[c]+' '+fmt(s.units[c])+' payloads in '+fmt(s.requests[c])+' requests').join('; ')+'. ');
if(D.evo.error_channel.length)p.push(fmt(D.evo.error_channel.length)+' error-channel extraction payload(s) were submitted; outcomes are not established. ');
if(s.related)p.push(fmt(s.related)+' of these payloads are related payloads, inferred from neighbouring identified payloads on the same parameter. ');
if(s.source_ip_total)p.push('Requests came from '+fmt(s.source_ip_total)+' source address(es) as recorded in the export. ');
if(IN){const src=D.src_all.filter(ip=>IN[ip]&&!IN[ip].error);const rep=src.filter(ip=>IN[ip].reports>0);const mx=Math.max(0,...src.map(ip=>IN[ip].score||0));
const inf={};const rq=new Map();for(const u of D.units)for(const ip of u.ips||[])rq.set(ip,(rq.get(ip)||0)+u.count);
for(const ip of src){const k=IN[ip].infra||'unknown';if(!inf[k])inf[k]=[0,0];inf[k][0]++;inf[k][1]+=rq.get(ip)||0;}
const ik=Object.keys(inf).sort((a,b)=>inf[b][1]-inf[a][1]||(a<b?-1:1));
if(ik.length)p.push('Source infrastructure: '+ik.map(k=>fmt(inf[k][0])+' '+k+' address(es) ('+fmt(inf[k][1])+' attack requests)').join(', ')+'. ');
p.push(rep.length+' of '+src.length+' checked public source address(es) have AbuseIPDB reports'+(rep.length?'; highest abuse confidence score '+mx:'')+'. ');}
p.push(fmt(s.unrelated)+' other analysed actions (benign, crawling or undetermined) are not described further.');
box.appendChild(el('p',null,p.join('')));
box.appendChild(el('h3',null,'Key phases (attack activity separated by gaps over two hours)'));
const ul=el('ul');for(const ph of D.phases){const cs=CATS.filter(c=>ph.cats[c]).map(c=>D.labels[c]+' '+fmt(ph.cats[c])).join(', ');
ul.appendChild(el('li',null,iso(ph.start)+' to '+iso(ph.end)+': '+cs+' requests against '+ph.targets+' endpoint(s); main techniques: '+ph.rules.map(r=>tname(r[0])).join(', ')+'.'));}
box.appendChild(ul);
box.appendChild(el('p',{class:'muted'},'Analysis generated '+(m.generated_at||'n/a')+' by analyzer '+(m.analyzer_version||'?')+' (rules '+(m.rule_catalogue_version||'?')+'), source SHA-256 '+(m.source_sha256||'n/a')+', '+fmt(m.units_total||0)+' units in total. This report is descriptive; it makes no statement about impact or success.'));})();
// ---- timeline
(function(){const host=document.getElementById('timeline');const EV=D.events;const CR=D.crawl;if(!EV.length){host.appendChild(el('p',null,'No timestamps available.'));return;}
const RANGES=[];{let a=EV[0][0],b=EV[EV.length-1][0]+60;for(const h of CR.hours){a=Math.min(a,h[0]);b=Math.max(b,h[0]+3600);}
RANGES.push(['whole period (attacks and related crawling)',a,b]);RANGES.push(['attack requests only ('+iso(EV[0][0])+' \u2013 '+iso(EV[EV.length-1][0]+60)+')',EV[0][0],EV[EV.length-1][0]+60]);
D.phases.forEach((p,i)=>{const pad=Math.max(300,Math.round((p.end-p.start)*0.05));RANGES.push(['phase '+(i+1)+': '+iso(p.start)+' \u2013 '+iso(p.end),p.start-pad,p.end+pad]);});}
const rsel=el('select',null,...RANGES.map((r,i)=>el('option',{value:String(i)},r[0])));rsel.value=FOCUS?'1':'0';
host.appendChild(el('div',{class:'ctl'},'Time range ',rsel,el('span',{class:'muted'},' choose a phase to zoom in')));
let ev,t0,t1,NB,bw,crh;function setRange(){const r=RANGES[+rsel.value];t0=r[1];t1=Math.max(r[2],t0+60);ev=EV.filter(e=>e[0]>=t0&&e[0]<t1);crh=CR.hours.filter(h=>h[0]+3600>t0&&h[0]<t1);
NB=Math.min(160,Math.max(10,Math.ceil((t1-t0)/60)));bw=(t1-t0)/NB;}setRange();
const W=1200,H=260,L=50,B=40;
const SRCPAL=['#4e79a7','#f28e2b','#59a14f','#e15759','#b07aa1','#76b7b2','#edc948','#ff9da7','#9c755f'];
const srcTot=new Map();for(const e of EV)srcTot.set(e[5],(srcTot.get(e[5])||0)+e[4]);
const topSrc=[...srcTot].sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1)).slice(0,8).map(x=>x[0]);const OTHER='other sources';
const srcKeys=srcTot.size>topSrc.length?[...topSrc,OTHER]:topSrc;const SC=Object.fromEntries(srcKeys.map((k,i)=>[k,SRCPAL[i%SRCPAL.length]]));
const srcLabel=x=>x===OTHER?x:x+(IN&&IN[x]&&IN[x].score!=null?' ('+(IN[x].infra||'unknown')+', abuse score '+IN[x].score+')':'');
const by=el('select',null,el('option',{value:'cat'},'category'),el('option',{value:'phase'},'payload phase'),el('option',{value:'src'},'source IP'));
host.appendChild(el('div',{class:'ctl'},'Colour attack requests by ',by));const legend=el('div',{class:'legend'});host.appendChild(legend);
const s=sv('svg',{viewBox:'0 0 '+W+' '+H,width:'100%'});const pw=(W-L-10)/NB;host.appendChild(s);
function drawHist(){const src=by.value==='src',ph=by.value==='phase';const keys=src?srcKeys:ph?Object.keys(PH):CATS;const col=src?SC:ph?PH:C;const lab=src?srcLabel:ph?(c=>PHL[c]):(c=>D.labels[c]);
const bins=Array.from({length:NB},()=>Object.fromEntries(keys.map(c=>[c,0])));
for(const e of ev){const k=src?(SC[e[5]]&&e[5]!==OTHER?e[5]:OTHER):ph?e[6]:e[1];bins[Math.min(NB-1,Math.floor((e[0]-t0)/bw))][k]+=e[4];}
let mx=1;bins.forEach(b=>mx=Math.max(mx,keys.reduce((a,c)=>a+b[c],0)));s.replaceChildren();
const sh=Array.from({length:NB},()=>({n:0,ips:new Set()}));for(const h of crh){const c=sh[Math.max(0,Math.min(NB-1,Math.floor((h[0]-t0)/bw)))];c.n+=h[1];h[2].forEach(ip=>c.ips.add(ip));}
const smx=Math.max(1,...sh.map(c=>c.n));sh.forEach((c,i)=>{if(!c.n)return;const r=sv('rect',{x:L+i*pw,y:10,width:pw,height:H-B-10,fill:'var(--shadow)','fill-opacity':(.15+.6*Math.sqrt(c.n/smx)).toFixed(2)});
hover(r,()=>iso(t0+i*bw)+' - '+iso(t0+(i+1)*bw)+'\nRelated crawling: '+fmt(c.n)+' non-attack requests from '+[...c.ips].map(srcLabel).join(', '));s.appendChild(r);});
for(let i=0;i<=4;i++){const y=H-B-(H-B-10)*i/4;s.appendChild(sv('line',{x1:L,x2:W-10,y1:y,y2:y,stroke:'var(--line2)'}));const t=sv('text',{x:L-4,y:y+4,'text-anchor':'end'});t.textContent=fmt(Math.round(mx*i/4));s.appendChild(t);}

bins.forEach((b,i)=>{let y=H-B;for(const c of keys){if(!b[c])continue;const h=(H-B-10)*b[c]/mx;y-=h;const r=sv('rect',{x:L+i*pw,y:y,width:Math.max(1,pw-1),height:h,fill:col[c]});
hover(r,()=>iso(t0+i*bw)+' - '+iso(t0+(i+1)*bw)+'\n'+keys.filter(k=>b[k]).map(k=>lab(k)+': '+b[k]).join('\n'));s.appendChild(r);}});
for(let i=0;i<=6;i++){const x=L+(W-L-10)*i/6;const t=sv('text',{x:x,y:H-B+16,'text-anchor':'middle'});t.textContent=iso(t0+(t1-t0)*i/6).slice(5);s.appendChild(t);}
legend.replaceChildren(...keys.map(c=>el('span',null,el('i',{style:'background:'+col[c]}),lab(c))),el('span',null,el('i',{style:'background:var(--shadow)'}),'related crawling (non-attack requests from attacking IPs; darker = more)'));}
by.addEventListener('change',()=>{drawHist();drawLanes();});rsel.addEventListener('change',()=>{setRange();drawHist();drawLanes();});drawHist();
const mode=el('select',null,el('option',{value:'2'},'per technique'),el('option',{value:'3'},'per target'),el('option',{value:'5'},'per source IP'));host.appendChild(el('div',{class:'ctl'},'Swimlanes ',mode,el('span',{class:'muted'},'top 30 lanes by requests')));
const lane=el('div');host.appendChild(lane);
function drawLanes(){if(!ev.length){lane.replaceChildren(el('p',{class:'muted'},'No attack requests in this range.'));return;}const k=+mode.value;const tot=new Map();for(const e of ev)tot.set(e[k],(tot.get(e[k])||0)+e[4]);
const keys=[...tot].sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1)).slice(0,30).map(x=>x[0]);const row=new Map(keys.map((x,i)=>[x,i]));
const LL=300,RH=18,HH=keys.length*RH+30;const g=sv('svg',{viewBox:'0 0 '+W+' '+HH,width:'100%'});const cells=new Map();
const ea=t0,eb=t1,ebw=bw;
for(const e of ev){if(!row.has(e[k]))continue;const bi=Math.max(0,Math.min(NB-1,Math.floor((e[0]-ea)/ebw)));const id=e[k]+'\u0001'+bi;let c=cells.get(id);if(!c){c={r:row.get(e[k]),b:bi,n:0,cat:{},ph:{}};cells.set(id,c);}c.n+=e[4];c.cat[e[1]]=(c.cat[e[1]]||0)+e[4];c.ph[e[6]]=(c.ph[e[6]]||0)+e[4];}
keys.forEach((x,i)=>{const t=sv('text',{x:LL-6,y:i*RH+13,'text-anchor':'end'});const lbl=k===2?tname(x):k===5?srcLabel(x):x;t.textContent=lbl.length>48?lbl.slice(0,47)+'\u2026':lbl;
hover(t,()=>lbl+' ('+x+'): '+fmt(tot.get(x))+' requests');g.appendChild(t);g.appendChild(sv('line',{x1:LL,x2:W-10,y1:i*RH+RH,y2:i*RH+RH,stroke:'var(--line2)'}));});
const cw=(W-10-LL)/NB;const php=by.value==='phase';for(const c of cells.values()){const top=CATS.reduce((a,b)=>(c.cat[b]||0)>(c.cat[a]||0)?b:a,CATS[0]);
const r=sv('circle',{cx:LL+(c.b+.5)*cw,cy:c.r*RH+9,r:Math.min(8,2+Math.log2(1+c.n)),fill:php?PH[Object.keys(PH).reduce((a,b)=>(c.ph[b]||0)>(c.ph[a]||0)?b:a,'probing')]:C[top],'fill-opacity':.8});
hover(r,()=>iso(ea+c.b*ebw)+': '+fmt(c.n)+' requests ('+Object.keys(PH).map(p=>fmt(c.ph[p]||0)+' '+PHL[p]).join(', ')+')');g.appendChild(r);}
for(let i=0;i<=4;i++){const x=LL+(W-10-LL)*i/4;const t=sv('text',{x:x,y:HH-6,'text-anchor':'middle'});t.textContent=iso(ea+(eb-ea)*i/4).slice(5);g.appendChild(t);}
lane.replaceChildren(g);}
mode.addEventListener('change',drawLanes);drawLanes();
host.appendChild(el('p',{class:'muted'},'Shadow: '+fmt(CR.requests)+' non-attack requests from source IPs that also sent attack payloads; '+fmt(CR.other_requests)+' non-attack requests from other sources are not shown.'));})();
// ---- attack evolution
(function(){const host=document.getElementById('evo');const E=D.evo;
const agg=(rows,key,cols)=>{const m=new Map();for(const r of rows){const k=key(r);let a=m.get(k);if(!a){a=cols(r);a.first=r.first;a.last=r.last;a.n=0;a.camps=new Set();a.u=new Set();m.set(k,a);}a.n+=r.n;a.first=Math.min(a.first,r.first);a.last=Math.max(a.last,r.last);a.camps.add(r.c);r.u.forEach(x=>a.u.add(x));}return [...m.values()];};
const O=r=>({c:r[0],kind:r[1],name:r[2],first:r[3],last:r[4],n:r[5],u:r[6]});const U=a=>[...a.u].sort();
host.appendChild(el('p',{class:'muted'},'Built from the identified payloads (decoded values, analysis artifacts and rule ids). A campaign is one site, path and parameter; campaigns on the same site worked on by exactly the same source IPs are merged. Inferred values are derived from the order of the comparison thresholds the attacker sent; they are not observed results. Click a row in these tables to see the full entry and the payloads behind it.'));
// overview per category
host.appendChild(el('h3',null,'SQL injection'));
const dbm=new Map();for(const r of E.dbms){const a=dbm.get(r[1])||{n:0,m:new Set(),c:new Set(),u:new Set()};a.n+=r[2];r[5].split(', ').forEach(x=>x&&a.m.add(x));a.c.add(r[0]);r[6].forEach(x=>a.u.add(x));dbm.set(r[1],a);}
host.appendChild(el('h4',null,'DBMS fingerprint'));
simple(host,['DBMS','Payloads','Campaigns','Markers'],[...dbm].map(([k,a])=>[k,a.n,a.c.size,[...a.m].slice(0,8).join(', '),U(a)]),1,-1);
host.appendChild(el('h4',null,'Referenced database objects (all campaigns)'));
simple(host,['Kind','Name','First seen','Last seen','Payloads','Campaigns'],agg(E.objects.map(O),r=>r.kind+'\u0001'+r.name.toUpperCase(),r=>({kind:r.kind,name:r.name})).map(a=>[a.kind,a.name,isoS(a.first),isoS(a.last),a.n,[...a.camps].join(' '),U(a)]),2);
host.appendChild(el('h4',null,'Blind inference: values read character by character'));
host.appendChild(el('p',{class:'muted'},'Each expression is read one character at a time through true/false comparisons. "Reads" tells environment fingerprinting (version, user, database name) and schema enumeration apart from expressions that select stored data from application tables. Click a row for the full expression, the comparison sequence and the payloads.'));
const span=(a,b)=>{const x=isoS(a),y=isoS(b);return x.slice(5,16)+(y.slice(0,16)!==x.slice(0,16)?' \u2192 '+(y.slice(0,10)===x.slice(0,10)?y.slice(11,16):y.slice(5,16)):'');};
const VH=['Campaign','Reads','Expression','Value read ([ab] = one of, \u00b7 = undetermined)','Length / count','Chars','Requests','Time (UTC)'];
const vrow=r=>[r[0],r[1],r[2],r[3],r[4],r[5],r[6],span(r[7],r[8]),r[9],r[10],r[11]];
if(E.strings.length)simple(host,VH,E.strings.map(vrow),7);
host.appendChild(el('h3',null,'Remote command execution'));
simple(host,['Command / expression','Family','First seen','Last seen','Payloads','Campaigns'],agg(E.commands.map(O),r=>r.kind+'\u0001'+r.name,r=>({kind:r.kind,name:r.name})).map(a=>[a.kind,a.name,isoS(a.first),isoS(a.last),a.n,[...a.camps].join(' '),U(a)]),2);
host.appendChild(el('h4',null,'External hosts and URLs referenced by command payloads'));
simple(host,['Kind','Value','First seen','Last seen','Payloads','Campaigns'],agg(E.callbacks.map(O),r=>r.kind+'\u0001'+r.name,r=>({kind:r.kind,name:r.name})).map(a=>[a.kind,a.name,isoS(a.first),isoS(a.last),a.n,[...a.camps].join(' '),U(a)]),2);
simple(host,['File','How','First seen','Last seen','Payloads','Campaigns'],agg(E.rfiles.map(O),r=>r.kind+'\u0001'+r.name,r=>({kind:r.kind,name:r.name})).map(a=>[a.kind,a.name,isoS(a.first),isoS(a.last),a.n,[...a.camps].join(' '),U(a)]),2);
host.appendChild(el('h3',null,'File access (grouped by OS file)'));
const fm=new Map();for(const r of E.files){const k=r[1]+'\u0001'+r[2].toLowerCase();let a=fm.get(k);if(!a){a={os:r[1],f:r[2],d:0,w:new Set(),u:new Set(),first:r[6],last:r[7],n:0,c:new Set(),ids:new Set()};fm.set(k,a);}
a.d=Math.max(a.d,r[3]);r[9].forEach(x=>a.ids.add(x));r[4]&&r[4].split(', ').forEach(x=>a.w.add(x));r[5]&&r[5].split(', ').forEach(x=>a.u.add(x));a.first=Math.min(a.first,r[6]);a.last=Math.max(a.last,r[7]);a.n+=r[8];a.c.add(r[0]);}
simple(host,['OS','File','Max traversal depth','Wrappers','UNC hosts','First seen','Last seen','Payloads','Campaigns'],[...fm.values()].map(a=>[a.os,a.f,a.d,[...a.w].join(', '),[...a.u].join(', '),isoS(a.first),isoS(a.last),a.n,[...a.c].join(' '),[...a.ids].sort()]),7,-1);
host.appendChild(el('h3',null,'Cross-site scripting vectors'));
simple(host,['Campaign','Parameter','Vector','Rules','First seen','Last seen','Payloads'],E.xss.map(r=>[r[0],r[1],r[2],r[3],isoS(r[4]),isoS(r[5]),r[6],r[7]]),4);
host.appendChild(el('h3',null,'Server-side request forgery: requested URLs'));
simple(host,['Campaign','Parameter','URL','Host','Port','Scheme','First seen','Last seen','Payloads'],E.ssrf.map(r=>[r[0],r[1],r[2],r[3],r[4],r[5],isoS(r[6]),isoS(r[7]),r[8],r[9]]),6);
// campaigns
host.appendChild(el('h3',null,'Campaigns (chronological)'));
simple(host,['Campaign','Site','Paths','Parameters','Source IPs','First','Last','Payloads','Requests','Categories'],D.campaigns.map(c=>[c.id,c.site,c.paths.join(' '),c.params.join(' '),ipl(c.ips),iso(c.first),iso(c.last),c.units,c.requests,Object.keys(c.cats).map(k=>D.labels[k]+' '+c.cats[k]).join(', ')]),0);
for(const c of D.campaigns){const d=el('details',{class:'camp'});d.appendChild(el('summary',null,c.id+' \u2014 '+c.site+' '+c.paths.slice(0,3).join(' ')+(c.paths.length>3?' \u2026':'')+' | '+c.units+' payloads | '+iso(c.first)));
let done=false;d.addEventListener('toggle',()=>{if(done||!d.open)return;done=true;campaign(d,c);});host.appendChild(d);}
function campaign(d,c){Object.keys(c.cats).forEach(k=>d.appendChild(tag(k)));
const nr=el('div',{class:'narr'});c.narrative.forEach(t=>nr.appendChild(el('p',null,t)));d.appendChild(nr);
const lanes=[...new Set(c.lanes.map(l=>l[0]))].sort((a,b)=>{const [ca,la]=a.split('|'),[cb,lb]=b.split('|');return CATS.indexOf(ca)-CATS.indexOf(cb)||D.lanes[ca].indexOf(la)-D.lanes[cb].indexOf(lb);});
const W=1100,LL=330,RH=20,H=lanes.length*RH+28,a=c.first,b=Math.max(c.last+60,a+60);const g=sv('svg',{viewBox:'0 0 '+W+' '+H,width:'100%'});
lanes.forEach((l,i)=>{const t=sv('text',{x:LL-6,y:i*RH+14,'text-anchor':'end'});t.textContent=D.labels[l.split('|')[0]]+': '+l.split('|')[1];g.appendChild(t);g.appendChild(sv('line',{x1:LL,x2:W-10,y1:i*RH+RH,y2:i*RH+RH,stroke:'var(--line2)'}));});
for(const x of c.lanes){const i=lanes.indexOf(x[0]);const r=sv('circle',{cx:LL+(W-10-LL)*(x[1]-a)/(b-a),cy:i*RH+10,r:Math.min(7,2.5+Math.log2(1+x[2])),fill:LANEC[x[0]]||'#888','fill-opacity':.8});hover(r,()=>iso(x[1])+' '+x[0].replace('|',': ')+': '+x[2]+' requests');g.appendChild(r);}
for(let i=0;i<=3;i++){const t=sv('text',{x:LL+(W-10-LL)*i/3,y:H-4,'text-anchor':'middle'});t.textContent=iso(a+(b-a)*i/3).slice(5);g.appendChild(t);}
d.appendChild(g);
const f=k=>E[k].filter(r=>r[0]===c.id);const sec=(h,heads,rows,s)=>{if(rows.length){d.appendChild(el('h4',null,h));simple(d,heads,rows,s||0);}};
sec('DBMS fingerprint',['DBMS','Payloads','First','Last','Markers'],f('dbms').map(r=>[r[1],r[2],isoS(r[3]),isoS(r[4]),r[5],r[6]]));
sec('Database objects',['Kind','Name','First','Last','Payloads'],f('objects').map(r=>[r[1],r[2],isoS(r[3]),isoS(r[4]),r[5],r[6]]),2);
sec('Error-channel extraction',['First seen (UTC)','Requests','Statuses','Error expression','Submitted expression','Table / view','Row selector','Kind'],f('error_channel').map(r=>[isoS(r[1]),r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9]]));
sec('Values read by blind inference',VH.slice(1),f('strings').map(r=>vrow(r).slice(1)),6);
sec('Commands and expressions',['Command / expression','Family','First','Last','Payloads'],f('commands').map(r=>[r[1],r[2],isoS(r[3]),isoS(r[4]),r[5],r[6]]),2);
sec('External references',['Kind','Value','First','Last','Payloads'],f('callbacks').map(r=>[r[1],r[2],isoS(r[3]),isoS(r[4]),r[5],r[6]]),2);
sec('Files written / downloaded / read by commands',['File','How','First','Last','Payloads'],f('rfiles').map(r=>[r[1],r[2],isoS(r[3]),isoS(r[4]),r[5],r[6]]),2);
sec('Files requested',['OS','File','Max depth','Wrappers','UNC hosts','First','Last','Payloads'],f('files').map(r=>[r[1],r[2],r[3],r[4],r[5],isoS(r[6]),isoS(r[7]),r[8],r[9]]),5);
sec('Requested URLs / hosts / ports',['Parameter','URL','Host','Port','Scheme','First','Last','Payloads'],f('ssrf').map(r=>[r[1],r[2],r[3],r[4],r[5],isoS(r[6]),isoS(r[7]),r[8],r[9]]),5);
sec('Script injection vectors',['Parameter','Vector','Rules','First','Last','Payloads'],f('xss').map(r=>[r[1],r[2],r[3],isoS(r[4]),isoS(r[5]),r[6],r[7]]),3);
const om=Object.entries(c.omitted);if(om.length)d.appendChild(el('p',{class:'muted'},'Not listed (size limit): '+om.map(x=>x[1]+' '+x[0]).join(', ')));
d.appendChild(el('h4',null,'Example payloads per stage'));for(const l of lanes){d.appendChild(el('div',{class:'muted'},l.replace('|',': ')));(c.examples[l]||[]).forEach((v,i)=>{d.appendChild(el('pre',null,v));injected(d,(c.example_sections[l]||[])[i]);});}}})();
// ---- per-category and per-target aggregates
(function(){const host=document.getElementById('agg');const g=new Map();
for(const u of D.units){const key=[u.cat,u.site,u.path,u.param,u.rules.join(' ')].join('\u0001');let a=g.get(key);
if(!a){a={cat:u.cat,site:u.site,path:u.path,param:u.param,rules:u.rules,first:u.first,last:u.last,n:0,count:0,probing:0,enumeration:0,extraction:0,exploitation:0};g.set(key,a);}
a.n++;a[u.phase]++;a.count+=u.count;if(u.first&&u.first<a.first)a.first=u.first;if(u.last>a.last)a.last=u.last;}
const kp=el('div',{class:'kpis'});for(const c of CATS){const rs=D.units.filter(u=>u.cat===c);const rc=new Map();rs.forEach(u=>u.rules.forEach(r=>rc.set(r,(rc.get(r)||0)+1)));
const top=[...rc].sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:1)).slice(0,6);kp.appendChild(el('div',{class:'kpi'},tag(c),el('b',null,fmt(rs.length)+' payloads'),
el('span',{class:'lbl'},new Set(rs.map(u=>u.site+u.path)).size+' endpoints'),el('div',null,phTag('probing'),' '+fmt(rs.filter(u=>u.phase==='probing').length)+' ',...(c==='sqli'?['enumeration','extraction']:['exploitation']).flatMap(p=>[phTag(p),' '+fmt(rs.filter(u=>u.phase===p).length)+' '])),el('ul',{class:'muted'},...top.map(t=>el('li',null,tname(t[0])+' ('+t[1]+')')))));}
host.appendChild(kp);host.appendChild(el('p',{class:'muted'},'Phase, from the payload content only (it says nothing about the outcome): ',phTag('probing'),' tests whether the injection point reacts (syntax, boolean or time checks, canary files such as the account database, script markers, callbacks); ',phTag('enumeration'),' maps database structure, environment, row counts or value sizes; ',phTag('extraction'),' reads stored values from application tables; ',phTag('exploitation'),' tries to read non-canary files, run non-diagnostic commands, download or write files, take browser data or reach cloud metadata services.'));
host.appendChild(el('h3',null,'Per target and technique'));
table(host,[['Category',r=>r.cat,r=>tag(r.cat)],['Site',r=>r.site],['Path',r=>r.path],['Parameter',r=>r.param],['Technique / rule',r=>r.rules.map(tname).join('; ')],
['First seen',r=>r.first],['Last seen',r=>r.last],['Payloads',r=>r.n],['Probing',r=>r.probing],['Enumeration',r=>r.enumeration],['Extraction',r=>r.extraction],['Exploitation attempts',r=>r.exploitation],['Requests',r=>r.count]],[...g.values()],{sort:7,dir:-1,catFilter:true});
if(IN){host.appendChild(el('h3',null,'IP intelligence (AbuseIPDB, cached lookup)'));const req=new Map();for(const u of D.units)for(const ip of u.ips)req.set(ip,(req.get(ip)||0)+u.count);
const rows=Object.keys(IN).sort().map(ip=>Object.assign({ip:ip,req:req.get(ip)||0},IN[ip]));const t=el('div');host.appendChild(t);
table(t,[['IP',r=>r.ip],['Infrastructure',r=>r.error?'':(r.infra||'unknown'),r=>r.error?'':(r.infra||'unknown')+(D.infra_note&&D.infra_note[r.infra||'unknown']?' \u2014 '+D.infra_note[r.infra||'unknown']:'')],['Role',r=>r.roles.join(', ')],['Attack requests',r=>r.req],['Score',r=>r.error?-1:r.score,r=>r.error?'error: '+r.error:String(r.score)],['Country',r=>r.country||''],['ISP',r=>r.isp||''],
['Usage type',r=>r.usage||''],['Domain',r=>r.domain||''],['Reports',r=>r.reports||0],['Reporters',r=>r.users||0],['Last reported',r=>r.last||''],['Tor',r=>r.tor?'yes':'']],rows,{sort:3,dir:-1});}})();
// ---- payload drill-down
let PAYTABLE=null;(function(){const host=document.getElementById('payloads');const det=el('div');
PAYTABLE=table(host,[['Unit',r=>r.id],['Category',r=>r.cat,r=>tag(r.cat)],['Campaign',r=>r.camp||''],['Site',r=>r.site],['Path',r=>r.path],['Parameter',r=>r.param],['Technique',r=>r.rules.map(tname).join('; ')],
['Phase',r=>r.phase,r=>phTag(r.phase)],['Stage',r=>r.lane],['First seen',r=>r.first],['Requests',r=>r.count],['Summary',r=>r.summary]],D.units,{sort:9,catFilter:true,search:r=>r.value+' '+(r.ips||[]).join(' '),onclick:u=>{
det.replaceChildren(el('h3',null,'Unit '+u.id+' ',tag(u.cat),phTag(u.phase),u.related?infTag():null),
el('p',null,u.summary),el('p',{class:'muted'},'Technique: '+u.rules.map(r=>tname(r)+(r.startsWith('related:')?'':' ('+r+')')).join('; ')+' | stage '+u.lane+' | campaign '+(u.camp||'-')+' | '+u.site+u.path+' param '+u.param+(u.ntargets>1?' (+'+(u.ntargets-1)+' more targets)':'')+' | source IPs: '+(ipl(u.ips)||'n/a')+' | statuses '+(u.statuses.join(', ')||'n/a')+' | '+u.first+' to '+u.last),
el('div',{class:'muted'},'Decoded value'+(u.truncated?' (truncated)':'')+':'),el('pre',null,u.value));injected(det,u.injected);det.scrollIntoView({block:'nearest'});}});
host.appendChild(det);})();
(function(){const f=document.getElementById('focus');f.value=FOCUS;f.addEventListener('change',()=>{const v=f.value.trim();const u=new URL(location.href);if(v)u.searchParams.set('focus',v);else u.searchParams.delete('focus');u.hash='';location.href=u.toString();});
if(FOCUS){const m=document.querySelector('main');const u=new URL(location.href);u.searchParams.delete('focus');
m.insertBefore(el('div',{class:'focusbar'},el('b',null,'Focused on \u201c'+FOCUS+'\u201d: '),fmt(D.units.length)+' of '+fmt(TOTAL_UNITS)+' attack payloads (target site, path, parameter, decoded value, summary or source IP contains it; case-insensitive). All sections below are built from these payloads only; the related-crawling shadow is limited to the source IPs of these payloads; campaign narratives still describe whole campaigns. ',el('a',{href:u.toString()},'clear focus')),m.firstChild);}})();
// ---- IOC graph (layered: source IPs -> targets -> payload indicators -> techniques)
(function(){const host=document.getElementById('graph');const G=D.graph;if(!G.nodes.length){host.appendChild(el('p',null,'No attacker indicators available.'));return;}
host.appendChild(el('p',{class:'muted'},'Source IPs (top '+Math.min(20,G.src_total)+' of '+G.src_total+') linked to the targets they hit; top '+Math.min(G.top,G.ioc_total)+' of '+G.ioc_total+' external indicators found in attack payloads, linked to targets and techniques. Hover to highlight; click a node to pin it and filter the payload table.'));
const gl=el('details',{class:'camp'},el('summary',null,'Complete lists: all '+fmt(G.all_iocs.length)+' external indicators and all '+fmt(G.all_targets.length)+' targets (the picture shows the top ones)'));host.appendChild(gl);gl.appendChild(el('h4',null,'All external indicators'));
simple(gl,['Kind','Indicator','Payloads','Targets','Techniques'],G.all_iocs,2,-1);
gl.appendChild(el('h4',null,'All targets'));
simple(gl,['Target (file name / site)','Payloads','Source IPs'],G.all_targets,1,-1);
const KN={source_ip:'Source IP',target:'Target',ip:'IP in payload',host:'Host/domain',url:'URL',email:'Email',unc:'UNC host',technique:'Technique'};
host.appendChild(el('div',{class:'legend'},...Object.keys(KN).map(k=>el('span',null,el('i',{style:'background:'+KIND[k]}),KN[k])),...(IN?[['>= 75','#d32f2f'],['25-74','#fb8c00'],['1-24','#fdd835'],['0','#9e9e9e']].map(x=>el('span',null,el('i',{style:'border:3px solid '+x[1]+';width:6px;height:6px;border-radius:50%'}),'AbuseIPDB '+x[0])):[])));
const N=G.nodes.length,adj=G.nodes.map(()=>new Set());for(const l of G.links){adj[l[0]].add(l[1]);adj[l[1]].add(l[0]);}
const cols=[[],[],[],[]];G.nodes.forEach((n,i)=>cols[n[2]].push(i));const RH=24,TOP=30,W=1300,CX=[20,345,670,995];const Y=new Array(N).fill(0);
cols[0].sort((a,b)=>G.nodes[b][3]-G.nodes[a][3]||a-b);cols[0].forEach((i,k)=>Y[i]=k);
const bary=i=>{let s=0,c=0;for(const j of adj[i])if(G.nodes[j][2]<G.nodes[i][2]){s+=Y[j];c++;}return c?s/c:1e9;};
for(const c of [1,2,3]){const b=new Map(cols[c].map(i=>[i,bary(i)]));cols[c].sort((x,y)=>b.get(x)-b.get(y)||G.nodes[y][3]-G.nodes[x][3]||x-y);cols[c].forEach((i,k)=>Y[i]=k);}
const H=TOP+Math.max(...cols.map(c=>c.length))*RH+10;const py=i=>TOP+Y[i]*RH+RH/2,px=i=>CX[G.nodes[i][2]]+8;
const s=sv('svg',{viewBox:'0 0 '+W+' '+H,width:W,height:H});s.appendChild(sv('rect',{x:0,y:0,width:W,height:H,fill:'#1d2433'}));
['Source IPs','Targets','Payload indicators','Techniques'].forEach((t,c)=>{const e=sv('text',{x:CX[c],y:18,class:'gl','font-weight':'bold'});e.textContent=t+' ('+cols[c].length+')';s.appendChild(e);});
const L=G.links.map(l=>{const x1=px(l[0]),y1=py(l[0]),x2=px(l[1]),y2=py(l[1]),m=(x1+x2)/2;
const e=sv('path',{d:'M'+x1+' '+y1+' C'+m+' '+y1+' '+m+' '+y2+' '+x2+' '+y2,fill:'none',stroke:'#7d8aa3','stroke-opacity':.45,'stroke-width':Math.min(4,.7+Math.log2(1+l[2])/2)});s.appendChild(e);return e;});
let pinned=-1;const circles=[],labels=[];
function hl(i){const on=i<0?null:adj[i];const v=j=>!on||j===i||on.has(j);circles.forEach((c,j)=>c.setAttribute('opacity',v(j)?1:.15));labels.forEach((t,j)=>t.setAttribute('opacity',v(j)?1:.15));
L.forEach((e,j)=>{const l=G.links[j];e.setAttribute('stroke-opacity',!on?.45:(l[0]===i||l[1]===i?.95:.04));});}
G.nodes.forEach((n,i)=>{const lbl=n[0]==='technique'?tname(n[1]):n[1];const isip=n[0]==='source_ip'||n[0]==='ip';const full=KN[n[0]]+': '+lbl+(n[0]==='technique'&&!n[1].startsWith('related:')?' ('+n[1]+')':'')+' | '+n[3]+' payload(s)'+(isip?ipi(n[1]):'');const rg=isip&&IN&&IN[n[1]]&&!IN[n[1]].error?ring(IN[n[1]].score):null;
const c=sv('circle',{cx:px(i),cy:py(i),r:Math.min(8,3+Math.log2(1+n[3])*.8),fill:KIND[n[0]]||'#888',stroke:rg||'#fff','stroke-width':rg?3:.8,style:'cursor:pointer'});
const t=sv('text',{x:px(i)+11,y:py(i)+4,class:'gl',style:'cursor:pointer'});t.textContent=lbl.length>32?lbl.slice(0,31)+'\u2026':lbl;
for(const e of [c,t]){e.addEventListener('mouseenter',()=>{if(pinned<0)hl(i);});e.addEventListener('mousemove',ev=>showTip(ev,full));e.addEventListener('mouseleave',()=>{hideTip();if(pinned<0)hl(-1);});
e.addEventListener('click',()=>{pinned=pinned===i?-1:i;hl(pinned);if(PAYTABLE)PAYTABLE.filter(pinned<0?null:new Set(n[4]),KN[n[0]]+' '+lbl);});}
s.appendChild(c);s.appendChild(t);circles.push(c);labels.push(t);});
host.appendChild(el('div',{style:'max-height:820px;overflow:auto;border:1px solid var(--line)'},s));
const rows=G.nodes.map((n,i)=>({kind:KN[n[0]],label:n[0]==='technique'?tname(n[1]):n[1],w:n[3],deg:adj[i].size}));
host.appendChild(el('h3',null,'Graph nodes'));const tt=el('div');host.appendChild(tt);table(tt,[['Kind',r=>r.kind],['Value',r=>r.label],['Payloads',r=>r.w],['Links',r=>r.deg]],rows,{sort:2,dir:-1});})();
"""

HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>Web attack incident report</title><style>{css}</style></head>
<body><header><h1>Web attack incident report</h1><nav><a href="#s-exec">Summary</a><a href="#s-time">Timeline</a><a href="#s-evo">Attack evolution</a><a href="#s-agg">Categories &amp; targets</a><a href="#s-pay">Payloads</a><a href="#s-graph">IOC graph</a><input id="focus" type="search" placeholder="Focus report on (domain, schema, IP, text) + Enter" title="Shows only activity related to this text: attack payloads whose target site, path, parameter, decoded value, summary or source IP contains it. Every section is rebuilt from those payloads. The browser's own find (Ctrl+F) only sees text currently displayed."></nav></header>
<main>
<section id="s-exec"><h2>Executive summary</h2><div id="exec"></div></section>
<section id="s-time"><h2>Attack timeline</h2><div id="timeline"></div></section>
<section id="s-evo"><h2>Attack evolution analysis</h2><div id="evo"></div></section>
<section id="s-agg"><h2>Categories and targets</h2><div id="agg"></div></section>
<section id="s-pay"><h2>Attack payloads (click a row for details)</h2><div id="payloads"></div></section>
<section id="s-graph"><h2>IOC relationship graph</h2><div id="graph"></div></section>
<noscript>JavaScript is required to decode and display this report.</noscript>
</main><div id="tip"></div>
<script type="application/octet-stream" id="d">
{data}
</script>
<script>const KEY=[{key}];{js}</script>
</body></html>
"""


def render(model):
    data = encode(model)
    lines = '\n'.join(data[i:i + 120] for i in range(0, len(data), 120))
    return HTML.format(css=CSS, data=lines, key=','.join(str(b) for b in XOR_KEY), js=JS)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('input')
    ap.add_argument('-o', '--output', help='HTML report to write (required unless --find is used)')
    ap.add_argument('--find', action='append', metavar='TEXT',
                    help='count where TEXT occurs (analysis per category, report data); repeatable; '
                         'the HTML embeds its data encoded, so a text search of the HTML file finds nothing')
    ap.add_argument('--html', help='with --find: also count TEXT inside this existing HTML report (decoded)')
    ap.add_argument('--ioc-top', type=int, default=40, help='IOC nodes shown in the graph (default 40)')
    ap.add_argument('--xor-key-hex', help='key for .pax input (else PAX_KEY_HEX or default)')
    ap.add_argument('--abuseipdb', action='store_true',
                    help='query uncached public IPs on AbuseIPDB (key from env ABUSEIPDB_KEY only)')
    ap.add_argument('--ip-intel', help='AbuseIPDB JSON cache (default: OUTPUT stem + .ip_intel.json)')
    ap.add_argument('--abuseipdb-max', type=int, default=900, help='maximum new lookups this run (default 900)')
    args = ap.parse_args(argv)
    if not args.output and not args.find:
        ap.error('-o/--output is required unless --find is used')
    paxio.configure_key(args.xor_key_hex)
    report = load_report(args.input)
    if args.find:
        html_text = Path(args.html).read_text(encoding='utf-8') if args.html else None
        print(find_text(report, args.find, build_model(report, max(1, args.ioc_top)), html_text))
        if not args.output:
            return 0
    out = Path(args.output)
    cache = Path(args.ip_intel) if args.ip_intel else out.with_name(out.stem + '.ip_intel.json')
    intel = None
    if args.abuseipdb or cache.exists():
        import abuseipdb_check
        if args.abuseipdb:
            key = os.environ.get('ABUSEIPDB_KEY', '').strip()
            if not key:
                ap.error('--abuseipdb needs the ABUSEIPDB_KEY environment variable')
            abuseipdb_check.lookup(report, cache, key, args.abuseipdb_max)
            del key
        cached = abuseipdb_check.load_cache(cache)
        wanted = abuseipdb_check.collect(report, False)
        intel = {ip: intel_entry(cached[ip], wanted[ip]) for ip in sorted(wanted) if ip in cached}
    model = build_model(report, max(1, args.ioc_top), intel)
    html = render(model)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + '.tmp')
    tmp.write_bytes(html.encode('utf-8'))
    tmp.replace(out)
    s = model['scope']
    print(f"wrote {out} ({len(html)} bytes): {sum(s['units'].values())} attack units, "
          f"{s['campaigns']} campaigns, {len(model['graph']['nodes'])} graph nodes")
    return 0


if __name__ == '__main__':
    sys.exit(main())
