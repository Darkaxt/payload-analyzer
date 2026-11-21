"""Look up the public IPs of an analyzer report on AbuseIPDB and save the results as JSON.

Usage:
    set ABUSEIPDB_KEY=<your key>          (PowerShell: $env:ABUSEIPDB_KEY = "<your key>")
    python -I abuseipdb_check.py payload_analysis.json -o ip_intel.json [--all-units] [--max 900]

By default only source IPs of attack units (effective category rce / file_access / sqli / xss / ssrf) plus
IPs mentioned in their decoded payloads are checked; --all-units checks every source IP.
Private, loopback, reserved and documentation addresses are skipped. Existing results in the
output file are reused, so re-running only queries new IPs (free plan: 1,000 checks per day).
The key is read from the environment only and is never written anywhere.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paxio  # noqa: E402

API = 'https://api.abuseipdb.com/api/v2/check'
ATTACK = {'rce', 'file_access', 'sqli', 'xss', 'ssrf'}
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def public(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def collect(report, all_units):
    found = {}
    for unit in report.get('units', []):
        category = unit.get('effective_category') or (unit.get('analysis') or {}).get('category')
        attack = category in ATTACK
        if not (attack or all_units):
            continue
        for occ in unit.get('occurrences', []):
            for ip in (occ.get('activity') or {}).get('source_ips') or []:
                found.setdefault(ip, set()).add('source')
            if attack:
                for ip in IPV4.findall(str(occ.get('dec_value') or '')):
                    found.setdefault(ip, set()).add('payload')
    return {ip: sorted(roles) for ip, roles in found.items() if public(ip)}


def check(ip, key):
    query = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90})
    request = urllib.request.Request(API + '?' + query, headers={'Key': key, 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)['data']
    keys = ('abuseConfidenceScore', 'countryCode', 'isp', 'domain', 'usageType', 'totalReports',
            'numDistinctUsers', 'lastReportedAt', 'isTor', 'isWhitelisted', 'hostnames')
    return {k: data.get(k) for k in keys}


def load_cache(path):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')).get('ips', {}) if path.exists() else {}


def lookup(report, cache_path, key, max_new=900, all_units=False):
    """Query uncached public IPs of REPORT, update the JSON cache at CACHE_PATH and return its 'ips'."""
    cache_path = Path(cache_path)
    targets = collect(report, all_units)
    results = load_cache(cache_path)
    todo = [ip for ip in sorted(targets) if ip not in results][:max_new]
    print('[AbuseIPDB] public IPs: {}, cached: {}, to query: {}'.format(
        len(targets), len([ip for ip in targets if ip in results]), len(todo)), file=sys.stderr)
    for n, ip in enumerate(todo, 1):
        try:
            info = check(ip, key)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                print('[AbuseIPDB] daily limit reached; re-run later to continue', file=sys.stderr)
                break
            info = {'error': 'HTTP {}'.format(exc.code)}
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            info = {'error': type(exc).__name__}
        results[ip] = info
        print('[AbuseIPDB] {}/{} {} score={}'.format(n, len(todo), ip, info.get('abuseConfidenceScore', info.get('error'))),
              file=sys.stderr)
        throttle = time.sleep  # stay well under the API rate limit
        throttle(0.2)
    for ip, roles in targets.items():
        if ip in results:
            results[ip]['roles'] = roles
    out = {'source': 'AbuseIPDB /api/v2/check, maxAgeInDays=90', 'ips': dict(sorted(results.items()))}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache_path.with_name(cache_path.name + '.tmp')
    tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')
    tmp.replace(cache_path)
    return out['ips']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('input', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    parser.add_argument('--all-units', action='store_true', help='check source IPs of all units, not only attacks')
    parser.add_argument('--max', type=int, default=900, help='maximum new lookups this run (default 900)')
    parser.add_argument('--xor-key-hex')
    args = parser.parse_args(argv)
    key = os.environ.get('ABUSEIPDB_KEY', '').strip()
    if not key:
        parser.error('set the ABUSEIPDB_KEY environment variable')
    paxio.configure_key(args.xor_key_hex)
    with paxio.open_text_in(args.input) as stream:
        report = json.load(stream)
    lookup(report, args.output, key, args.max, args.all_units)
    print('[Write] {}'.format(args.output), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
