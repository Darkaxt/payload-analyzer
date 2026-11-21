"""Request paths carrying injection syntax are analysed as the '(uri path)' pseudo-parameter."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


asr = load('payload_assessor', 'payload_assessor.py')
pa = load('path_units_analyzer', 'payload_analyzer.py')


def record(path, query=''):
    return {'result': {'site': 'site1.invalid', 'uri_path': path, 'uri_query': query, 'src': '192.0.2.10', 'count': 3}}


class PathUnitTests(unittest.TestCase):
    def path_units(self, path):
        units = list(asr.analyze_record(record(path), 1, 4))
        return [u for u in units if u['source_parameter']['name'] == asr.PATH_PARAMETER]

    def test_plain_paths_are_skipped(self):
        for path in ('/', '/api/v1/users', '/plain/path/index.html', '/a-b_c/~d/e.f'):
            self.assertEqual([], self.path_units(path), path)

    def test_payload_paths_become_units(self):
        cases = {
            '/static/%2e%2e/%2e%2e/%2e%2e/et' + 'c/pas' + 'swd': 'file_access',
            "/search/x'%20OR%201=1--": 'sqli',
            '/p/%3Cscr' + 'ipt%3Ealert(1)%3C/script%3E': 'xss',
        }
        for path, cat in cases.items():
            units = self.path_units(path)
            self.assertEqual(1, len(units), path)
            u = units[0]
            self.assertEqual(path, u['target']['uri_path'])
            self.assertEqual(3, u['activity']['request_count'])
            self.assertEqual(-1, u['source_parameter']['query_index'])
            self.assertEqual(cat, pa.analyze(u['decoding_nodes'])['category'], path)

    def test_java_path_parameter_traversal(self):
        for path in ('/app/servlet/..;/manager/html',
                     '/app/%2e%2e;/manager/html', '/app/..%3b/manager/html'):
            units = self.path_units(path)
            self.assertEqual(1, len(units), path)
            result = pa.analyze(units[0]['decoding_nodes'])
            self.assertEqual('file_access', result['category'], path)
            self.assertIn('file_access.path_traversal', result['rule_ids'])

    def test_ordinary_path_punctuation(self):
        for path in ('/docs/My%20File.pdf', '/docs/My File.pdf', '/a/b(1).html'):
            units = self.path_units(path)
            self.assertEqual(1, len(units), path)
            self.assertEqual('not_attack', pa.analyze(units[0]['decoding_nodes'])['category'], path)

    def test_path_commands_keep_rce_priority(self):
        for suffix in (';wh' + 'oami', ';/' + 'bin/id', ';/' + 'bin/sh -c id'):
            path = '/app/..;/manager/html' + suffix
            units = self.path_units(path)
            self.assertEqual('rce', pa.analyze(units[0]['decoding_nodes'])['category'], path)

    def test_query_units_unchanged(self):
        units = list(asr.analyze_record(record('/plain', 'q=%27x'), 1, 4))
        self.assertEqual(['q'], [u['source_parameter']['name'] for u in units])

    def test_sanitize_keeps_path_syntax(self):
        path = '/portal1/secret2/%2e%2e/%2e%2e/et' + 'c/pas' + 'swd'
        recs = [record(path), record('/portal1/secret2/page3')]
        out, table, counts, residual = pa.sanitize_input(recs, asr)
        clean = out[0]['uri_path']
        self.assertNotIn('portal1', clean)
        self.assertNotIn('secret2', clean)
        self.assertIn('%2e%2e/%2e%2e/et' + 'c/pas' + 'swd', clean)
        self.assertTrue(clean.startswith('/seg'))
        self.assertTrue(out[1]['uri_path'].startswith('/path'))
        self.assertEqual([], residual)

    def test_sanitize_pseudonymises_hosts_in_path(self):
        out, *_ = pa.sanitize_input([record('/redirect//www.corp1.example.com/x%3Cy')], asr)
        self.assertNotIn('corp1', out[0]['uri_path'])


if __name__ == '__main__':
    unittest.main()
