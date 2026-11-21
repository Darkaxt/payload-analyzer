"""Shareable report pseudonyms retain diagnostic path details."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sanitize_analyzer', ROOT / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class SanitizeTests(unittest.TestCase):
    def test_span_replacement_preserves_attack_content(self):
        sentence = "This payload's purpose is to test file access"
        unix = '/' + 'etc' + '/' + 'passwd'
        digest = 'abcdef0123456789' * 4
        report = {'source_sha256': digest, 'units': [{
            'target': {'site': 'x.corp-internal.example.net', 'uri_path': '/'},
            'raw_value': sentence, 'unix_payload': unix, 'sql_payload': '1 OR 1=1',
            'windows_path': r'C:\a\private.json',
            'summary': sentence + ' 10.23.45.67',
            'rule_ids': ['file_access.canary', 'sql.boolean'],
            'payload_id': digest, 'event_id': 'a', 'status': 'investigate',
            'actions': ['inspect'], 'transform': 'identity', 'route': '/a',
            'injection_points': ['a']}]}
        result, mapping, _ = a.sanitize_report(report)
        unit = result['units'][0]
        for key in ('raw_value', 'unix_payload', 'sql_payload', 'rule_ids', 'payload_id',
                    'event_id', 'status', 'actions', 'transform', 'route', 'injection_points'):
            self.assertEqual(report['units'][0][key], unit[key])
        self.assertEqual(digest, result['source_sha256'])
        self.assertEqual('/', unit['target']['uri_path'])
        self.assertNotEqual(report['units'][0]['target']['site'], unit['target']['site'])
        self.assertEqual(sentence + ' ' + mapping['10.23.45.67'], unit['summary'])
        self.assertTrue(unit['windows_path'].startswith('C:\\a\\'))
        self.assertNotIn('a', mapping)
        self.assertNotIn('/', mapping)

    def test_sanitize_large_report(self):
        sites = ['portal{:04d}.corp.local'.format(i) for i in range(500)]
        uris = ['/private-api/{:04d}'.format(i) for i in range(3000)]
        ips = ['10.23.{}.{}'.format(i // 254, i % 254 + 1) for i in range(2000)]
        report = {'units': [
            {'unit_id': 'u' + str(i),
             'target': {'site': sites[i % 500], 'uri_path': uris[i % 3000]},
             'raw_value': ips[i % 2000] + ' ' + r'\\SERVER01\private\tenant\record.json' +
                          ' http://' + sites[i % 500] + uris[i % 3000] + '?row=' + str(i)}
            for i in range(30000)]}
        started = time.perf_counter()
        result, _, _ = a.sanitize_report(report)
        elapsed = time.perf_counter() - started
        print('Large sanitize runtime: {:.3f}s'.format(elapsed))
        self.assertLess(elapsed, 30)
        text = json.dumps(result)
        self.assertTrue(all(ip not in text for ip in ips))
        for original in sites + uris:
            self.assertNotIn(original, text)

    def test_sanitize_report(self):
        ip, site, email = '10.23.45.67', 'portal.corp.local', 'alice@corp.local'
        config = r'C:\CorpApp\directories\Tenant\config-store\config-store.json'
        canary = 'C:\\Windows\\' + 'win' + '.ini'
        unc = r'\\SRV01\share\private.json'
        report = {'meta': {'source': ip}, 'series': [{'members': [{'unit_id': 'u1'}]}],
                  'units': [{'unit_id': 'u1', 'target': {'site': site, 'uri_path': '/private-api'},
                             'raw_value': config, 'dec_value': ip,
                             'encoded_raw_values': [
                                 '%5C%5CFILESRV07%5Ccommonservices%5CTenantAcme%5Cx.rptx',
                                 'C%3A%5CAcmeGIS%5CTenantAcme%5Cx.rptx',
                                 '%5C%5C10.20.30.40%5Cx.rlf'],
                             'bare_host': 'Contact FILESRV07 for details',
                             'bare_segments': 'AcmeGIS commonservices',
                             'url': 'http://internal-db.corp-secret.local:8080/admin?x=1;id',
                             'single_host_url': 'http://INTERNAL01:8081/console?y=2#section',
                             'malformed_urls': ['http://[10.1.2.3/x',
                                                'http://10.1.2.4]/y?h=srv.corp-internal.example.net',
                                                'http://user@[fe80::1/z',
                                                'http://internal-host.corp.lan[0]=1/'],
                             'private_paths': [r'\\SRV\share\report.TenantZeta', r'C:\a\x.fe80::abcd'],
                             'path_sentence': r'Reference the UNC path \\SRV\share\x.rptx, which makes sense.',
                             'summary': ' '.join((ip, site, email, config, canary, unc, '/private-api'))}]}
        scratch = Path('E:/Temp/payload-analyzer')
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            source, output, mapping = [Path(folder) / n for n in ('source.json', 'out.json', 'mapping.json')]
            source.write_text(json.dumps(report), encoding='utf-8')
            self.assertEqual(0, a.main(['sanitize', str(source), '-o', str(output), '--mapping', str(mapping)]))
            text = output.read_text(encoding='utf-8')
            actual = json.loads(text)
            for original in (ip, site, email, 'CorpApp', 'Tenant', 'config-store', 'SRV01', '/private-api',
                             '10.1.2.3', '10.1.2.4', 'srv.corp-internal.example.net',
                             'fe80::1', 'internal-host.corp.lan', 'TenantZeta', 'fe80::abcd'):
                self.assertNotIn(original, text)
            self.assertEqual(actual['meta']['source'], actual['units'][0]['dec_value'])
            self.assertIn(actual['meta']['source'], actual['units'][0]['summary'])
            self.assertIn(canary, actual['units'][0]['summary'])
            self.assertTrue(actual['units'][0]['raw_value'].endswith('.json'))
            self.assertIn('.rptx, which', actual['units'][0]['path_sentence'])
            self.assertRegex(actual['units'][0]['url'], r'^http://host\d+\.invalid:8080/admin\?x=1;id$')
            self.assertRegex(actual['units'][0]['single_host_url'], r'^http://host\d+\.invalid:8081/console\?y=2#section$')
            self.assertNotIn('corp-secret', text)
            self.assertNotIn('INTERNAL01', text)
            self.assertTrue(mapping.is_file())
            table = json.loads(mapping.read_text(encoding='utf-8'))
            self.assertEqual(actual['meta']['source'], table[ip])
            unit = actual['units'][0]
            self.assertEqual('%5C%5C' + table['FILESRV07'] + '%5C' + table['commonservices'] +
                             '%5C' + table['TenantAcme'] + '%5C' + table['x.rptx'],
                             unit['encoded_raw_values'][0])
            self.assertEqual('C%3A%5C' + table['AcmeGIS'] + '%5C' + table['TenantAcme'] +
                             '%5C' + table['x.rptx'], unit['encoded_raw_values'][1])
            self.assertEqual('%5C%5C' + table['10.20.30.40'] + '%5C' + table['x.rlf'],
                             unit['encoded_raw_values'][2])
            self.assertEqual('Contact ' + table['FILESRV07'] + ' for details', unit['bare_host'])
            self.assertEqual('AcmeGIS commonservices', unit['bare_segments'])
            for secret in ('FILESRV07', 'commonservices', 'AcmeGIS', 'TenantAcme', '10.20.30.40'):
                self.assertNotIn(secret, ' '.join(unit['encoded_raw_values']))
            self.assertFalse(any(key.startswith('5C') for key in table))
            self.assertNotIn('mapping', actual)
            self.assertNotIn(ip, text)


class SanitizeInputTests(unittest.TestCase):
    def test_raw_export_pseudonymised_including_base64_layers(self):
        import base64
        from urllib.parse import quote_plus
        hidden = base64.b64encode(b'http://10.20.30.40/x?db=corp-secret.lan').decode()
        record = {'result': {
            'site': 'portal.corp-secret.net', 'uri_path': '/acme/api/item',
            'uri_query': ['next=%2Facme%2Fapi%2Fitem&ip=10.20.30.40&blob=' + quote_plus(hidden) +
                          '&q=1+OR+1%3D1&mail=ann%40corp-secret.net&r=https%3A%2F%2Fcorp-secret.net%2Fa%2F%252e%252e%2Fx'],
            'src': ['10.20.30.41', '203.0.113.9'], 'count': '3', 'et': '2026-01-01T00:00:00',
            'lt': '2026-01-02T00:00:00', 'status': ['200'], 'action': 'allowed', 'user': 'alice'}}
        assessor = a.load_assessor()
        out, table, _, residual = a.sanitize_input([record, None], assessor)
        self.assertEqual([], residual)
        self.assertIsNone(out[1])
        rec = out[0]
        text = json.dumps(rec)
        for secret in ('corp-secret', '10.20.30.4', '203.0.113.9', '/acme/', 'alice', 'ann'):
            self.assertNotIn(secret, text)
        self.assertNotIn('user', rec)
        for key in ('count', 'et', 'lt', 'status', 'action'):
            self.assertEqual(record['result'][key], rec[key])
        pairs = {p['name']: p['value'] for p in assessor.query_pairs(rec['uri_query'][0])}
        self.assertEqual('1 OR 1=1', pairs['q'])
        self.assertEqual(table['/acme/api/item'], pairs['next'])
        self.assertEqual(table['10.20.30.40'], pairs['ip'])
        self.assertEqual('http://{}/x?db={}'.format(table['10.20.30.40'], table['corp-secret.lan']),
                         base64.b64decode(pairs['blob']).decode())
        self.assertEqual(table['10.20.30.41'], rec['src'][0])
        # Only entity spans change; other characters keep their exact (here double) encoding.
        self.assertEqual('https://{}/a/%2e%2e/x'.format(table['corp-secret.net']), pairs['r'])

    def test_compressed_base64_layer_pseudonymised(self):
        import base64
        import zlib
        from urllib.parse import quote
        xml = ('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
               'AssertionConsumerServiceURL="https://sp.corp-secret.net/acs" ID="_1"/>')
        packer = zlib.compressobj(9, zlib.DEFLATED, -15)
        value = base64.b64encode(packer.compress(xml.encode()) + packer.flush()).decode()
        record = {'result': {'site': 'idp.corp-secret.net', 'uri_path': '/sso',
                             'uri_query': 'SAMLRequest=' + quote(value, safe='') + '&RelayState=abc'}}
        assessor = a.load_assessor()
        out, table, _, residual = a.sanitize_input([record], assessor)
        self.assertEqual([], residual)
        pairs = {p['name']: p['value'] for p in assessor.query_pairs(out[0]['uri_query'])}
        inflated = zlib.decompress(base64.b64decode(pairs['SAMLRequest']), -15).decode()
        self.assertNotIn('corp-secret', inflated)
        self.assertEqual(xml.replace('sp.corp-secret.net', table['sp.corp-secret.net']), inflated)
        self.assertEqual('abc', pairs['RelayState'])
