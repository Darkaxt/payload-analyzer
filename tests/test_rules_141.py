"""Synthetic catalogue and internal-resource regression cases."""
import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('rules141', Path(__file__).resolve().parents[1] / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class Rules141Tests(unittest.TestCase):
    def result(self, value):
        nodes = [{'node_id': 0, 'value': value}]
        result = a.analyze(nodes)
        a.validate(result, nodes)
        return result

    def check(self, value, rule, category):
        result = self.result(value)
        self.assertIn(rule, result['rule_ids'], value)
        self.assertEqual(category, result['category'], value)

    def test_conditional_probes(self):
        for expr in ('IF((1=2),id,-id)', "IF((LENGTH(('SYNTH'))>3),id,-id)", "IF((ORD(SUBSTRING(('SYNTH'),2,1))>20),id,-id)", 'CASE WHEN (1=0) THEN 1 ELSE 0 END'):
            for value in (expr, json.dumps({'field': expr, 'order': 'ASC'})):
                self.check(value, 'sqli.boolean_blind.conditional_probe', 'sqli')
        for expr in ('IF(price>3,id,-id)', 'IF(LENGTH(label)>3,id,-id)', 'CASE WHEN active THEN 1 ELSE 0 END', 'IF(1=2,id)', 'IF(1=2,id,-id'):
            self.assertNotIn('sqli.boolean_blind.conditional_probe', self.result(expr)['rule_ids'])

    def test_scalar_subqueries(self):
        for value in ('1=(SELECT 1)', "IF(((LENGTH(((SELECT 'xy'))))>2),id,-id)", json.dumps({'onStatisticField': '(SELECT COUNT(*) FROM DUAL@db.invalid)'})):
            self.check(value, 'sqli.scalar_subquery', 'sqli')
        for value in ('(select)', 'Select a record from this menu.', '(SELECT 1'):
            self.assertNotIn('sqli.scalar_subquery', self.result(value)['rule_ids'])

    def test_database_apis(self):
        cases = (
            ("SYSCS_UTIL.SYSCS_EXPORT_QUERY('values 2','C:/sample/out.txt',',',NULL,'UTF-8')", 'sqli.derby_export', 'sqli'),
            ("DBMS_XMLGEN.GETXML('select 2 from dual')", 'sqli.oracle_dynamic_query', 'sqli'),
            ("UTL_FILE.FOPEN('SYNTH_DIR','sample.txt','r')", 'file_access.database_file_api', 'file_access'),
            ("BFILENAME('SYNTH_DIR','sample.txt')", 'file_access.database_file_api', 'file_access'),
            ("UTL_TCP.OPEN_CONNECTION('service.invalid',1)", 'sqli.oracle_network_api', 'sqli'),
            ("SYS_CONTEXT('USERENV','DB_NAME') IS NOT NULL", 'sqli.database_context', 'sqli'),
            ('@@secure_file_priv', 'sqli.database_context', 'sqli'),
            ("VALUES CURRENT_USER", 'sqli.values_query', 'sqli'),
            ("INTO OUTFILE '/tmp/synthetic.txt'", 'sqli.file_output', 'sqli'),
            ('CREATE TABLE synthetic_table (id INTEGER)', 'sqli.database_statement', 'sqli'),
            ('UPDATE synthetic_table SET id=2', 'sqli.database_statement', 'sqli'),
        )
        for value, rule, category in cases:
            self.check(value, rule, category)
        for value in ('SYSCS_UTIL.SYSCS_EXPORT_QUERY', 'UTL_FILE.FOPEN', 'BFILENAME', 'values ordinary', 'create table', 'update your settings'):
            self.assertFalse(self.result(value)['rule_ids'], value)

    def test_complex_select(self):
        self.check('select a.id, cast(a.label as varchar(30)) as label from sample_records a where a.id>2', 'sqli.raw_select', 'sqli')
        self.assertNotIn('sqli.raw_select', self.result('Please select a name from the menu')['rule_ids'])

    def test_paths(self):
        for value in ('../../includes/sample.php', '....//....//opt/sample.txt'):
            self.check(value, 'file_access.path_traversal', 'file_access')
        self.check('/etc/./' + 'pass' + 'wd', 'file_access.system_canary_file', 'file_access')
        for value in ('../sample.txt', '/opt/sample/document.txt', 'C:/sample/document.txt'):
            self.assertNotIn('file_access.path_traversal', self.result(value)['rule_ids'])

    def test_shell_delay(self):
        for value in ('$(sleep 4)', 'x;sleep 4'):
            self.check(value, 'rce.shell_delay', 'rce')
        for value in ('sleep 4', 'please sleep 4 hours', '$(sleep fast)'):
            self.assertNotIn('rce.shell_delay', self.result(value)['rule_ids'])

    def test_internal_resources(self):
        hosts = ('localhost', 'sample.localhost', 'service.internal', 'sample.local', '.'.join(('127', '0', '0', '1')), '.'.join(('10', '0', '0', '2')), '.'.join(('172', '16', '0', '2')), '.'.join(('192', '168', '0', '2')), '[::1]', '[fc00::2]', '[fe80::2]', '[::ffff:127.0.0.1]')
        for host in hosts:
            for value in ('http://' + host + '/sample', json.dumps({'url': 'http://' + host + '/sample'})):
                self.check(value, 'ssrf.internal_resource', 'ssrf')
        for value in ('https://public.invalid/path', 'http://192.0.2.8/', 'http://198.51.100.2/', 'http://203.0.113.2/', 'http://198.18.0.2/', 'http://localhost.public.invalid/', 'http://localhost@public.invalid/', 'http://[2001:db8::2]/', 'http://[invalid]/'):
            self.assertNotIn('ssrf.internal_resource', self.result(value)['rule_ids'], value)

    def test_metadata(self):
        for host in ('.'.join(('169', '254', '169', '254')), 'metadata.google.internal', '[fd00:ec2::254]'):
            self.check('http://' + host + '/sample', 'file_access.cloud_metadata', 'file_access')
        for value in ('file:///opt/sample/config.txt', 'FILE:////opt/sample/config.txt'):
            self.check(value, 'file_access.file_scheme_read', 'file_access')

    def test_precision(self):
        for value in ('http://public.invalid/MapServer/0', json.dumps({'url': 'http://public.invalid/MapServer/0'})):
            self.assertNotIn('sqli.error_based.divide_by_zero', self.result(value)['rule_ids'])
        self.assertNotIn('rce.python_execution', self.result('import sample; obj.exec(2)')['rule_ids'])
        self.assertNotIn('xss.attribute_breakout', self.result('<jsp:root xmlns:jsp="http://schema.invalid/JSP/Page" version="2.0"></jsp:root>')['rule_ids'])
        self.check('\"><svg/onload=alert(2)>', 'xss.attribute_breakout', 'xss')

    def test_protocol_tokens(self):
        import base64
        import zlib
        def packed(xml):
            compressor = zlib.compressobj(wbits=-15)
            return base64.b64encode(compressor.compress(xml.encode()) + compressor.flush()).decode()
        xml = '<s:AuthnRequest xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol" ID="sample" Destination="https://sso.invalid/login"/>'
        token = base64.b64encode(bytes(range(256))).decode()
        relay = 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Ab6Cd7Ef8|abcd123456'
        for value in (token, base64.b64encode(relay.encode()).decode(), relay, packed(xml), 'sample/00000000-0000-0000-0000-000000000000', 'https://schema.invalid/2001/04/algorithm#rsa-sha256', 'ab12' * 16):
            self.assertEqual('not_attack', self.result(value)['category'], value)
        for value in ('1/0', '1' * 32 + '/0', 'SampleIdentifierWithLotsOfLetters/0', '(SELECT 2)', '<script>alert(2)</script>'):
            self.assertIn(self.result(value)['category'], a.DETERMINED_PRIORITY)
            encoded = base64.b64encode(value.encode()).decode()
            nodes = [{'node_id': 0, 'value': encoded}, {'node_id': 1, 'value': value, 'transform': 'base64_decode'}]
            self.assertIn(a.analyze(nodes)['category'], a.DETERMINED_PRIORITY)
        self.assertFalse(a.opaque_protocol_value(packed('SELECT 2 FROM sample_records')))
        self.assertNotEqual('not_attack', self.result(packed('SELECT 2 FROM sample_records'))['category'])
        for body in ('<!DOCTYPE x [<!ENTITY y "sample">]>' + xml, xml.replace('/>', '><script>alert(2)</script></s:AuthnRequest>'), xml.replace('sample', '(SELECT 2)')):
            self.assertFalse(a.opaque_protocol_value(packed(body)))
            self.assertNotEqual('not_attack', self.result(packed(body))['category'])

    def test_priority_and_versions(self):
        self.assertEqual('1.4.1', a.RULE_CATALOGUE_VERSION)
        self.assertEqual('1.9.7', a.ANALYZER_VERSION)
        for value, expected in (('http://localhost/ {{7*7}}', 'rce'), ('http://localhost/ file:///opt/sample/a', 'file_access'), ('http://localhost/ (SELECT 2)', 'sqli'), ('http://localhost/ <script>alert(2)</script>', 'xss')):
            self.assertEqual(expected, self.result(value)['category'])


if __name__ == '__main__':
    unittest.main()
