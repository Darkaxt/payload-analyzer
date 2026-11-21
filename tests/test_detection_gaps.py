"""Synthetic request-definition and expression regression cases."""
import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('gaps', Path(__file__).resolve().parents[1] / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class DetectionGapTests(unittest.TestCase):
    def result(self, value):
        nodes = [{'node_id': 0, 'value': value}]
        result = a.analyze(nodes)
        a.validate(result, nodes)
        return result['category']

    def test_request_definitions(self):
        for value in ('GET http://remote.invalid/sample HTTP/1.1', json.dumps({'method': 'GET', 'uri': 'http://remote.invalid/sample'}), 'j' + 'dbc:mysql://remote.invalid:3306/sample', "{!xml" + "parser v='http://remote.invalid/sample'}x"):
            self.assertEqual('ssrf', self.result(value), value)
        from urllib.parse import quote
        self.assertEqual('ssrf', self.result(quote("{!xml" + "parser v='http://remote.invalid/sample'}x", safe='!')))

    def test_internal_fetch_schemes(self):
        for scheme in ('gop' + 'her', 'ftp', 'dict'):
            self.assertEqual('ssrf', self.result(scheme + '://localhost:6379/_INFO'))
            self.assertNotIn(self.result(scheme + '://public.invalid/sample'), a.DETERMINED_PRIORITY)

    def test_database_expressions(self):
        for value in ("(CASE WHEN ((SYS.UTL_" + "INADDR.GET_HOST_ADDRESS('remote.invalid')='192.0.2.1')) THEN 1 ELSE 0 END)=1", "schema.invalid(1,'x')=1", "1=1 AND LENGTH('synthetic')=9"):
            self.assertEqual('sqli', self.result(value), value)
        for value in ("UPPER(label)='A'", "LENGTH(label)>10", "CASE WHEN active THEN 1 ELSE 0 END", '''type=page AND text ~ "UPPER('a')='A'"''', '''project=SYNTH AND summary ~ "LENGTH('abc')=3"'''):
            self.assertNotIn(self.result(value), a.DETERMINED_PRIORITY)

    def test_shell_transfer(self):
        value = 'where cu' + 'rl & cu' + 'rl.exe -sk -m 8 -o NUL -w "%{http_code}" https://remote.invalid/sample'
        self.assertEqual('rce', self.result(value))
        self.assertNotIn(self.result('https://remote.invalid/sample'), a.DETERMINED_PRIORITY)

    def test_embedded_resources(self):
        for tag, attr in (('iframe', 'src'), ('object', 'data'), ('img', 'src')):
            self.assertEqual('xss', self.result('<' + tag + ' ' + attr + '="http://192.0.2.1/sample">SYNTH</' + tag + '>'))
        for value in ('<b>SYNTH</b>', '<img src="sample.png">'):
            self.assertNotIn(self.result(value), a.DETERMINED_PRIORITY)

    def test_legitimate_and_redirect_values(self):
        for value in (json.dumps({'url': 'https://public.invalid/arcgis/rest/services/Sample/MapServer/0'}), 'https://sso.invalid/login', '//redirect.invalid/sample', '/\\redirect.invalid', 'https://a@b.invalid/', "type=page AND text~'synthetic'", "project = SYNTH AND text ~ 'synthetic'", '{{#externalredirect:https://remote.invalid/%0d%0aSet-Cookie:x=y}}', '{{#externalredirect:ftp://localhost/sample}}'):
            self.assertNotIn(self.result(value), a.DETERMINED_PRIORITY, value)
