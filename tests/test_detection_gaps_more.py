"""Additional synthetic syntax probes and precision boundaries."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('more_gaps', Path(__file__).resolve().parents[1] / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class MoreDetectionGapTests(unittest.TestCase):
    def result(self, value):
        nodes = [{'node_id': 0, 'value': value}]
        result = a.analyze(nodes)
        a.validate(result, nodes)
        return result

    def test_command_and_el(self):
        for value in ('cu' + 'rl.exe -s -m 4 -o NUL -w "TEST:%{http_code}|%{errormsg}" http://remote.invalid/', '#{7*7}', '#{ 11 + 22 }', '<'+ '%=7*7%>', '@(7*7)', '#if(7>6)Y#end', '%24%7B7*7%7D', '%3C%25%3D%207*7%20%25%3E', 'di' + 'r /b "C:/synthetic/*.jsp"', 'de' + 'l /f /q "C:/synthetic/sample.jsp"', '<?php fi' + 'le_put_contents("sample.txt","synthetic");'):
            self.assertEqual('rce', self.result(value)['category'], value)
        for value in ('#{user}', 'cu' + 'rl.exe', 'Use cu' + 'rl.exe to read documentation.'):
            self.assertNotIn(self.result(value)['category'], a.DETERMINED_PRIORITY)

    def test_sql_conditions(self):
        for value in ("US'-- -", 'ROWNUM<=1', '1%3D1 AND 1%3D2', "1=1 AND ASCII('a')=97", '1=2', '1=1 AND (1)=1', 'ASCII(SUBSTR(USER,1,1))>0', "SYS_CONTEXT('USERENV','HOST') IS NOT NULL", 'SYS.DBMS_UTILITY.GET_TIME>0'):
            self.assertEqual('sqli', self.result(value)['category'], value)
        for value in ('1=1', '(1)=1', 'active=1', "US'", "US\\'", "X'", "'", "O'Brien"):
            self.assertNotIn(self.result(value)['category'], a.DETERMINED_PRIORITY, value)

    def test_values_expressions(self):
        for value in ("values length('abc')", 'values SYSIBM.CHR(60)', "values X'3C'", "values UPPER(TRIM('a'))", 'values 1+1', "values 'a'||'b'", 'values chr(60)||chr(37)||chr(62)'):
            self.assertEqual('sqli', self.result(value)['category'], value)
        for value in ('values', 'values ordinary', 'values from a list'):
            self.assertNotIn(self.result(value)['category'], a.DETERMINED_PRIORITY)

    def test_style_resource(self):
        value = '<style>@font-face{src:url(http://192.0.2.7/f.woff)}</style>'
        self.assertEqual('xss', self.result(value)['category'])
        for value in ('<div style="background-image:url(http://192.0.2.7/b.png)">SYNTH</div>', '<embed src="http://192.0.2.7/sample">', '%3Cscript%3Ealert(1)%3C%2Fscript%3E', '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'):
            self.assertEqual('xss', self.result(value)['category'], value)
        self.assertNotIn(self.result('<style>body{color:blue}</style>')['category'], a.DETERMINED_PRIORITY)

    def test_server_classes_path(self):
        for value in ('C:/Program Files/Apache Software Foundation/Tomcat 9.0/webapps/synthetic/WEB-INF/classes/sample.properties', '/opt/tomcat/webapps/synthetic/WEB-INF/classes/sample.properties'):
            result = self.result(value)
            self.assertEqual('file_access', result['category'], value)
            self.assertIn(value, result['artifacts']['file_paths'])
        for value in ('/docs/WEB-INF/classes/sample.txt', 'C:/sample/document.txt', 'WEB-INF/classes/sample.properties'):
            self.assertNotIn(self.result(value)['category'], a.DETERMINED_PRIORITY)

    def test_unsupported_and_legitimate(self):
        for value in ('{!bool should=test}test', 'process|INIT', 'Ordinary wiki title', '{"kty":"RSA","e":"AQAB","n":"synthetic"}', 'text ~ "password"', 'type=page AND text ~ "ROWNUM<=1"', 'project=SYNTH AND summary ~ "ASCII(97)=97"'):
            self.assertNotIn(self.result(value)['category'], a.DETERMINED_PRIORITY, value)
