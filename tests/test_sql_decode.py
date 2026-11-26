import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_builder as r


class SQLDecodeTests(unittest.TestCase):
    def test_sql_decode(self):
        xml = 'DBMS_' + 'XMLGEN.GETXML'
        cases = [
            ('(SELECT 1 FROM dual)', '1'),
            ("(SELECT 'x' FROM DUAL)", "'x'"),
            ('((SELECT COUNT(*) FROM dual WHERE C)>0)', 'C'),
            ('((SELECT COUNT(*) FROM dual WHERE C)=1)', 'C'),
            ('((SELECT COUNT(*) FROM dual WHERE C)>=1)', 'C'),
            ('(SELECT COUNT(*) FROM dual WHERE C)', '(CASE WHEN C THEN 1 ELSE 0 END)'),
            ('(SELECT COUNT(*) FROM dual)', '1'),
            ('((x))', '(x)'),
            ("syscs_util.syscs_get_database_property('derby.database.sqlAuthorization')",
             "syscs_util.syscs_get_database_property('derby.database.sqlAuthorization')"),
            ("SYS_CONTEXT/**/('USERENV','DB_NAME')", "SYS_CONTEXT('USERENV','DB_NAME')"),
            ("SUBSTRING(MD5(9),1,28)||'x'", "SUBSTRING(MD5(9),1,28)||'x'"),
            ('username||CHR(58)||password', "username||':'||password"),
            ('CHR(0x3a)', "':'"), ('NCHAR(39)', "''''"),
            ("'a'||'b'", "'ab'"), ("'a'+'b'", "'ab'"),
            ("CoNcAt(CoNcAt(x,'.'),y)", "x||'.'||y"),
            ("CONCAT(owner,'.',table_name,CHAR(58))", "owner||'.'||table_name||':'"),
            ('CHAR(113)+CHAR(120)+CHAR(106)', "'qxj'"),
            ('0x6162', "'ab'"), ("X'3C'", "'<'"),
            ("CAST(X'3C' AS VARCHAR(1))", "'<'"),
            ('CHR(10) CHAR(128) 0x00', 'CHR(10) CHAR(128) 0x00'),
            ("'CHR(58)'", "'CHR(58)'"),
            ('AND/**/1=1\n\tAND 2=2', 'AND 1=1 AND 2=2'),
            ('/*!50000 SELECT CHR(58) */', "SELECT ':'"),
            ('/*!50000SELECT*/ 1', 'SELECT 1'),
            ("x' AND 0x61646d696e='admin", "x' AND 'admin'='admin"),
            ("'0x61646d696e'", "'0x61646d696e'"),
            ('col0x61646d696e', 'col0x61646d696e'),
            ('NULL-- -', 'NULL-- -'),
            ('NULL# CHAR(58)', 'NULL# CHAR(58)'),
            ('NULL/* retained */', 'NULL/* retained */'),
            ("EXTRACTVALUE(1,'~'||(SUBSTRING(MD5(9),1,28)))", "EXTRACTVALUE(1,'~'||SUBSTRING(MD5(9),1,28))"),
            ("CONCAT('~',SUBSTRING(MD5(9),1,28))", "'~'||SUBSTRING(MD5(9),1,28)"),
            ('ASCII(SUBSTRING(x,3,1))>77', "ASCII(SUBSTRING(x,3,1))>77 /* 'M' */"),
            (xml + "('SELECT CHR(58) FROM dual')", xml + "('SELECT '':'' FROM dual')"),
            ("EXEC('SELECT CHAR(58)')", "EXEC('SELECT '':''')"),
            ('EXECUTE ' + "IMMEDIATE 'SELECT CHR(58)'", 'EXECUTE ' + "IMMEDIATE 'SELECT '':'''"),
            ("sp_executesql N'SELECT CHAR(58)'", "sp_executesql 'SELECT '':'''"),
            ("SYSCS_UTIL.SYSCS_EXPORT_QUERY('values CHR(58)', 'path')",
             "SYSCS_UTIL.SYSCS_EXPORT_QUERY('values '':''','path')"),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                actual = r.sql_decode(source)
                self.assertEqual(expected, actual)
                self.assertEqual(actual, r.sql_decode(actual))
        long = '+'.join(['CHAR(65)'] * 1000)
        self.assertEqual("'" + 'A' * 1000 + "'", r.sql_decode(long))

    def test_classification_and_sections(self):
        xml = 'DBMS_' + 'XMLGEN.GETXML'
        error = 'CTXSYS.DRI' + 'THSX.SN'
        cases = [
            ('((SELECT COUNT(*) FROM dual WHERE ' + xml + "('SELECT 1 FROM dual') IS NOT NULL)>0)", 'probing'),
            (xml + "('SELECT EMAIL FROM APP.USERS')", 'extraction'),
            (xml + "('SELECT COUNT(*) FROM APP.USERS')", 'enumeration'),
            (error + '(1,((SELECT username||CHR(58)||password FROM user_users)))', 'extraction'),
            (error + '(1,' + xml + "('SELECT 1 FROM dual'))", 'probing'),
            (error + '(1,' + xml + "('SELECT COUNT(*) FROM APP.USERS'))", 'enumeration'),
            ("SYSCS_UTIL.SYSCS_EXPORT_QUERY('SELECT EMAIL FROM APP.USERS','path')", 'extraction'),
            ("CAST('x' AS INT)", 'probing'),
            ("EXTRACTVALUE(1,CONCAT(CHAR(126),SUBSTRING(MD5(999999999),1,28)))", 'probing'),
            ("convert(int,(select sys.fn_sqlvarbasetostr(HashBytes('MD5','127381'))))", 'probing'),
            ("convert(int,(select @@version))", 'extraction'),
            ("EXTRACTVALUE(1,CONCAT(CHAR(126),SUBSTRING(USER,1,28)))", 'extraction'),
        ]
        probe = '((SELECT COUNT(*) FROM dual WHERE ' + xml + "('SELECT 1 FROM dual') IS NOT NULL)>0)"
        self.assertEqual(xml + "('SELECT 1 FROM dual') IS NOT NULL", r.sql_decode(probe))
        self.assertEqual([{'text': xml + "('SELECT 1 FROM dual') IS NOT NULL",
                           'layer': '', 'label': 'Decoded SQL'}],
                         r.injected_sections({'effective_category': 'sqli', 'final_decoded_value': probe}, {}))
        for whole in ["values CAST(X'3C' AS VARCHAR(1))", 'CHAR(113)+CHAR(120)+CHAR(106)',
                      '1 AND IF(ASCII(SUBSTRING((SELECT email FROM app.users LIMIT 1),3,1))>77,' + 'SLE' + 'EP(5),0)']:
            self.assertEqual('Decoded SQL', r.injected_sections(
                {'effective_category': 'sqli', 'final_decoded_value': whole}, {})[0]['label'])
        self.assertEqual([], r.injected_sections(
            {'effective_category': 'rce', 'final_decoded_value': 'CHAR(65)'}, {}))
        query = 'SELECT owner FROM SYS.All_Tab_Columns WHERE ROWNUM=1'
        wrapper = "0' AND 1=1/(SELECT COUNT(*) FROM dual WHERE 1=" + error + '(1,((' + query + ")))) AND '1'='1"
        self.assertEqual("0' AND 1=1/(CASE WHEN 1=" + error + '(1,(' + query + ")) THEN 1 ELSE 0 END) AND '1'='1", r.sql_decode(wrapper))
        for text, phase in cases:
            with self.subTest(text=text):
                self.assertEqual(phase, r.phase_of('sqli', '', [], {}, text))
        text = error + '(1,((SELECT username||CHR(58)||password FROM user_users)))'
        unit = {'final_decoded_value': text, 'decoding_nodes': [{'node_id': 0, 'value': text}]}
        sections = r.injected_sections(unit, {})
        self.assertEqual('Decoded SQL', sections[0]['label'])
        self.assertEqual('Error-based extraction', sections[1]['label'])
        self.assertEqual(r.sql_decode(text), sections[0]['text'])
        self.assertEqual(1, sum(s.get('label') == 'Decoded SQL' for s in sections))
        from test_injected_section import sample
        for text, quote in [('1=(SELECT 1)', 'SELECT'), ('1=1 AND/**/1=1', 'AND'),
                            ("1=1 AND ASCII('a')=97", 'ASCII')]:
            candidate = sample(text, [quote])
            sections = r.injected_sections(candidate, candidate['analysis'])
            self.assertEqual([r.sql_decode(text)], [s['text'] for s in sections
                                                   if s.get('label') == 'Decoded SQL'])
        candidate = sample('SELECT 1  ', ['SELECT'])
        self.assertFalse(any(s.get('label') == 'Decoded SQL' for s in r.injected_sections(candidate, candidate['analysis'])))
        candidate = sample('SELECT CHAR(65)', ['CHAR'])
        candidate['effective_category'] = 'ssrf'
        self.assertFalse(any(s.get('label') == 'Decoded SQL' for s in r.injected_sections(candidate, candidate['analysis'])))
        import json
        expression = 'IF((ORD((SELECT token FROM app.t)))>63,id,-id)'
        for data, path in [({'field': expression, 'order': 'ASC'}, 'field'),
                           ([{'field': expression, 'order': 'ASC'}], '[0].field')]:
            document = json.dumps(data)
            candidate = sample(document, ['ORD'])
            sections = r.injected_sections(candidate, candidate['analysis'])
            decoded = [s for s in sections if s.get('label') == 'Decoded SQL']
            self.assertEqual(1, len(decoded))
            self.assertEqual(path + ': ' + r.sql_decode(expression), decoded[0]['text'])
            self.assertFalse(any(s['text'].startswith(('{', '[' + '{')) for s in decoded))
        url = 'http://127.0.0.1:80/example\n'
        document = json.dumps({'url': url})
        candidate = sample(document, ['127.0.0.1'], 'ssrf.synthetic')
        candidate['effective_category'] = 'ssrf'
        self.assertFalse(any(s.get('label') == 'Decoded SQL' for s in r.injected_sections(candidate, candidate['analysis'])))
        from test_report_builder import unit as make_unit
        constant_calls = ["updatexml(1,concat(0x7e,'abc'),1)", 'UTL_' + "INADDR.GET_HOST_NAME('a'||'b')"]
        units = [make_unit(str(i), 'sqli', call, '2026-01-01 10:00:00', rules=('sqli.error_based',))
                 for i, call in enumerate(constant_calls)]
        rows = r.build_model({'units': units})['evo']['error_channel']
        self.assertEqual(2, len(rows))
        self.assertTrue(all(row[8] == 'probing' for row in rows))
        for call in ["CAST('x' AS INT)", "EXTRACTVALUE(1,CONCAT(CHAR(126),SUBSTRING(MD5(999999999),1,28)))",
                     "convert(int,(select sys.fn_sqlvarbasetostr(HashBytes('MD5','127381'))))"]:
            self.assertTrue(all(s['label'] == 'Error-based probe' for s in r.injected_sections(
                {'effective_category': 'sqli', 'final_decoded_value': call}, {})
                if s.get('label', '').startswith('Error-based')))
        details = r.error_channel_details(error + '(1,' + xml + "('SELECT EMAIL FROM APP.USERS WHERE ROWNUM=1'))")
        self.assertIn('APP.USERS', details[2])
        self.assertIn('ROWNUM=1', details[3])
        self.assertIn('EMAIL', details[1])
