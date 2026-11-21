"""Synthetic catalogue regression cases; no incident data."""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rules140', ROOT / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class Rules140Tests(unittest.TestCase):
    def analyze(self, value):
        return a.analyze([{'node_id': 0, 'value': value}])

    def assert_rule(self, value, rule, category):
        result = self.analyze(value)
        self.assertIn(rule, result['rule_ids'], value)
        self.assertEqual(category, result['category'], value)
        a.validate(result, [{'node_id': 0, 'value': value}])

    def test_conditional_subqueries(self):
        for value in (
            'IF((SELECT COUNT(*) FROM sample_records WHERE active=1)>2,id,-id)',
            'CASE WHEN (SELECT COUNT(*) FROM sample_records)>2 THEN id ELSE -id END',
            'CASE WHEN EXISTS(SELECT id FROM sample_records) THEN id ELSE -id END',
        ):
            with self.subTest(value=value):
                self.assert_rule(value, 'sqli.conditional_subquery', 'sqli')

    def test_nested_ordering_subqueries(self):
        for target in ('sample_schema.sample_table', 'host96.invalid', 'sample_table'):
            for depth in (2, 3, 4):
                query = "SELECT COUNT(sample_column) FROM " + target + " WHERE label LIKE '%sample%'"
                expr = 'IF(' + '(' * (depth + 1) + query + ')' * depth + '>3),id,-id)'
                for key in ('sort', 'where', 'sql', 'outStatistics'):
                    with self.subTest(target=target, depth=depth, key=key):
                        self.assert_rule(json.dumps({key: expr}), 'sqli.conditional_subquery', 'sqli')

    def test_database_function_inference(self):
        expressions = (
            'IF((ASCII(SUBSTR((USER_NAME()),2,1))>3),id,-id)',
            'IF((LENGTH(DB_NAME())>3),id,-id)',
            'IF((ORD(MID(DATABASE(),2,1))=3),id,-id)',
            'IF((ASCII(SUBSTRING(VERSION(),2,1))<3),id,-id)',
            'IF((LENGTH(USER())>3),id,-id)',
            'IF((LEN(CURRENT_USER)>3),id,-id)',
            "CASE WHEN LENGTH(SYS_CONTEXT('USERENV','CURRENT_SCHEMA'))>3 THEN id ELSE -id END",
        )
        for expr in expressions:
            for key in ('sort', 'where', 'sql', 'outStatistics'):
                with self.subTest(expr=expr, key=key):
                    self.assert_rule(json.dumps({key: expr}), 'sqli.boolean_blind.function_inference', 'sqli')
        for value in ('IF((LENGTH(label)>3),id,-id)', 'IF((LENGTH(display_name())>3),id,-id)', 'IF((price>3),id,-id)', 'ASCII(SUBSTR(USER_NAME(),2,1))', 'name', '-date', 'id asc', json.dumps({'field': 'name', 'order': 'desc'})):
            self.assertFalse(any(r.startswith('sqli.') for r in self.analyze(value)['rule_ids']), value)

    def test_dictionary(self):
        for view in ('ALL_ARGUMENTS', 'ALL_DB_LINKS', 'DBA_TABLES', 'USER_OBJECTS', 'V$PARAMETER'):
            self.assert_rule('SELECT name FROM ' + view, 'sqli.oracle_dictionary_query', 'sqli')
        self.assert_rule("ROWNUM <= ASCII(SUBSTR((SELECT name FROM ALL_ARGUMENTS),2,1))", 'sqli.oracle_dictionary_query', 'sqli')
        self.assert_rule("SELECT LISTAGG(name,',') FROM V$PARAMETER", 'sqli.oracle_dictionary_query', 'sqli')

    def test_raw_query(self):
        for value in ('select id from sample_records', 'select id,name from sample_records fetch first 2 rows only', 'select count(*) from sample_records where active=1'):
            self.assert_rule(value, 'sqli.raw_select', 'sqli')

    def test_comment_truncation(self):
        for value in ("operator'--", "operator'#", 'operator"--'):
            self.assert_rule(value, 'sqli.comment_truncation', 'sqli')

    def test_template_arithmetic(self):
        for value in ('${7*7}', '{{7*7}}', '#set($x=7*7)$x', '*{7*7}', '${3+4}{{8*2}}'):
            self.assert_rule(value, 'rce.template_expression_probe', 'rce')

    def test_local_file_urls(self):
        for value in ('file:///opt/sample/config.txt', 'file:///C:/sample/config.txt'):
            self.assert_rule(value, 'file_access.file_scheme_read', 'file_access')
        self.assert_rule('file://files.invalid/share/config.txt', 'file_access.unc_remote_path', 'file_access')

    def test_python_call_required(self):
        self.assert_rule('time.' + 'sleep' + '(2)', 'rce.python_code_injection.time_delay', 'rce')
        for value in (
            json.dumps([{'REF': 'record-1', 'OBJECT_MODE': 'edit', 'label': 'time delay'}]),
            json.dumps({'input_json': [{'REF': 'record-2', 'OBJECT_MODE': 'view'}]}),
            'time.sleep', 'time delay 2',
        ):
            self.assertFalse(any(rule.startswith('rce.') for rule in self.analyze(value)['rule_ids']))

    def test_xss(self):
        for value, rule in (
            ('<script>alert(1)</script>', 'xss.script_element'),
            ('\"><img src=x onerror=alert`2`>', 'xss.event_handler'),
            ('<svg onload="alert(2)">', 'xss.event_handler'),
            ('javascript:alert(2)', 'xss.javascript_uri'),
            ('{{#externalredirect:javascript:alert(2)}}', 'xss.javascript_uri'),
            ('\"><b>sample</b>', 'xss.attribute_breakout'),
            ('" title="sample">', 'xss.attribute_breakout'),
        ):
            with self.subTest(value=value):
                self.assert_rule(value, rule, 'xss')
                self.assertFalse(any(r.startswith('rce.') for r in self.analyze(value)['rule_ids']))

    def test_arithmetic_identifier_boundary(self):
        for value in ('IP/0/0', 'PRES/0/0', 'IP/93/58', 'ABC/12/0'):
            self.assertEqual('not_attack', self.analyze(value)['category'])
        for value in ("x' AND 1/0", '(SELECT 1/0)', 'n/0'):
            self.assert_rule(value, 'sqli.error_based.divide_by_zero', 'sqli')

    def test_negative_values(self):
        for value in ('name', '-date', 'id asc', 'Please select a record from the menu.', 'select', 'ALL_ARGUMENTS', 'V$PARAMETER', '${name}', '{{name}}', '*{name}', 'description', 'onboard', '2 < 3', '4 > 2', 'https://example.invalid/path', 'ordinary text'):
            with self.subTest(value=value):
                self.assertEqual('not_attack', self.analyze(value)['category'])


if __name__ == '__main__':
    unittest.main()
