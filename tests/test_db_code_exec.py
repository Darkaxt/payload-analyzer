"""Synthetic database execution and expression-channel regressions."""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import payload_analyzer as analyzer
import report_builder as report
from test_report_builder import unit

SN = 'CTXSYS.DRI' + 'THSX.SN'
JAVA = 'DBMS_' + 'JAVA'
A = JAVA + ".RUNJAVA('java.lang.System')"
B = "XMLTYPE('<a/>').transform(XMLTYPE('<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:value-of select=\"''marker''\"/></xsl:template></xsl:stylesheet>')).getStringVal()"
SCHED = "DBMS_SCHEDULER.CREATE_JOB(job_name=>'synthetic',job_type=>'EXECUTABLE',job_action=>'/opt/synthetic/task')"


def sample(expr):
    return "0' AND 1=1/(SELECT COUNT(*) FROM dual WHERE 1=" + SN + "(1,(" + expr + "))) AND '1'='1"


def row(expr):
    value = sample(expr)
    whole = json.dumps([{'REF': '1', 'OBJECT_MODE': 'M', 'ID': value, 'PARAM_NAME': 'n'}])
    nodes = [{'node_id': 0, 'value': whole},
             {'node_id': 1, 'parent_node_id': 0, 'transform': 'json_leaf_extract', 'route': '[0].ID', 'value': value}]
    analysis = analyzer.analyze(nodes)
    u = unit('synthetic', analysis['category'], whole, '2026-01-01 10:00:00')
    u.update(analysis=analysis, decoding_nodes=nodes)
    return report.build_model({'units': [u]})['units'][0]


class DatabaseCodeTests(unittest.TestCase):
    def test_expression_channels(self):
        for expr in [A, B, 'USER', "SYS_CONTEXT('USERENV','CURRENT_USER')"]:
            with self.subTest(expr=expr):
                calls = report.extract_error_channel(SN + '(1,(' + expr + '))')
                self.assertIn(expr, calls[0][1])
                self.assertEqual(report.phase_of('sqli', '', [], {}, expr, calls), 'enumeration')
        for expr in ['1', "'marker'", 'NULL', '-1.25']:
            self.assertFalse(report.extract_error_channel(SN + '(1,' + expr + ')'))
        for cols in ['COUNT(PASSWORDHASH)', 'MAX(LENGTH(PASSWORDHASH))']:
            self.assertEqual(report.phase_of('sqli', '', [], {}, '(SELECT ' + cols + ' FROM s.T)'), 'enumeration')

    def test_database_execution(self):
        for expr, phase in [(A, 'probing'), (JAVA + ".RUNJAVA('example.Task argument')", 'exploitation'),
                            (JAVA + "_TEST.FUNCALL('example.Task','main','argument')", 'exploitation'),
                            (JAVA + ".SET_OUTPUT_TO_JAVA('example.Task','argument')", 'exploitation'),
                            ('CREATE OR REPLACE JAVA SOURCE NAMED synthetic AS public class Example {}', 'exploitation'),
                            (SCHED, 'exploitation'),
                            (SCHED.replace('CREATE_JOB', 'CREATE_PROGRAM').replace('job_', 'program_'), 'exploitation'),
                            ('<xsl:stylesheet xmlns:j="http://xml.apache.org/' + 'xa' + 'lan/java"/>', 'probing'),
                            ('<xsl:stylesheet xmlns:j="java:example.Task"><xsl:value-of select="j:run(1)"/></xsl:stylesheet>', 'exploitation')]:
            with self.subTest(expr=expr):
                analysis = analyzer.analyze([{'node_id': 0, 'value': expr}])
                self.assertEqual(analysis['category'], 'rce')
                self.assertEqual(report.lane_of('rce', analysis['rule_ids']), 'command execution')
                self.assertEqual(report.phase_of('rce', 'command execution', analysis['rule_ids'], analysis, expr), phase)
        self.assertNotIn('rce.database_code_execution', analyzer.analyze([{'node_id': 0, 'value': SCHED.replace('EXECUTABLE', 'PLSQL_BLOCK')}])['rule_ids'])

    def test_json_sections(self):
        for expr, expected in [(A, ('rce', 'probing', 'command execution')),
                               (B, ('sqli', 'enumeration', 'metadata enumeration')),
                               (SCHED, ('rce', 'exploitation', 'command execution'))]:
            result = row(expr)
            self.assertEqual((result['cat'], result['phase'], result['lane']), expected)
            self.assertEqual(len(result['injected']), 1)
            self.assertTrue(result['injected'][0]['text'].startswith('[0].ID: '))

    def test_sql_values_vs_structure(self):
        cases = [(SN + '(1,(SELECT TABLE_NAME FROM ALL_TABLES WHERE R=3))', 'enumeration'),
                 (SN + '(1,(SELECT EMAIL FROM APP.USERS WHERE ROWNUM=1))', 'extraction'),
                 ('ASCII(SUBSTR((SELECT PASSWORDHASH FROM APP.T WHERE ROWNUM=1),1,1))>64', 'extraction'),
                 ('ASCII(SUBSTR((SELECT TABLE_NAME FROM ALL_TABLES WHERE ROWNUM=1),1,1))>64', 'enumeration'),
                 ("CASE WHEN (SELECT COUNT(*) FROM ALL_OBJECTS WHERE OWNER='X')>0 THEN 1 ELSE 0 END", 'probing'),
                 ('SELECT NVL(MAX(LENGTH(PASSWORDHASH)),0) FROM APP.T', 'enumeration'),
                 ('SELECT COUNT(USERNAME) FROM APP.USERS', 'enumeration'),
                 ('SELECT PASSWORD,SPARE4 FROM SYS.USER$', 'extraction'),
                 ('SELECT PASSWORD FROM DBA_USERS', 'extraction'),
                 ('SELECT password_hash FROM sys.sql_logins', 'extraction'),
                 ('SELECT USERNAME FROM DBA_USERS', 'enumeration'),
                 ("SELECT LISTAGG(EMAIL,',') FROM APP.T", 'extraction')]
        cases.extend([
            ('OBJECTID IN (SELECT 1 FROM information_schema.tables)', 'probing'),
            ("1=1 AND LEN('aa')=2", 'probing'),
            ("1=1 AND LENGTH('aa')=2", 'probing'),
            ("1=1 AND CHAR_LENGTH('aa')=2", 'probing'),
            ('1=1 AND @@VERSION IS NOT NULL', 'probing'),
            ('1=1 AND @@VERSION IS NULL', 'probing'),
            ('ASCII(SUBSTR(USER,1,1))>0', 'probing'),
            ('ASCII(SUBSTR((SELECT USER FROM dual),1,1))>0', 'probing'),
            ('1=(SELECT banner FROM v$version WHERE rownum=1)', 'enumeration'),
            ('ASCII(SUBSTR(USER,1,1))>77', 'enumeration'),
            ('LENGTH(USER)>5', 'enumeration'),
            ('IF(((LENGTH(((SELECT user_token FROM app.user WHERE user_id=1))))>68),id,-id)', 'enumeration'),
            ('IF(((LENGTH(((SELECT user_token FROM app.user WHERE user_id=1))))>12),id,-id)', 'enumeration'),
            ('IF(((LENGTH(((SELECT user_token FROM app.user WHERE user_id=1))))>32),id,-id)', 'enumeration'),
        ])
        for expr in ["SYS_CONTEXT('USERENV','HOST')", 'USER', '@@VERSION', 'VERSION()',
                     'DB_NAME()', 'current_user', '(SELECT banner FROM v$version WHERE rownum=1)']:
            for predicate in [' IS NULL', ' IS NOT NULL']:
                cases.append((expr + predicate, 'probing'))
        cases.append(("SYS_CONTEXT('USERENV','HOST') IS NOT NULL AND "
                      "1=(SELECT EMAIL FROM APP.USERS WHERE ROWNUM=1)", 'extraction'))
        for text, phase in cases:
            self.assertEqual(report.phase_of('sqli', '', [], {}, text), phase, text)
