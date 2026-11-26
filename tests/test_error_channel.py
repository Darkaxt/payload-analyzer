"""Synthetic error-channel classification and report regression coverage."""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import payload_analyzer as analyzer
import report_builder as report
from test_report_builder import unit

SN = 'CTXSYS.DRI' + 'THSX.SN'
QUERY = 'SELECT TABLE_NAME FROM (SELECT TABLE_NAME,ROWNUM R FROM ALL_' + 'TABLES) WHERE R=3'


class ErrorChannelTests(unittest.TestCase):
    def test_channels(self):
        query = '(SELECT sample_value FROM synthetic_rows WHERE item_key=3)'
        values = [
            SN + '(1,' + query + ')',
            'CTXSYS.CTX_' + 'REPORT.TOKEN_TYPE(' + query + ')',
            'UTL_' + 'INADDR.GET_HOST_NAME(' + query + ')',
            'UTL_' + 'INADDR.GET_HOST_ADDRESS(' + query + ')',
            'XML' + 'Type(' + query + ')',
            'DBMS_' + 'XDBUTIL_INT.XMLCLOBTOrAW(' + query + ')',
            'ORDSYS.ORD_' + 'DICOM.GETMAPPINGXPATH(' + query + ')',
            'CON' + 'VERT(int,' + query + ')',
            'CA' + 'ST(' + query + ' AS int)',
            'EXTRACT' + 'VALUE(1,CONCAT(0x7e,' + query + '))',
            'UPDATE' + 'XML(1,CONCAT(0x7e,' + query + '),1)',
            'GTID_' + 'SUBSET(CONCAT(0x7e,' + query + '),1)',
            'EX' + 'P(~' + query + ')',
        ]
        for value in values:
            with self.subTest(value=value):
                nodes = [{'node_id': 0, 'value': '1 AND 1=' + value}]
                result = analyzer.analyze(nodes)
                analyzer.validate(result, nodes)
                self.assertIn('sqli.error_based', result['rule_ids'])
                self.assertTrue(report.extract_error_channel(value))
                self.assertEqual(report.phase_of('sqli', '', result['rule_ids'], result, value), 'extraction')

    def test_probes_and_exact_subqueries(self):
        for text in [SN + '(1,1)', '1/0']:
            self.assertFalse(report.extract_error_channel(text))
            self.assertEqual(report.phase_of('sqli', '', [], {}, text), 'probing')
        self.assertFalse(report.extract_error_channel(SN + "(1,'(SELECT sample_value FROM synthetic_rows)')"))
        q = "SELECT COUNT(*) FROM ALL_" + "TABLES WHERE OWNER='APP'"
        for value in ["1' AND 1=" + SN + '(1,(' + q + '))--',
                      "1' AND 1=" + SN + '(1,(' + q + ")) AND 'a'='a"]:
            self.assertEqual(report.extract_error_channel(value), [(SN, [q])])
            self.assertEqual(report.phase_of('sqli', '', [], {}, value), 'enumeration')
        for expr in ['COUNT(*)', 'LENGTH(USER)', 'MAX(LENGTH(token))', 'MIN(LENGTH(token))',
                     'NVL(MAX(LENGTH(token)),0)']:
            for submitted in [expr, 'SELECT ' + expr + ' FROM synthetic_rows']:
                self.assertEqual(report.phase_of('sqli', '', [], {}, SN + '(1,(' + submitted + '))'), 'enumeration')
        for expr in ['USER', 'VERSION()', "SYS_CONTEXT('USERENV','HOST')", 'COUNT(*)+1',
                     'MAX(token)', 'NVL(USER,0)', 'SELECT TABLE_NAME FROM ALL_TABLES']:
            self.assertEqual(report.phase_of('sqli', '', [], {}, SN + '(1,(' + expr + '))'), 'extraction')
        probe = report.injected_sections({'final_decoded_value': SN + '(1,1)'}, {})
        self.assertEqual(probe, [{'text': SN + '(1,1)', 'layer': '', 'label': 'Error-based probe'}])
        call = SN + '(1,((SELECT owner FROM SYS.All_Tab_Columns WHERE ROWNUM=1)))'
        value = "0' AND 1=1/(SELECT COUNT(*) FROM dual WHERE 1=" + call + ") AND '1'='1"
        evidence = {'techniques': [{'rule_id': 'sqli.error_based',
                                   'evidence': [{'node_id': 0, 'quote': SN + '('}]}]}
        section_unit = {'final_decoded_value': value, 'decoding_nodes': [{'node_id': 0, 'value': value}]}
        self.assertEqual(report.injected_sections(section_unit, evidence),
                         [{'text': call, 'layer': '', 'label': 'Error-based extraction'}])
        count = SN + '(1,(SELECT COUNT(*) FROM APP.USERS))'
        for text, expected in [(count, 'Error-based enumeration'), (SN + '(1,1)', 'Error-based probe')]:
            section_unit['final_decoded_value'] = '1=' + text
            section_unit['decoding_nodes'][0]['value'] = '1=' + text
            self.assertEqual(report.injected_sections(section_unit, evidence),
                             [{'text': text, 'layer': '', 'label': expected}])
        section_unit['final_decoded_value'] = '1=' + call + ' AND 2=' + count
        section_unit['decoding_nodes'][0]['value'] = section_unit['final_decoded_value']
        self.assertEqual(report.injected_sections(section_unit, evidence),
                         [{'text': call, 'layer': '', 'label': 'Error-based extraction'},
                          {'text': count, 'layer': '', 'label': 'Error-based enumeration'}])
        self.assertEqual(report.phase_of('sqli', 'x', [], {}, "1' AND (SELECT PASS FROM USERS WHERE ID=1)='a"),
                         'extraction')
        query = 'SELECT /* synthetic */ sample_value\n FROM synthetic_rows WHERE item_key=3'
        self.assertEqual(report.extract_error_channel(SN + '(1,(' + query + '))'), [(SN, [query])])
        self.assertFalse(report.extract_error_channel('CAST((SELECT sample_value FROM synthetic_rows) AS text)'))
        for selector in ['ROWNUM=3', 'R=3', 'OFFSET 3', 'LIMIT 1 OFFSET 3', 'TOP 1', 'WHERE item_key=3']:
            q = 'SELECT ' + ('TOP 1 ' if selector == 'TOP 1' else '') + 'sample_value FROM synthetic_rows '
            if selector != 'TOP 1':
                q += selector
            self.assertIn(selector, report.error_channel_details(SN + '(1,(' + q + '))')[3])

    def test_model_order_counts_and_full_text(self):
        long_query = QUERY + " AND '" + 'x' * 5000 + "'='synthetic'"
        values = [SN + '(1,(' + long_query + '))', SN + '(1,(SELECT COUNT(*) FROM ALL_' + 'TABLES))', SN + '(1,1)']
        units = [unit(str(i), 'sqli', v, '2026-01-01 10:00:0' + str(2-i),
                      rules=('sqli.error_based', 'sqli.oracle_dictionary_query'), status='500')
                 for i, v in enumerate(values)]
        with mock.patch.object(report, 'extract_error_channel', wraps=report.extract_error_channel) as parse:
            model = report.build_model({'units': units})
            self.assertEqual(parse.call_count, 2 * len(units))
        rows = model['evo']['error_channel']
        self.assertEqual([r[9] for r in rows], [['1'], ['0']])
        self.assertEqual(rows[1][2:4], [2, '500'])
        self.assertEqual(rows[1][5], long_query)
        self.assertIn('ALL_' + 'TABLES', rows[1][6])
        self.assertIn('R=3', rows[1][7])
        for u in model['units']:
            if u['id'] == '0':
                self.assertEqual((u['lane'], u['phase']), ('data extraction / inference', 'extraction'))
            elif u['id'] == '1':
                self.assertEqual((u['lane'], u['phase']), ('metadata enumeration', 'enumeration'))
            else:
                self.assertEqual(u['phase'], 'probing')
        self.assertEqual(model, report.build_model({'units': list(reversed(units))}))
        # Equal timestamps must use submitted query, not input order, as the tie-breaker.
        for u in units:
            u['occurrences'][0]['activity']['first_seen'] = '2026-01-01 10:00:00 UTC'
        tied = report.build_model({'units': units})['evo']['error_channel']
        self.assertEqual(tied, sorted(tied, key=lambda r: (r[0], r[1], r[5], r[9][0])))

    def test_focus_javascript(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for focus-mode integration coverage')
        units = [unit(str(i), 'sqli', SN + '(1,(SELECT sample_value FROM synthetic_rows WHERE item_key=' + str(i) + '))',
                      '2026-01-01 10:00:00', rules=('sqli.error_based',)) for i in range(2)]
        model = report.build_model({'units': units})
        js = report.JS[report.JS.index('function focusModel'):report.JS.index('function decode')]
        script = js + '\nconst D=' + json.dumps(model) + ';focusModel(D,"item_key=1");console.log(JSON.stringify(D.evo.error_channel));'
        result = subprocess.run([node, '-e', script], check=True, capture_output=True, text=True)
        rows = json.loads(result.stdout)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0][2], rows[0][9]), (2, ['1']))
        self.assertIn('Error-channel extraction', report.JS)
        self.assertIn('error-channel extraction payload(s) were submitted', report.JS)
