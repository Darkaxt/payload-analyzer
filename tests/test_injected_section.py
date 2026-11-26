"""Synthetic evidence-based report excerpts."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import report_builder as report
from test_report_builder import unit


def sample(text, quotes, rule='sqli.boolean_tautology'):
    value = unit('excerpt', 'sqli', text, '2026-01-01 10:00:00', rules=(rule,))
    value['decoding_nodes'] = [{'node_id': 0, 'value': text, 'transform': 'original'}]
    value['analysis']['techniques'] = [{'rule_id': rule, 'evidence': [
        {'node_id': 0, 'quote': q} for q in quotes]}]
    return value


class InjectedSectionTests(unittest.TestCase):
    def test_json_leaves_order_and_long_values(self):
        expression = '(SELECT synthetic_value FROM synthetic_rows)' + ' ' * 4200
        text = json.dumps([{'safe': 'ok', 'onStatisticField': expression, 'number': 314}])
        value = sample(text, ['314', 'SELECT synthetic_value'])
        sections = report.injected_sections(value, value['analysis'])
        self.assertEqual([s['text'] for s in sections], [
            '[0].onStatisticField: ' + expression, '[0].number: 314'])
        value['decoding_nodes'].append({'node_id': 1, 'parent_node_id': 0,
                                       'transform': 'json_leaf_extract', 'value': expression})
        value['analysis']['techniques'][0]['evidence'] = [{'node_id': 1, 'quote': 'SELECT synthetic_value'}]
        self.assertEqual(report.injected_sections(value, value['analysis'])[0]['text'],
                         '[0].onStatisticField: ' + expression)
        value['analysis']['techniques'][0]['evidence'].extend(
            [{'node_id': 0, 'quote': '314'}, {'node_id': 0, 'quote': 'SELECT synthetic_value'}])
        self.assertEqual(report.injected_sections(value, value['analysis']), sections)

    def test_breakout_scope_omission_and_layer(self):
        text = "ordinary' );  AND 7=7-- synthetic tail"
        value = sample(text, ['AND 7=7'])
        self.assertEqual(report.injected_sections(value, value['analysis'])[0]['text'],
                         "' );  AND 7=7-- synthetic tail")
        value = sample('AND 7=7', ['AND 7=7'])
        self.assertEqual(report.injected_sections(value, value['analysis']), [])
        cases = [
            ("TEST'||to_char(1/0)||'", '1/0', "'||to_char(1/0)||'"),
            ('1;sleep 5', 'sleep', ';sleep 5'),
            ('$(id)', 'id', None),
            ('../../../../etc', '../../../../', None),
            ('https://host1.invalid/\"><svg/onload=alert(1)>', 'onload', '\"><svg/onload=alert(1)>'),
            ('https://host1.invalid/{{7*7}}', '7*7', '{{7*7}}'),
            ("x' AND 1=1-- tail", 'AND', "' AND 1=1-- tail"),
            ('  ../../../../etc  ', '../../../../', None),
            ('prefix ordinary_word tail', 'word', 'ordinary_word tail'),
            ("prefix' AND 1=1 AND 'a'='a' /* tail */  ", '1=1',
             "' AND 1=1 AND 'a'='a' /* tail */  "),
        ]
        for text, quote, expected in cases:
            with self.subTest(text=text):
                candidate = sample(text, [quote])
                sections = report.injected_sections(candidate, candidate['analysis'])
                self.assertEqual([s['text'] for s in sections], [] if expected is None else [expected])
                if text == '$(id)':
                    candidate['final_decoded_value'] = 'opaque'
                    candidate['decoding_nodes'][0].update(
                        parent_node_id=1, transform='text_segment_extract')
                    candidate['decoding_nodes'].append(
                        {'node_id': 1, 'transform': 'url_form_decode', 'value': 'opaque'})
                    self.assertEqual(report.injected_sections(candidate, candidate['analysis']), [])
        value = sample("prefix' AND 7=7", ['AND 7=7'])
        value['final_decoded_value'] = 'opaque'
        value['decoding_nodes'][0]['parent_node_id'] = 2
        value['decoding_nodes'][0]['transform'] = 'base64_decode'
        value['decoding_nodes'].append({'node_id': 2, 'value': 'opaque', 'transform': 'original'})
        self.assertIn('base64_decode', report.injected_sections(value, value['analysis'])[0]['layer'])
        value['analysis']['techniques'][0]['rule_id'] = 'supporting.synthetic'
        self.assertEqual(report.injected_sections(value, value['analysis']), [])

    def test_complete_error_calls(self):
        for call in ['CTXSYS.DRI' + 'THSX.SN(1,(SELECT TABLE_NAME FROM synthetic_rows WHERE R=3))',
                     'CONVERT(INT,(SELECT TOP 1 name FROM synthetic_rows))',
                     'EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))']:
            value = sample('prefix AND ' + call + '-- tail', [call.split('(')[0]], 'sqli.error_based')
            self.assertEqual(report.injected_sections(value, value['analysis'])[0]['text'], call)
            details = report.error_channel_details(value['final_decoded_value'],
                         report.extract_error_channel(value['final_decoded_value'], expressions=True))
            self.assertEqual(details[0], call)
            self.assertIn('SELECT', details[1])

    def test_model_reuses_sections_and_safe_rendering(self):
        value = sample("safe' AND 7=7-- tail", ['AND 7=7'])
        with mock.patch.object(report, 'injected_sections', wraps=report.injected_sections) as extract:
            model = report.build_model({'units': [value]})
            self.assertEqual(extract.call_count, 1)
        row = model['units'][0]
        campaign = model['campaigns'][0]
        self.assertEqual(next(iter(campaign['example_sections'].values()))[0], row['injected'])
        self.assertIn('injected(det,u.injected)', report.JS)
        self.assertIn('injected(d,(c.example_sections[l]||[])[i])', report.JS)
        self.assertIn("el('pre',null,section.text)", report.JS)
        self.assertIn('Error expression', report.JS)
        self.assertEqual(json.loads(report.decode_html(report.render(model))), json.loads(json.dumps(model)))
