"""Synthetic regressions for substantial families and conservative series promotion."""
import copy
import io
from contextlib import redirect_stderr
import unittest
from unittest.mock import patch
from test_series import a, records


class Series161Tests(unittest.TestCase):
    def report(self, values):
        with redirect_stderr(io.StringIO()):
            return a.build_report(records(values, structured=False))

    def controlled(self, categories, secondary=None, probe='select'):
        values = ['sample' + str(i) for i in range(len(categories))] + [probe]
        original = a.analyze
        def analyze(nodes):
            result = original(nodes)
            value = nodes[0]['value']
            if value.startswith('sample'):
                index = int(value[6:])
                category = categories[index]
                result = copy.deepcopy(result)
                result['category'] = category
                result['rule_ids'] = [category + '.synthetic']
                if secondary and index in secondary:
                    result['rule_ids'].append('file_access.synthetic')
            return result
        with patch.object(a, 'analyze', side_effect=analyze):
            return self.report(values)['series'][0]

    def test_minor_secondary_family_excluded(self):
        series = self.controlled(['sqli'] * 21, secondary={0})
        self.assertNotIn('file_access', series['families'])
        self.assertEqual('sqli', series['members'][-1]['category'])

    def test_five_percent_family_included_but_majority_promotes(self):
        series = self.controlled(['sqli'] * 19 + ['rce'], secondary={0})
        self.assertIn('file_access', series['families'])
        self.assertIn('rce', series['families'])
        self.assertEqual('sqli', series['members'][-1]['category'])

    def test_tie_uses_priority(self):
        series = self.controlled(['sqli', 'rce'])
        self.assertEqual('rce', series['members'][-1]['category'])

    def test_structured_ids_are_benign(self):
        for value in ('IP/0/0', 'PRES/0/0', 'IP/93/58', 'ABC-12_34.56:78'):
            with self.subTest(value=value):
                analysis = a.analyze([{'node_id': 0, 'value': value}])
                self.assertEqual('not_attack', analysis['category'])
                self.assertFalse(analysis['notes'])
        report = self.report(['IP/0/0', 'PRES/0/0', 'IP/93/58'])
        self.assertEqual(0, report['series'][0]['determined_count'])
        self.assertTrue(all(u['effective_category'] == 'not_attack' for u in report['units']))

    def test_odd_syntax_and_keywords_remain_suspicious(self):
        for value in ('IP/0/(0)', "IP/0/'0", 'select/0/0'):
            with self.subTest(value=value):
                self.assertNotEqual('not_attack', a.analyze([{'node_id': 0, 'value': value}])['category'])

    def test_path_probe_never_inherits_rce(self):
        series = self.controlled(['rce', 'rce', 'file_access'], probe='/a/b')
        member = series['members'][-1]
        self.assertEqual('path_probe', member['series_role'])
        self.assertEqual('file_access', member['category'])

    def test_no_substantial_file_family_no_path_promotion(self):
        series = self.controlled(['rce'] * 21, secondary={0}, probe='/a/b')
        member = series['members'][-1]
        self.assertEqual('variant', member['series_role'])
        self.assertNotEqual('rce', member['category'])


if __name__ == '__main__':
    unittest.main()
