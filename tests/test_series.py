"""Deterministic differential analysis with encoded synthetic fixtures."""
import base64
from contextlib import redirect_stderr
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import copy
import zlib
from urllib.parse import quote_plus

CATALOGUE_BLOB = (
    'eNqNkVFLwzAQgP9KuacOSksVQQp7UNY3UZlP0pUQ06ONpElMYlkR/7tJO7Hbg9tD'
    'uR6XfPfd5Qss67CnZEBjuZJQ5AlYZ7hsLRRVncBADafShQwc7zG1AlHHtytIgBDe'
    'a2UcIfFuKu5gtawz6qLMAzKh2syO0nXoOEt95otKo4wnCBPUWkL8P+6RhTBQ4cNE'
    '8nFuAl6mQUFHYj4FQgGGYapH1ylJmGqQcPmOzPkh0qBCprP+tjbqDc/eCe0+hD+R'
    'R3ePm+jloSyf45swhMO9C8PzZj3X8nUepP7Sq9/0abspt9H9a3QdZBm1GNZWwaHj'
    'bK+V5Y4PGNDH+6wuG6lOqtp/x1SJLV1QzRJbX0xeYOe1LWQP7/UP6tRsRizMAgKb'
    'c0Zeo/7+AfF45Hg='
)
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('series_analyzer', ROOT / 'payload_analyzer.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
DATA = json.loads(zlib.decompress(base64.b64decode(CATALOGUE_BLOB)))


def records(values, structured=True, path='/series', offset=0):
    result = []
    for i, value in enumerate(values, offset):
        text = json.dumps([{'REF': 'synthetic', 'MODE': 'Q', 'ID': 207,
                            'NAME': 'sample', 'VALUE': value, 'SRC': 'fixture'}]) if structured else value
        result.append({'source_parameter': {'name': 'p', 'raw_value': quote_plus(text),
                                            'url_decoded_value': text},
                       'decoding_nodes': [{'node_id': 0, 'transform': 'url_decode', 'value': text}],
                       'target': {'site': 'example.invalid', 'uri_path': path},
                       'activity': {'first_seen': i, 'last_seen': i + 1,
                                    'source_ips': ['192.0.2.' + str(i % 2 + 1)], 'request_count': i + 1}})
    return result


class SeriesTests(unittest.TestCase):
    def test_promoted_file_access_categories(self):
        rows = records(['C:\\Windows\\' + 'win' + '.ini',
                        'C:\\CorpApp\\config-store.json', 'C:\\CorpApp\\other.json'], structured=False)
        for row in rows:
            row['source_parameter']['name'] = 'Report_Template'
        report = a.build_report(rows)
        probes = [m for m in report['series'][0]['members'] if m['series_role'] == 'path_probe']
        self.assertEqual(2, len(probes))
        for member in probes:
            self.assertEqual('file_access', member['category'])
            self.assertEqual('undetermined', member['own_category'])
        for unit in report['units']:
            self.assertEqual('file_access', unit['effective_category'])
        self.assertEqual(3, report['meta']['effective_category_counts']['file_access'])
        self.assertEqual(1, report['meta']['category_counts']['file_access'])

    def test_file_access_series_path_probes(self):
        values = ['C:\\Windows\\' + 'win' + '.ini', 'C:\\Windows\\missing-control.ini',
                  'C:\\app\\config\\settings.json', 'C:\\app\\config\\other.json',
                  'C:\\app\\config\\third.json', '\\\\host.invalid\\x.rlf',
                  '\\\\192.0.2.10\\x.rlf']
        rows = records(values, structured=False)
        for row in rows:
            row['source_parameter']['name'] = 'Report_Template'
        report = a.build_report(rows)
        series = report['series'][0]
        self.assertGreaterEqual(series['determined_count'], 2)
        self.assertEqual(['determined', 'path_probe', 'path_probe', 'path_probe',
                          'path_probe', 'determined', 'determined'],
                         [m['series_role'] for m in series['members']])
        self.assertIn('and 4 path probes', series['summary'])
        self.assertIn('path_probe', series['families'])
        for unit in report['units']:
            if unit['series_role'] == 'path_probe':
                self.assertEqual('series', unit['determined_via'])
                self.assertIn('path probe', unit['series_description'])
        self.assertEqual(7, len(a.determined_report(report)['units']))

    def test_json_series_normalized_leaves(self):
        items = []
        for i, (field, order) in enumerate([('name', 'asc'), ('Name  ', ' DESC'),
                                            ('id/**/', 'asc'), ('title', 'desc,SL' + 'EEP(5)'),
                                            ('a"b', 'ASC  ')]):
            raw = json.dumps({'field': field, 'order': order, 'page': 1})
            items.append({'source_parameter': {'name': 'sort', 'url_decoded_value': raw,
                                                'raw_value': raw},
                          'decoding_nodes': [{'node_id': 0, 'parent_node_id': None,
                                              'transform': 'url_form_decode', 'route': '',
                                              'value': raw}],
                          'target': {'site': 's', 'uri_path': '/p'},
                          'activity': {'first_seen': 1767225600 + i,
                                       'last_seen': 1767225600 + i, 'request_count': 1}})
        report = a.build_report(items)
        self.assertTrue(all('series_error' not in unit for unit in report['units']))
        self.assertEqual(1, len(report['series']))
        self.assertEqual(['.field', '.order'], report['series'][0]['injection_points'])
        member = next(unit for unit in report['units'] if unit['first_seen'] == 1767225603)
        self.assertTrue(any(node.get('transform') == 'json_leaf_extract'
                            for node in member['decoding_nodes']))
        self.assertNotEqual('undetermined', member['analysis']['category'])

    def test_nonfinite_json_series_serializes(self):
        for token in ('NaN', 'Infinity', '-Infinity', '1e400'):
            with self.subTest(token=token), redirect_stderr(io.StringIO()):
                values = ['{"fixed":"sample","value":' + token + ',"other":' + str(i) + '}'
                          for i in range(3)]
                rows = records(values, structured=False)
                for row in rows:
                    row['decoding_nodes'][0]['components'] = json.loads(values[0])
                scratch = Path('E:/Temp/payload-analyzer')
                scratch.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(dir=scratch) as folder:
                    for suffix in ('.json', '.jsonl'):
                        source = Path(folder) / ('resolutions' + suffix)
                        source.write_text(json.dumps(rows) if suffix == '.json' else
                                          '\n'.join(json.dumps(row) for row in rows), encoding='utf-8')
                        loaded = list(a.load_resolutions(source))
                        json.dumps(loaded, allow_nan=False)
                        report = a.build_report(loaded)
                        json.dumps(report, allow_nan=False)
                self.assertEqual(3, len(report['units']))
                self.assertEqual(1, len(report['series']))
                self.assertFalse(any(n.get('transform') == 'json_leaf_extract'
                                     for u in report['units'] for n in u['decoding_nodes']))
                json.dumps(report, allow_nan=False)

    def test_series_member_analysis_failure_isolated(self):
        rows = records(['a', 'b', 'c'])
        original = a.analyze
        baseline = original(copy.deepcopy(rows[1]['decoding_nodes']))
        def failing(nodes):
            if any(n.get('transform') == 'json_leaf_extract' and n['value'] == 'b' for n in nodes):
                nodes[0]['value'] = 'mutated'
                raise ValueError('synthetic failure')
            return original(nodes)
        progress = io.StringIO()
        with patch.object(a, 'analyze', side_effect=failing), redirect_stderr(progress):
            report = a.build_report(rows)
        failed = next(u for u in report['units'] if u['first_seen'] == 1)
        self.assertEqual('ValueError: synthetic failure', failed['series_error'])
        self.assertEqual(baseline, failed['analysis'])
        self.assertEqual(rows[1]['decoding_nodes'], failed['decoding_nodes'])
        self.assertEqual('variant', failed['series_role'])
        self.assertIn('route=[0].VALUE: ValueError: synthetic failure', progress.getvalue())
        self.assertEqual(3, len(report['series'][0]['members']))
        for unit in report['units']:
            if unit is failed:
                continue
            self.assertNotIn('series_error', unit)
            self.assertTrue(any(n.get('transform') == 'json_leaf_extract' for n in unit['decoding_nodes']))
            self.assertEqual(original(unit['decoding_nodes']), unit['analysis'])

    def test_large_json_series_with_interleaved_rows(self):
        rows = records(['value-' + str(i) for i in range(5000)])
        for index in (1000, 2500, 4000):
            stray = records(['unrelated-' + str(index)], structured=False, offset=index)[0]
            stray['activity']['first_seen'] = index - 0.5
            rows.insert(index, stray)
        progress = io.StringIO()
        started = time.perf_counter()
        with redirect_stderr(progress):
            report = a.build_report(rows, generated_at='fixed')
            scratch = Path('E:/Temp/payload-analyzer')
            scratch.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as folder:
                output = Path(folder) / 'report.json.pax'
                a.atomic_write_json(output, report)
                self.assertIn('[Write] ' + str(output), progress.getvalue())
        elapsed = time.perf_counter() - started
        print('Large JSON series regression: {:.3f}s'.format(elapsed))
        self.assertLess(elapsed, 20)
        series = next(s for s in report['series'] if s['injection_points'] == ['[0].VALUE'])
        self.assertEqual(5000, series['value_count'])
        self.assertEqual(5000, len(series['members']))
        self.assertEqual(5003, len(report['units']))
        self.assertIn('[Analyze] analysed=2000/5003', progress.getvalue())
        self.assertIn('[Analyze] analysed=4000/5003', progress.getvalue())
        self.assertIn('[Series] buckets=1/1 series=2', progress.getvalue())

    def test_pipeline_includes_baseline_values(self):
        scratch = Path('E:/Temp/payload-analyzer')
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            source, output = Path(folder) / 'input.json.pax', Path(folder) / 'report.json.pax'
            values = ['1', '2', '3', DATA['text'][0][3:].replace('1 AND', '3 AND', 1)]
            rows = [{'result': {'site': 'example.invalid', 'uri_path': '/list',
                                'uri_query': '?page=' + quote_plus(value), 'src': '192.0.2.1',
                                'et': i, 'lt': i, 'count': '1', 'status': '200', 'action': 'allowed'}}
                    for i, value in enumerate(values, 1)]
            with a.paxio.open_text_out(source) as stream:
                for row in rows:
                    stream.write(json.dumps(row) + '\n')
            self.assertEqual(0, a.main(['pipeline', str(source), '-o', str(output)]))
            with a.paxio.open_text_in(output) as stream:
                report = json.load(stream)
            with a.paxio.open_text_in(output.with_name('report.determined.json.pax')) as stream:
                selected = json.load(stream)
            self.assertEqual(4, len(report['units']))
            series = report['series'][0]
            self.assertEqual('/list', series['target']['uri_path'])
            self.assertEqual('page', series['parameter_name'])
            self.assertEqual(['whole value'], series['injection_points'])
            self.assertEqual(1, series['determined_count'])
            self.assertEqual(['variant'] * 3 + ['determined'], [m['series_role'] for m in series['members']])
            self.assertEqual('sqli', series['members'][-1]['category'])
            self.assertEqual(1, len(selected['units']))
            self.assertEqual(3, selected['meta']['excluded_units'])
            self.assertEqual(3, selected['meta']['excluded_requests'])
            self.assertNotIn('0 keyword probes', series['summary'])
            benign = a.build_report(records(['a', 'b', 'c']))
            self.assertIn('it includes no determined values.', benign['series'][0]['summary'])
            text = a.build_report(records(DATA['text'], structured=False))
            self.assertIn("the varying text after 'id=1 '", text['series'][0]['summary'])
            self.assertEqual(0, a.main(['pipeline', str(source), '-o', str(output), '--assessor-matched-only']))
            with a.paxio.open_text_in(output) as stream:
                matched = json.load(stream)
            self.assertEqual(1, len(matched['units']))
            self.assertEqual([], matched['series'])

    def test_json_series_and_extraction(self):
        report = a.build_report(records(DATA['variants']), generated_at='fixed')
        self.assertEqual(1, len(report['series']))
        series = report['series'][0]
        self.assertEqual(['[0].VALUE'], series['injection_points'])
        self.assertEqual(9, series['value_count'])
        unit = next(u for u in report['units'] if any(n['value'] == DATA['variants'][1]
                                                    for n in u['decoding_nodes']))
        self.assertIn(DATA['delay_rule'], unit['analysis']['rule_ids'])
        leaf = next(n for n in unit['decoding_nodes'] if n.get('transform') == 'json_leaf_extract')
        self.assertEqual('[0].VALUE', leaf['route'])
        self.assertEqual(DATA['variants'][1], leaf['value'])
        self.assertEqual(0, leaf['parent_node_id'])
        for unit in report['units']:
            a.validate(unit['analysis'], unit['decoding_nodes'])
        # Occurrences of identical values contribute their own scoped activity.
        extra = records([DATA['variants'][0]], path='/other', offset=40)
        scoped = a.build_report(records(DATA['variants']) + extra)
        self.assertEqual(9, scoped['series'][0]['value_count'])
        self.assertIsNone(next(u for u in scoped['units'] if u['first_seen'] == 40)['series_id'])

    def test_python_delay_not_database_delay(self):
        for value in DATA['variants'][:2]:
            analysis = a.analyze([{'node_id': 0, 'value': value}])
            self.assertIn(DATA['delay_rule'], analysis['rule_ids'])
            self.assertFalse(any(r.startswith('sqli.') for r in analysis['rule_ids']))
        sql = a.analyze([{'node_id': 0, 'value': DATA['sql']}])
        self.assertEqual('sqli', sql['category'])
        self.assertTrue(any(r.startswith('sqli.time_based.') for r in sql['rule_ids']))

    def test_neighbours_and_benign_series(self):
        rows = records(DATA['variants'] + ['2']) + records(['a', 'b', 'c'], path='/benign', offset=20)
        report = a.build_report(rows)
        selected = a.determined_report(report)
        keywords = [u for u in report['units'] if u.get('series_role') == 'keyword_probe']
        self.assertTrue(keywords)
        self.assertTrue(all(u['determined_via'] == 'series' and u in selected['units'] for u in keywords))
        benign = next(s for s in report['series'] if s['target']['uri_path'] == '/benign')
        self.assertEqual(0, benign['determined_count'])
        self.assertTrue(all(m['series_role'] == 'variant' for m in benign['members']))
        variants = [u for u in report['units'] if u.get('series_role') == 'variant']
        self.assertTrue(variants)
        self.assertTrue(all(u not in selected['units'] and 'determined_via' not in u for u in variants))
        self.assertEqual(1, len(selected['series']))

    def test_text_series(self):
        report = a.build_report(records(DATA['text'], structured=False))
        series = report['series'][0]
        self.assertEqual([{'prefix': 'id=1 ', 'suffix': ''}], series['injection_points'])
        self.assertEqual([v[5:] for v in DATA['text']], [m['injected_value'] for m in series['members']])
        self.assertEqual(3, series['value_count'])

    def test_exclusions_cli_and_deterministic_bytes(self):
        rows = records(DATA['variants']) + records(['a', 'b', 'c'], path='/benign', offset=20)
        rows[-1]['activity']['request_count'] = None
        report = a.build_report(rows, generated_at='fixed')
        selected = a.determined_report(report)
        excluded = [u for u in report['units'] if u not in selected['units']]
        self.assertEqual(3, selected['meta']['excluded_units'])
        self.assertEqual(43, selected['meta']['excluded_requests'])
        self.assertEqual(3, len(excluded))
        scratch = Path('E:/Temp/payload-analyzer')
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            source, output = Path(folder) / 'source.json.pax', Path(folder) / 'report.json.pax'
            a.atomic_write_json(source, rows)
            snapshots = []
            for _ in range(2):
                self.assertEqual(0, a.main([str(source), '-o', str(output)]))
                pair = []
                for path in (output, output.with_name('report.determined.json.pax')):
                    with a.paxio.open_text_in(path) as stream:
                        actual = json.load(stream)
                    actual['meta'].pop('generated_at')
                    pair.append(json.dumps(actual, ensure_ascii=False, indent=2).encode())
                snapshots.append(pair)
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertEqual(3, json.loads(snapshots[0][1])['meta']['excluded_units'])
