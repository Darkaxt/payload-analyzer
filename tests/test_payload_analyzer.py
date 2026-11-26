"""Offline evidence processing with encoded, nonexecutable JSON data."""
import base64 as _base64
import json as _json
import zlib as _zlib

CATALOGUE_BLOB = (
    'eNp1Vm1vGzcM/isHY2iAoo6XoA26DBnQdGmQdVuXOO2Q1YOgu6N9inXSRZT80i7/'
    'fSTvzrGb9IOtE0lR1MOHlL4OsKig1moBAY13g+ODF4Pal8nC4HgQASOO+F81em29'
    'LpV22q6/QNhv1oMXA4zBuBkOjj8PvjUg7dNraj0HNTWrmAIgzdtNesFoR92u+MZC'
    'IwKiD8qn2KS4f4ve7c++kGGK0+FrGkOkP7KHUqIIuoYIQTka2cqZyBtDCJ7DlPDQ'
    'oMKoY8Jtybcm7JugUabkT8Pu3+qorZ8lyFiDWW0QCZOs8WiiWUBWaJRzfs/QgQ5D'
    'nmws8c4a5XxUoYB2qiqPsQuftTQUOsLMB8ZHh2imupBDFb6utZPwaPV+OyiswFrV'
    '6ZRxt1BEyrbqg+zMPG5sAhSP9Ow+eESKrYTWgvMJUfeoqujpkDTj6HWMupjTJAdn'
    'Zk5sSk5EbZxkBhM2pjA+oUqu1pGYyOI/rn/kU13ZTx8u19Xhzd+rg3/G8xPWjE9P'
    'r+eXM3hzwtP35jUP+vwT5uevXXn40zo/v2TRzTgaiaLkXNHXQtvE8ZcUdEmoyxFa'
    '9hWVM3epBT5CI6PAhTCrwbVUWZgSnCBwl3zs00BhM4oIlvDcBmsPU1EQSffklISo'
    '5OmzNXR6wYfRvsVGLSFvN1sG0m27GPkmjgqSmkLbkSaWNw/s67L72EMfWO69Be1U'
    '1Cl6Yt1627W2S73GYQxpazbVFiXD3lEduKh6wY6/3BoihwU3ixVzhYprJ+qpCRiz'
    '8dl4fPHhT/XX1cWncRb8kjQn2aunnRWVDk+5aj+9yw5o8kt29JKGg5OD3kk0Naic'
    'KqZUaAGa7aWvMmRylviEsQ+6IAwb0+zspqUguEytR8hiBRkmqn6iLNGlKyxiQ0a5'
    'nEt3kxTqhVYhOfEPKyh2DgBkQkAK51jgqI8Jw1OwaupD/aDi2I5ePsyhzqEsKVw2'
    'JXaGtXpEYQLOOAFqSc1bOEAcpfW8xbLyuuYa+Hj9bnhw9PtZdipbiAMkXjXSAEoI'
    'ZqH5E3vXtGmEVZTyCbW2hjq3uvWy1ZakuzBUh8uuclkRF7HRff8y+z6fJix0B7KI'
    'touHCf/8+YiGN6ebApRSww6vPrYehhWjVFS+bYUMQ/Az6vT09TP9/qPfs2f05ykN'
    'OkoXh1+jvTmsFhdvf6s+HF6YbdH5OyDRya6o6EUCaxi1MfTJ5++dhE8JcbvutE3V'
    'CCPSU422WceKpN/Vc3e6xaf13VpMOZ2Ym8wmwJJu6VjxmSk51hNFujm7nBruHK6w'
    'qdwhfgyaU6kt1QwRrW1yYsyL2fktlYCyTLJ+UsJUJxs3SnCLXtZ3pnaNnyfuWlfA'
    'd3adW8j2WLO3y8LOzXBjL8fpyk5bm9M1sm8cZV46H9+Fm61LLbfPGdeLVG3Pjx++'
    'UlTHH8dnV/cy41I97kh733IK29cB1+jDTUF4OOTi5JPQC0OqcUVSjtlMpxBatsvT'
    '4OHCk+B024DXjgKhvp11Qm5im5cE9ZmFieu+VxL/QSrCJyFG/1jZebhQm4TV9v5Z'
    'H5kvCupSnDUUAubB8MOAD5L1l0cWDM7l7t6dT1xbHk7qXUmBo64bC/Kk4lNR4dSm'
    '6C4nFjLUx5PJNdTNZNK974b9+24y6d5owzwZK5cUND60L7R2ZruWsIHIODpgSD0P'
    'Gn7LCKBK1dTelBr8e/8/kyHKDw=='
)
_DATA = _json.loads(_zlib.decompress(_base64.b64decode(CATALOGUE_BLOB)))
def _text(index):
    return _DATA['strings'][index]

import base64
import gzip
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
a = load_module(_text(0), ROOT / _text(1))
generator = load_module(_text(2), ROOT / _text(3))
FIXTURE = ROOT / _text(4)

def decode64(value):
    return base64.b64decode(value).decode(_text(5))

class AnalyzerTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with gzip.open(FIXTURE, _text(6), encoding=_text(5)) as stream:
            cls.items = json.load(stream)
        cls.report = a.build_report(cls.items, generated_at=_text(7))
        cls.by_name = {u[_text(8)]: u for u in cls.report[_text(9)]}

    def test_catalogue_positive_and_near_miss_per_rule(self):
        (positives, negatives) = (set(), set())
        for (name, value, required, forbidden) in generator.CASES:
            with self.subTest(case=name):
                unit = self.by_name[name]
                self.assertNotEqual(_text(10), unit[_text(11)], unit.get(_text(12)))
                result = unit[_text(13)]
                for rule in required:
                    positives.add(rule)
                    self.assertIn(rule, result[_text(14)], value)
                for rule in forbidden:
                    negatives.add(rule)
                    self.assertNotIn(rule, result[_text(14)], value)
        cases = [
            ("john.doe@corp.example'" + " OR " + "'1'=" + "'1", True),
            ('"' + ' AND ' + '"x"=' + '"x"--', True),
            ("')" + " OR (" + "'a'=" + "'a", True),
            ("O'Brien" + " or 1 more", False),
            ("it's a " + "'quote' or 'other'", False),
            ("rock " + "'n' roll", False),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                nodes = [{'node_id': 0, 'value': value}]
                result = a.analyze(nodes)
                self.assertEqual(expected, result['category'] == 'sqli')
                if expected:
                    self.assertIn('sqli.boolean_tautology', result['rule_ids'])
                a.validate(result, nodes)
        rid = 'rce.database_code_execution'
        for value, expected in [('DBMS_' + "JAVA.RUNJAVA('example.Task')", True),
                                ("DBMS_SCHEDULER.CREATE_JOB(job_type=>'PLSQL_BLOCK')", False)]:
            result = a.analyze([{'node_id': 0, 'value': value}])
            self.assertEqual(rid in result['rule_ids'], expected)
            (positives if expected else negatives).add(rid)
        catalogue = {r[_text(15)] for r in a.CATALOGUE
                     if r['handler'] not in ('file_access', 'include_wrapper_execution')
                     and r['handler'] not in a._DATA.get('generic_probe', {})}  # Covered in test_rules_140.
        self.assertEqual(set(), catalogue - positives, _text(16))
        self.assertEqual(set(), catalogue - negatives, _text(17))

    def test_file_access_rule_matrix(self):
        cases = [
            ('C:\\Windows\\' + 'win' + '.ini', 'file_access', 'system_canary_file'),
            ('/etc/' + 'passwd', 'file_access', 'system_canary_file'),
            ('../' * 2 + 'etc/sample', 'file_access', 'path_traversal'),
            ('../../css/site.css', None, None),
            ('../' * 4 + 'var/x', 'file_access', 'path_traversal'),
            ('//cdn.example.com/lib/x.js', None, None),
            ('data:' + '//text/plain;base64,PD9waHAgZWNobyAxOyA/Pg==', 'rce', 'include_wrapper_execution'),
            ('data:' + 'text/plain,sample', 'rce', 'include_wrapper_execution'),
            ('..\\..\\' + 'boot' + '.ini', 'file_access', 'system_canary_file'),
            ('\\\\192.0.2.10\\x.rlf', 'file_access', 'unc_remote_path'),
            ('\\\\host.invalid\\x.rlf', 'file_access', 'unc_remote_path'),
            ('Report_A.rptx', None, None),
            ('https://host.invalid/sample', None, None),
            ('C:\\app\\config\\settings.json', None, None),
            ('../', None, None),
            ('php:' + '//input', 'rce', 'include_wrapper_execution'),
            ('php:' + '//filter/convert.base64-encode/resource=sample.php', 'file_access', 'include_wrapper_read'),
            ('/proc/self/' + 'environ', 'file_access', 'system_canary_file'),
        ]
        for value, category, suffix in cases:
            with self.subTest(value=value):
                result = a.analyze([{'node_id': 0, 'value': value}])
                if category:
                    self.assertEqual(category, result['category'])
                    self.assertIn(category + '.' + suffix, result['rule_ids'])
                    a.validate(result, [{'node_id': 0, 'value': value}])
                else:
                    self.assertNotIn(result['category'], ('rce', 'sqli', 'file_access'))
                    self.assertEqual([], result['rule_ids'])

    def test_sql_identifiers_are_not_commands(self):
        for name in (_text(18), _text(19)):
            result = self.by_name[name][_text(13)]
            self.assertEqual(_text(20), result[_text(21)])
            self.assertEqual([], result[_text(22)][_text(23)])
            self.assertFalse(any((r.startswith(_text(24)) for r in result[_text(14)])))
        for name in (_text(25), _text(26)):
            self.assertEqual(_text(27), self.by_name[name][_text(13)][_text(21)])
        self.assertNotEqual(_text(27), self.by_name[_text(28)][_text(13)][_text(21)])

    def test_default_includes_all_and_conservative_benign(self):
        self.assertEqual(len(self.report[_text(9)]), self.report[_text(29)][_text(30)])
        self.assertEqual(_text(31), self.by_name[_text(32)][_text(13)][_text(21)])
        self.assertEqual(_text(33), self.by_name[_text(34)][_text(13)][_text(21)])
        # A standalone false constant is now an explicit SQL condition probe.
        self.assertEqual('sqli', a.analyze([{'node_id': 0, 'value': decode64(_text(35))}])['category'])
        for text in (decode64(_text(36)), decode64(_text(37)), decode64(_text(38)), decode64(_text(39)), decode64(_text(40))):
            self.assertEqual(_text(33), a.analyze([{_text(41): 0, _text(42): text}])[_text(21)])
        filtered = a.build_report(self.items, exclude_not_attack=True)
        self.assertTrue(all((u[_text(13)] is None or u[_text(13)][_text(21)] != _text(31) for u in filtered[_text(9)])))
        self.assertLess(len(filtered[_text(9)]), len(self.report[_text(9)]))

    def test_evidence_artifacts_prose_and_derivations(self):
        for unit in self.report[_text(9)]:
            with self.subTest(unit=unit[_text(8)]):
                self.assertIsNotNone(unit[_text(13)], unit.get(_text(12)))
                (result, nodes) = (unit[_text(13)], unit[_text(43)])
                a.validate(result, nodes)
                values = {n[_text(41)]: n[_text(42)] for n in nodes}
                for entry in result[_text(44)] + result[_text(45)] + result.get(_text(46), []):
                    self.assertTrue(entry[_text(47)])
                    for ev in entry[_text(47)]:
                        self.assertEqual(int, type(ev[_text(41)]))
                        self.assertIn(ev[_text(48)], values[ev[_text(41)]])
                for artifacts in result[_text(22)].values():
                    for artifact in artifacts:
                        self.assertTrue(any((artifact in value for value in values.values())))
        literal = self.by_name[_text(49)][_text(13)]
        self.assertIn(_text(50), literal[_text(51)])
        self.assertNotIn(_text(52), literal[_text(51)])
        jsp = self.by_name[_text(53)][_text(13)]
        self.assertIn(_text(54), jsp[_text(51)])
        write = next((t for t in jsp[_text(44)] if t[_text(55)] == _text(56)))
        self.assertEqual(_text(54), write[_text(47)][0][_text(48)])

    def test_constant_conditions_and_blind_specifics(self):
        result = self.by_name[_text(57)][_text(13)]
        self.assertIn(_text(58), json.dumps(result[_text(44)]))
        self.assertIn(_text(59), json.dumps(self.by_name[_text(60)][_text(13)][_text(44)]))
        length = self.by_name[_text(61)][_text(13)]
        self.assertIn(_text(62), length[_text(51)])
        self.assertIn(_text(63), length[_text(51)])
        char = self.by_name[_text(64)][_text(13)]
        self.assertIn(_text(65), char[_text(51)])
        self.assertIn(_text(66), char[_text(51)])
        self.assertIn(_text(67), self.by_name[_text(68)][_text(13)][_text(51)])
        self.assertIn(_text(69), self.by_name[_text(70)][_text(13)][_text(51)])

    def test_structure_and_sibling_deduplication(self):
        result = self.by_name[_text(57)][_text(13)]
        actions = [s[_text(71)] for s in result[_text(45)]]
        self.assertIn(_text(72), actions[0])
        self.assertIn(_text(73), actions[-1])
        item = copy.deepcopy(self.by_name[_text(74)])
        original = item[_text(43)][0]
        sibling = dict(original, node_id=1, parent_node_id=0, transform=_text(75))
        analysis = a.analyze([original, sibling])
        actions = [s[_text(71)] for s in analysis[_text(45)]]
        self.assertEqual(len(actions), len(set(actions)))

    def test_nested_chain_and_powershell_decoding(self):
        unit = self.by_name[_text(76)]
        self.assertEqual([_text(77), _text(78), _text(79), _text(78)], unit[_text(80)])
        self.assertEqual(3, unit[_text(13)][_text(44)][0][_text(47)][0][_text(41)])
        result = self.by_name[_text(81)][_text(13)]
        self.assertIn(_text(82), json.dumps(result[_text(44)]))
        self.assertIn(_text(83), json.dumps(result[_text(44)]))
        self.assertNotIn(_text(82), result[_text(22)][_text(23)])
        self.assertEqual(_text(82), result[_text(84)][0][_text(85)])

    def test_normalization_maps_to_original_and_resolves_literals(self):
        for name in (_text(86), _text(87), _text(88)):
            result = self.by_name[name][_text(13)]
            self.assertIn(_text(89), result[_text(14)])
            a.validate(result, self.by_name[name][_text(43)])
        joined = self.by_name[_text(86)][_text(13)]
        union = next((t for t in joined[_text(44)] if t[_text(55)] == _text(90)))
        self.assertIn(_text(91), union[_text(47)][0][_text(48)])
        self.assertTrue(any((d[_text(85)] == _text(92) for d in joined[_text(84)])))
        version = self.by_name[_text(87)][_text(13)]
        self.assertTrue(any((d[_text(85)] == _text(92) for d in version[_text(84)])))
        self.assertNotIn(_text(92), joined[_text(22)][_text(23)])

    def test_shell_tokenizer_families_and_execution_arguments(self):
        unit = self.by_name[_text(93)]
        value = unit[_text(94)]
        segments = a.tokenize_shell(value)
        self.assertEqual([_text(95), _text(96), _text(15), _text(97)], [s[_text(98)] for s in segments])
        self.assertEqual([None, _text(99), _text(100), _text(101)], [s[_text(102)] for s in segments])
        self.assertEqual(2, len(a.tokenize_shell(decode64(_text(103)))))
        self.assertEqual(2, len(a.tokenize_shell(decode64(_text(104)))))
        self.assertEqual(2, len(a.tokenize_shell(decode64(_text(105)))))
        self.assertEqual(_text(106), self.by_name[_text(107)][_text(13)][_text(46)][0][_text(108)])
        for name in (_text(109), _text(110), _text(111), _text(112)):
            self.assertIn(_text(82), self.by_name[name][_text(13)][_text(22)][_text(23)])
        for name in (_text(113), _text(114), _text(115), _text(93)):
            result = self.by_name[name][_text(13)]
            self.assertIn(_text(116), json.dumps(result[_text(44)]))
            self.assertTrue(result[_text(22)][_text(117)])

    def test_nested_jndi_derivation_and_symbolic_targets(self):
        for name in (_text(118), _text(119), _text(120)):
            result = self.by_name[name][_text(13)]
            technique = next((t for t in result[_text(44)] if t[_text(55)] == _text(121)))
            self.assertIn(_text(122), technique[_text(123)])
            self.assertEqual(_text(124), result[_text(84)][0][_text(125)])
            self.assertIn(_text(126), result[_text(22)][_text(127)])
        result = self.by_name[_text(128)][_text(13)]
        self.assertEqual(4, sum((s[_text(71)].startswith(_text(129)) for s in result[_text(45)])))
        self.assertTrue(any((_text(130) in host for host in result[_text(22)][_text(127)])))
        self.assertTrue(any((_text(131) in url for url in result[_text(22)][_text(132)])))

    def test_graph_digest_and_per_unit_error_recovery(self):
        first = copy.deepcopy(self.items[0])
        second = copy.deepcopy(first)
        second[_text(43)].append({_text(41): 1, _text(133): 0, _text(134): _text(78), _text(135): _text(136), _text(42): _text(137)})
        report = a.build_report([first, second])
        self.assertEqual(2, report[_text(29)][_text(30)])
        self.assertEqual(0, report[_text(29)][_text(138)])
        with patch.object(a, _text(139), side_effect=ValueError(_text(140))):
            report = a.build_report([first, second])
        self.assertEqual(2, report[_text(29)][_text(138)])
        for unit in report[_text(9)]:
            self.assertEqual(_text(10), unit[_text(11)])
            self.assertIn(_text(140), unit[_text(12)])
            self.assertTrue(unit[_text(43)])
        second[_text(43)][1][_text(133)] = 1
        report = a.build_report([first, second])
        self.assertEqual(1, report[_text(29)][_text(138)])
        self.assertEqual(2, len(report[_text(9)]))

    def test_determinism_occurrences_and_timeline(self):
        self.assertEqual(self.report, a.build_report(self.items, generated_at=_text(7)))
        first = copy.deepcopy(self.items[0])
        first[_text(141)][_text(142)] = 1
        first[_text(143)][_text(144)] = 7
        for node in first[_text(43)]:
            node[_text(135)] = _text(145)
        report = a.build_report(self.items + [first])
        self.assertEqual(len(self.report[_text(9)]), len(report[_text(9)]))
        self.assertEqual(1, report[_text(9)][0][_text(142)])
        self.assertEqual(2, len(report[_text(9)][0][_text(146)]))

    def test_reject_fabricated_evidence_artifacts_and_templates(self):
        unit = self.by_name[_text(49)]
        result = copy.deepcopy(unit[_text(13)])
        result[_text(44)][0][_text(47)][0][_text(48)] = _text(147)
        with self.assertRaises(ValueError):
            a.validate(result, unit[_text(43)])
        result = copy.deepcopy(unit[_text(13)])
        result[_text(22)][_text(23)].append(_text(147))
        with self.assertRaises(ValueError):
            a.validate(result, unit[_text(43)])
        result = copy.deepcopy(unit[_text(13)])
        result[_text(51)] += _text(148)
        with self.assertRaises(ValueError):
            a.validate(result, unit[_text(43)])
        with self.assertRaises(ValueError):
            a.Prose(unit[_text(43)])(_text(149))

    def test_json_jsonl_cli_and_atomic_writer(self):
        self.assertEqual(self.items, list(a.load_resolutions(FIXTURE)))
        text = _text(150).join((json.dumps(item) for item in self.items))
        with patch.object(a.paxio, _text(151), return_value=io.StringIO(text)):
            self.assertEqual(self.items, list(a.load_resolutions(Path(_text(152)))))
        with patch.object(a, _text(153)) as writer:
            self.assertEqual(0, a.main([str(FIXTURE)]))
            self.assertEqual(len(self.report[_text(9)]), len(writer.call_args.args[1][_text(9)]))
        scratch = Path(_text(154))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            destination = Path(folder) / _text(155)
            a.atomic_write_json(destination, self.report)
            self.assertEqual(self.report, json.loads(destination.read_text(encoding=_text(5))))
            original = destination.read_bytes()
            with patch.object(a.os, _text(156), side_effect=OSError(_text(157))):
                with self.assertRaises(OSError):
                    a.atomic_write_json(destination, {_text(158): True})
            self.assertEqual(original, destination.read_bytes())
            self.assertEqual([_text(155)], [p.name for p in Path(folder).iterdir()])
if __name__ == _text(159):
    unittest.main()
