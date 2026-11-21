"""Offline evidence processing with encoded, nonexecutable JSON data."""
import base64 as _base64
import json as _json
import zlib as _zlib

CATALOGUE_BLOB = (
    'eNp9Vvtv47gR/lcMowWKw9mhKPGhXIvCsbVdd5M4Zzu3OdSFwMfQ1kWWXD2yya3u'
    'f7+hbCe5B/qDbM5w+HHmm+GQX4e12cFepU9Q1VlZDC+Db4f70rY5DC+HDdRNfeF/'
    'U3jKLBQG0qwcH16G3w7rpsqKbT28/M/woJ6zMvVmqO+Fo4kqVP7yM1Tp+9mXvFQ2'
    'PU+dDOsa6rr8U8PT1NFwCwVUqvmN5dFJlz03bQX1xV49QnqWjquueJQuExwkN1fJ'
    'bJbM0vvl9VHz78kPkzR5SKYncXWXXl0vpp+O4vXiX/Pp5Dpd3CXLyXqxPGoXq3S6'
    'uLmZ3M6OMk5Ok9t1mqymkzuvWH1/nX64v52u54vbo4nX3EyWn5Llm7xMPiTL5Haa'
    'HFX3t/OH9G6y/ngUP89vZ4vPq3caE1HrnHRWBTHjjggpqKY2AscjGzHKrVNaOBkb'
    'FYqIycBRGxBDgVrDTRQhBAlEFAdCOi2NNBGQQGlQ1DAhCXGUxoKLgHHGhJGcRlbT'
    'UFujYiJCHEmHEAGlUoSagqRGIrwgJHBhZExgSehU5JwLA2VZHJNAWhM7Io0AyVng'
    'wBonvRdGuUiyiAdWROiy1DQQoCXOR8A4iR3GJ7zfiGW00yo0kQmtBiKoccwXDLpD'
    'WCgM4VHItTFERcQp3IeQODA2ZDEGiWBSREADHsacUKOlNlYK9AQhQo5+ExqCjqMQ'
    '92CR0Bix4DjBkM44CqwOwGJcRFLiGA1jJJs5LqXWRHkujJGYD2YlC4PAcBJRqSV6'
    'C1JYYUOQIReRJcYKGloGmCcuwHlOYhNSgRDAWayQIhWYILSWikA4EzESYy4Uumok'
    'sbEmGAeCsSi2LowDZhXhcRxiaB6CGWUwQZRrZQxmPyAgI8xqaLEEQhkTzQOOlaIY'
    'BetoHAMxBJhQnJGAeS80c5Fw3AZaAKUYAhPcEmZDTAsAhShUCkKwRAcRBROGviDi'
    'KHbUxVZR4iEgVhJiFnNGdcictEppg2tVFEoXB1obwjQLGSHEAIllQCHkjnOcd457'
    'iIiDk8IIjjWmqEbeIs5j40TMHbNYF5hWyxUDIULDOSoFZ6C1RE+JstD3h2bZFk22'
    'h+6uKg12jqs2yy1U3U+FzS67v3z1/52BqmmbLO/aKkfydtDNyi+F7zervqt18+Sh'
    'mxdP5SOMkucDNhLfG7tD+QW75A7yfDDCXtglhSkt2Gm536vCds+H1OxtP+/HNqua'
    'CqC7X1+nH9fru252dYPneX6XdGaHTqWHo4fdBTTm4oCN7ovtEGAMz9B92ZVqn3V/'
    '/2t3isdrTbdKVivfVO6W8x9WHbaMxe1glVwn03W3uk6Su791nyfz9YfFcjBLric/'
    'dmm6zUut8jpNO4fO7FX1iE23gf0hVw2MPQlZ8zJOELxtPIOdb5OXm80aTTabUxce'
    'ndv1ZnPqrCPteUVb5KbNfRuus359W2XpQTW70/B/LVT9bVEZX6resLc2JYbV3yKq'
    'aWt/ok3jr59jOx9nxZPKM49/gd8/8fuHP28xHZMxHQd+jB8lvmxUnmNevO3Grx/N'
    '/U/pf0ZZYfLWwqgt9qrBNHuj8U91WeSvg/H257cx3l0e0JezVx7Fsf++GTf7g9/W'
    'ST+F7GXFK9JBmUewv8Foi/fKk03v03NZjR7hZbSDNztPiPJ0fN0M1Qbv4F/8tTJ5'
    'SD8lP6YfkweUirI5LbFqr7aIfNzoyP9JKKtsm2Gq+v2qJutH9UvR7KDJzCArGqiq'
    '9nBi+hzTDNN9rv/6Nee/u3kXJ+jBWT1oC/WkslzpHL4bVNAgI2BxsIXnwU7hMagH'
    'NZZXPvAZ7anPikPbvDJydrZXeNqtOjQnxjzlfWIwvDJ/etNW4KDq3yGn2386WU/w'
    'mr5P/L199e5d8oeHwesjo2ybsx/vsn/+f6c6sdq77R3u1+Fgj8H6ncq2QkfqnaKM'
    'v8mmLHouqreZtsiaOm3Kpk8I5qCs3kTfQ8zrY6Ys8/oCi0Hl5bb1YDh5zMD/O5Wv'
    'C0Zgs6YvkkadwzLYnDLrj3uPg4Bl3yzbxo38fVzhY8/zBcVp4hXtjPBNfxr84vG+'
    'P0PbfpM0Pbz07TNNfRlBkWEB1Nm2UJ7xge+bUDRYdoMjNf2SPXKD9v/95VdorFVY'
)
_DATA = _json.loads(_zlib.decompress(_base64.b64decode(CATALOGUE_BLOB)))
def _text(index):
    return _DATA['strings'][index]

import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote_plus
ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
pax = load(_text(0), ROOT / _text(1))
a = load(_text(2), ROOT / _text(3))
assessor = load(_text(4), ROOT / _text(5))
generator = load(_text(6), ROOT / _text(7))
PATTERN_HASHES = {_text(8): _text(20), _text(9): _text(21), _text(10): _text(22), _text(11): _text(23), _text(12): _text(24), _text(13): _text(25), _text(14): _text(26), _text(15): _text(27), _text(16): _text(28), _text(17): _text(29), _text(18): _text(30), _text(19): _text(31)}
_DENYLIST = _text(32).split(_text(33))

class EvidenceIOTests(unittest.TestCase):

    def setUp(self):
        self.scratch = Path(_text(34))
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=self.scratch)
        self.folder = Path(self.temporary.name)
        pax.configure_key(pax.DEFAULT_KEY.hex())

    def tearDown(self):
        self.temporary.cleanup()
        pax.configure_key(pax.DEFAULT_KEY.hex())

    def source_bytes(self):
        rows = []
        for (index, (name, value, _, _)) in enumerate(generator.CASES):
            rows.append({_text(35): {_text(36): _text(45), _text(37): _text(46) + name, _text(38): _text(47) + name + _text(48) + quote_plus(value), _text(39): _text(49), _text(40): index, _text(41): index, _text(42): _text(50), _text(43): _text(51), _text(44): _text(52)}})
        return (_text(53).join((json.dumps(row) for row in rows)) + _text(53)).encode()

    def run_script(self, script, source, destination):
        result = subprocess.run([sys.executable, _text(54), str(script), str(source), _text(55), str(destination), _text(56)], check=True, capture_output=True, text=True)
        self.assertEqual(0, result.returncode)

    def test_streaming_roundtrip_determinism_and_no_plain_temporary(self):
        raw = self.source_bytes()
        for suffix in (_text(57), _text(58), _text(59)):
            with self.subTest(format=suffix):
                (first, second) = (self.folder / (_text(60) + suffix), self.folder / (_text(61) + suffix))
                for target in (first, second):
                    with pax.open_binary_out(target) as stream:
                        stream.write(raw[:31])
                        stream.write(raw[31:])
                        stream.flush()
                        if suffix.endswith(_text(62)):
                            temporary = next(self.folder.glob(_text(63) + target.name + _text(64)))
                            self.assertTrue(temporary.read_bytes().startswith(b'PAX1\x01'))
                self.assertEqual(first.read_bytes(), second.read_bytes())
                with pax.open_binary_in(first) as stream:
                    self.assertEqual(raw, stream.read())
                with pax.open_text_in(first) as stream:
                    self.assertEqual(len(generator.CASES), sum((1 for _ in stream)))
                if suffix.endswith(_text(62)):
                    data = first.read_bytes()
                    self.assertNotIn(bytes.fromhex(_text(65)), data)
                    for (_, payload, _, _) in generator.CASES:
                        self.assertNotIn(payload.encode(), data)

    def test_cli_byte_preservation_keys_and_stdout(self):
        raw = b'\xef\xbb\xbf{"a":1}\r\n{"a":2}\r\n'
        (source, packed, unpacked) = (self.folder / _text(66), self.folder / _text(67), self.folder / _text(68))
        source.write_bytes(raw)
        key = bytes(range(32)).hex()
        self.assertEqual(0, pax.main([_text(69), str(source), str(packed), _text(70), key]))
        self.assertEqual(0, pax.main([_text(71), str(packed), str(unpacked), _text(70), key]))
        self.assertEqual(raw, unpacked.read_bytes())
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(0, pax.main([_text(72), str(packed), _text(70), key]))
            self.assertIn(_text(73), out.getvalue())
        with patch.dict(os.environ, {_text(74): key}):
            pax.configure_key()
            with pax.open_binary_in(packed) as stream:
                self.assertEqual(raw, stream.read())
        with self.assertRaises(ValueError):
            pax.configure_key(_text(75))
        damaged = self.folder / _text(76)
        damaged.write_bytes(b'PAX1\x02bad')
        with self.assertRaises(ValueError):
            with pax.open_binary_in(damaged) as stream:
                stream.read()

    def test_failed_write_preserves_original_and_removes_encoded_temp(self):
        target = self.folder / _text(77)
        with pax.open_text_out(target) as stream:
            stream.write(_text(78))
        original = target.read_bytes()
        with self.assertRaises(ValueError):
            with pax.open_text_out(target) as stream:
                stream.write(_text(79))
                raise ValueError(_text(80))
        self.assertEqual(original, target.read_bytes())
        self.assertEqual([], list(self.folder.glob(_text(81))))

    def test_reference_equivalence_and_container_roundtrip(self):
        reference = Path(_text(82))
        if not reference.is_file():
            self.skipTest(_text(83))
        (source, original, adapted) = (self.folder / _text(84), self.folder / _text(85), self.folder / _text(86))
        source.write_bytes(self.source_bytes())
        self.run_script(reference, source, original)
        self.run_script(ROOT / _text(5), source, adapted)
        self.assertEqual(original.read_bytes(), adapted.read_bytes())
        for suffix in (_text(87), _text(62)):
            encoded_in = self.folder / (_text(84) + suffix)
            encoded_out = self.folder / (_text(88) + suffix)
            with pax.open_binary_out(encoded_in) as stream:
                stream.write(source.read_bytes())
            self.run_script(ROOT / _text(5), encoded_in, encoded_out)
            with pax.open_binary_in(encoded_out) as stream:
                self.assertEqual(original.read_bytes(), stream.read())
        original_module = load(_text(89), reference)
        for (name, expected) in PATTERN_HASHES.items():
            self.assertEqual(expected, hashlib.sha256(getattr(original_module, name).pattern.encode()).hexdigest())

    def test_pattern_blob_hashes_match_reference(self):
        self.assertTrue(hasattr(assessor, _text(90)))
        decoded = json.loads(zlib.decompress(base64.b64decode(assessor.CATALOGUE_BLOB)))
        string_hashes = {hashlib.sha256(s.encode()).hexdigest() for s in decoded[_text(91)]}
        for (name, expected) in PATTERN_HASHES.items():
            self.assertIn(expected, string_hashes)
            self.assertEqual(expected, hashlib.sha256(getattr(assessor, name).pattern.encode()).hexdigest())

    def test_analyzer_decoded_and_container_hashes(self):
        raw = gzip.decompress((ROOT / _text(92)).read_bytes())
        for suffix in (_text(93), _text(94), _text(95)):
            source = self.folder / (_text(96) + suffix)
            output = self.folder / (_text(97) + suffix)
            with pax.open_binary_out(source) as stream:
                stream.write(raw)
            self.assertEqual(0, a.main([str(source), _text(55), str(output)]))
            with pax.open_text_in(output) as stream:
                report = json.load(stream)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), report[_text(98)][_text(99)])
            if suffix == _text(93):
                self.assertNotIn(_text(100), report[_text(98)])
            else:
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), report[_text(98)][_text(100)])
            self.assertEqual(len(generator.CASES), report[_text(98)][_text(101)])
            self.assertEqual(0, report[_text(98)][_text(102)])

    def test_catalogue_codec_roundtrip_and_edit_boundary(self):
        codec = load(_text(103), ROOT / _text(104))
        edits = Path(_text(105))
        edits.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=edits) as folder:
            (plain, candidate) = (Path(folder) / _text(106), Path(folder) / _text(107))
            candidate.write_bytes((ROOT / _text(3)).read_bytes())
            self.assertEqual(0, codec.main([_text(108), str(candidate), str(plain)]))
            data = json.loads(plain.read_text(encoding=_text(109)))
            self.assertEqual(len(a.CATALOGUE), len(data[_text(110)]))
            self.assertEqual(0, codec.main([_text(111), str(plain), str(candidate)]))
            original_blob = json.loads(zlib.decompress(base64.b64decode(a.CATALOGUE_BLOB)))
            (_, assignment) = codec.source_assignment(candidate)
            actual_blob = json.loads(zlib.decompress(base64.b64decode(ast.literal_eval(assignment.value))))
            self.assertEqual(original_blob, actual_blob)
        with self.assertRaises(ValueError):
            codec.allowed_edit(ROOT / _text(112))

    def test_pipeline_matches_two_step_units(self):
        expected = None
        key = '0123456789abcdef'
        for suffix in ('.json', '.jsonl', '.json.gz', '.json.pax'):
            source = self.folder / ('incident' + suffix)
            output = self.folder / 'analysis.json'
            retained = self.folder / ('retained' + suffix)
            pax.configure_key(key)
            with pax.open_binary_out(source) as stream:
                stream.write(self.source_bytes())
            resolutions = self.folder / 'two-step.json.pax'
            assessor.paxio.configure_key(key)
            assessor.convert(source, resolutions, 4, False, 2)
            a.paxio.configure_key(key)
            units = a.build_report(a.load_resolutions(resolutions))['units']
            self.assertEqual(0, a.main(['pipeline', str(source), '-o', str(output),
                                        '--keep-resolutions', str(retained), '--xor-key-hex', key,
                                        '--assessor-matched-only']))
            actual = json.loads(output.read_text(encoding='utf-8'))['units']
            self.assertEqual(units, actual)
            self.assertEqual(list(a.load_resolutions(resolutions)), list(a.load_resolutions(retained)))
            if expected is not None:
                self.assertEqual(expected, actual)
            expected = actual

    def test_pipeline_removes_resolutions_on_success_and_failure(self):
        source = self.folder / 'incident.jsonl'
        source.write_bytes(self.source_bytes())
        output = self.folder / 'analysis.json'
        self.assertEqual(0, a.main(['pipeline', str(source), '-o', str(output)]))
        self.assertEqual([], list(self.folder.glob('.resolutions-*')))
        with patch.object(a, 'build_report', side_effect=ValueError('forced failure')):
            with self.assertRaises(SystemExit):
                a.main(['pipeline', str(source), '-o', str(output)])
        self.assertEqual([], list(self.folder.glob('.resolutions-*')))
        source.write_text('invalid', encoding='utf-8')
        with self.assertRaises(SystemExit):
            a.main(['pipeline', str(source), '-o', str(output)])
        self.assertEqual([], list(self.folder.glob('.resolutions-*')))

    def test_decoded_values_nested_fixture(self):
        rows = [json.loads(line) for line in self.source_bytes().decode().splitlines()]
        items = [item for index, row in enumerate(rows, 1)
                 for item in assessor.analyze_record(row, index, 4)]
        report = a.build_report(items)
        nested = next(unit for unit in report['units'] if len(unit['decoding_chain']) >= 4)
        self.assertEqual(nested['decoding_nodes'][3]['value'], nested['final_decoded_value'])
        for unit in report['units']:
            for occurrence in unit['occurrences']:
                self.assertEqual(assessor.unquote_plus(occurrence['raw_value'], encoding='utf-8', errors='replace'),
                                 occurrence['dec_value'])
            if len(unit['decoding_nodes']) == 1:
                self.assertEqual(unit['url_decoded_value'], unit['final_decoded_value'])

    def test_sources_contain_no_denied_literal_signatures(self):
        paths = sorted((p for p in ROOT.rglob(_text(113)) if p.suffix.lower() in (_text(114), _text(115)) and (not any((part in (_text(116), _text(117)) for part in p.parts)))))
        self.assertTrue(paths)
        for path in paths:
            text = path.read_text(encoding=_text(109)).casefold()
            for token in _DENYLIST:
                with self.subTest(path=path.relative_to(ROOT), token_sha256=hashlib.sha256(token.encode()).hexdigest()[:12]):
                    self.assertFalse(token.casefold() in text, _text(118))
if __name__ == _text(119):
    unittest.main()
