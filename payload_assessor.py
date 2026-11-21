"""Offline evidence processing with encoded, nonexecutable JSON data."""
from __future__ import annotations
import base64 as _base64
import json as _json
import zlib as _zlib

CATALOGUE_BLOB = (
    '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'
    'nXWHw8GQXPG8BZex55Xcp38AE3z1dg=='
)
_DATA = _json.loads(_zlib.decompress(_base64.b64decode(CATALOGUE_BLOB)))
def _text(index):
    return _DATA['strings'][index]

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlsplit
MAX_TEXT_CHARS = 1000000
MAX_NODES = 64
MAX_COMPONENTS = 256
B64_RE = re.compile(_text(0), re.ASCII)
PERCENT_ESCAPE = re.compile(_text(1))
SQL_FUNCTION_RE = re.compile(_text(2))
SQL_REFERENCE_RE = re.compile(_text(3), re.I)
WINDOWS_PATH_RE = re.compile(_text(4))
UNIX_PATH_RE = re.compile(_text(5))
EMBEDDED_URL_RE = re.compile(_text(6), re.I)
OS_COMMAND_RE = re.compile(_text(7), re.I)
JAVA_EXEC_RE = re.compile(_text(8), re.I)
JSP_BLOCK_RE = re.compile(_text(9), re.I)
LOGICAL_OPERATOR_RE = re.compile(_text(10), re.I)
SQL_MARKER_RE = re.compile(_text(11), re.I)
import importlib.util
_spec = importlib.util.spec_from_file_location(_text(12), Path(__file__).with_name(_text(13)))
paxio = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(paxio)

def decoded_size(path):
    total = 0
    with paxio.open_binary_in(path) as stream:
        for block in iter(lambda : stream.read(1048576), b''):
            total += len(block)
    return total

def unique(items):
    return list(dict.fromkeys(items))

def b64_text(value: str) -> str | None:
    if not isinstance(value, str) or not 8 <= len(value) <= MAX_TEXT_CHARS:
        return None
    if not B64_RE.fullmatch(value):
        return None
    bare = value.rstrip(_text(14))
    if len(bare) % 4 == 1 or ((_text(15) in bare or _text(16) in bare) and (_text(17) in bare or _text(18) in bare)):
        return None
    urlsafe = _text(17) in bare or _text(18) in bare
    try:
        raw = base64.b64decode(bare + _text(14) * (-len(bare) % 4), altchars=b'-_' if urlsafe else None, validate=True)
        normalized = base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)
        if normalized.decode(_text(19)).rstrip(_text(14)) != bare:
            return None
        text = raw.decode(_text(20))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not text or not all((c.isprintable() or c in _text(21) for c in text)):
        return None
    return text

def query_pairs(query: str):
    if query.startswith(_text(22)):
        query = query[1:]
    for (i, fragment) in enumerate(query.split(_text(23))):
        if not fragment:
            continue
        (raw_name, has_equals, raw_value) = fragment.partition(_text(14))
        yield {_text(24): i, _text(25): unquote_plus(raw_name, encoding=_text(20), errors=_text(29)), _text(26): raw_name, _text(27): raw_value if has_equals else _text(30), _text(28): unquote_plus(raw_value, encoding=_text(20), errors=_text(29))}

def parsed_http_url(value: str):
    try:
        parsed = urlsplit(value)
        return parsed if parsed.scheme.lower() in {_text(31), _text(32)} and parsed.hostname else None
    except ValueError:
        return None

def url_fields(value: str):
    parsed = parsed_http_url(value)
    if parsed is None:
        return None
    return {_text(33): parsed.scheme, _text(34): parsed.hostname, _text(35): parsed.port if is_valid_port(parsed) else None, _text(36): unquote(parsed.path, encoding=_text(20), errors=_text(29)), _text(37): _text(22) + parsed.query if parsed.query else _text(30), _text(38): [{_text(24): pair[_text(24)], _text(25): pair[_text(25)], _text(28): pair[_text(28)]} for pair in query_pairs(parsed.query)], _text(39): parsed.fragment}

def is_valid_port(parsed):
    try:
        parsed.port
        return True
    except ValueError:
        return False

def find_closing_parenthesis(text: str, open_at: int) -> int | None:
    (depth, quote) = (0, None)
    i = open_at
    while i < len(text):
        c = text[i]
        if quote:
            if c == _text(40) and quote == _text(41) and (i + 1 < len(text)):
                i += 2
                continue
            if c == quote:
                if quote == _text(42) and i + 1 < len(text) and (text[i + 1] == _text(42)):
                    i += 2
                    continue
                quote = None
        elif c in (_text(42), _text(41)):
            quote = c
        elif c == _text(43):
            depth += 1
        elif c == _text(44):
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None

def split_top_level(text: str, delimiter: str=_text(45)) -> list[str]:
    (out, start, quote) = ([], 0, None)
    paren = brace = bracket = 0
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == _text(40) and quote == _text(41) and (i + 1 < len(text)):
                i += 2
                continue
            if c == quote:
                if quote == _text(42) and i + 1 < len(text) and (text[i + 1] == _text(42)):
                    i += 2
                    continue
                quote = None
        elif c in (_text(42), _text(41)):
            quote = c
        elif c == _text(43):
            paren += 1
        elif c == _text(44):
            paren = max(paren - 1, 0)
        elif c == _text(46):
            brace += 1
        elif c == _text(47):
            brace = max(brace - 1, 0)
        elif c == _text(48):
            bracket += 1
        elif c == _text(49):
            bracket = max(bracket - 1, 0)
        elif c == delimiter and (not any((paren, brace, bracket))):
            out.append(text[start:i].strip())
            start = i + 1
        i += 1
    out.append(text[start:].strip())
    return out

def scan_quoted_strings(text: str, quote: str=_text(42)) -> list[dict]:
    result = []
    i = 0
    while i < len(text) and len(result) < MAX_COMPONENTS:
        if text[i] != quote:
            i += 1
            continue
        start = i
        i += 1
        parts = []
        while i < len(text):
            if text[i] == quote:
                if i + 1 < len(text) and text[i + 1] == quote:
                    parts.append(quote)
                    i += 2
                    continue
                i += 1
                result.append({_text(28): _text(30).join(parts), _text(50): start, _text(51): i})
                break
            if quote == _text(41) and text[i] == _text(40) and (i + 1 < len(text)):
                parts.append(text[i:i + 2])
                i += 2
                continue
            parts.append(text[i])
            i += 1
    return result

def scan_function_calls(text: str) -> list[dict]:
    output = []
    for match in SQL_FUNCTION_RE.finditer(text):
        if len(output) >= MAX_COMPONENTS:
            break
        open_at = text.find(_text(43), match.start(), match.end())
        close_at = find_closing_parenthesis(text, open_at)
        if close_at is None:
            continue
        name = text[match.start():open_at].strip()
        args_text = text[open_at + 1:close_at]
        output.append({_text(25): re.sub(_text(54), _text(55), name), _text(52): split_top_level(args_text) if args_text.strip() else [], _text(53): text[match.start():close_at + 1], _text(50): match.start(), _text(51): close_at + 1})
    return output

def sql_logical_parts(text: str) -> dict | None:
    (parts, operators) = ([], [])
    (start, depth, quote) = (0, 0, None)
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == quote:
                if quote == _text(42) and i + 1 < len(text) and (text[i + 1] == _text(42)):
                    i += 2
                    continue
                quote = None
        elif c in (_text(42), _text(41)):
            quote = c
        elif c == _text(43):
            depth += 1
        elif c == _text(44):
            depth = max(depth - 1, 0)
        elif depth == 0:
            candidate = LOGICAL_OPERATOR_RE.match(text, i)
            if candidate and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == _text(18))):
                parts.append(text[start:i].strip())
                operators.append(candidate.group(1).upper())
                i += len(candidate.group(0))
                start = i
                continue
        i += 1
    if not operators:
        return None
    parts.append(text[start:].strip())
    return {_text(56): [parse_simple_comparison(p) or {_text(53): p} for p in parts], _text(57): operators}

def parse_simple_comparison(text: str) -> dict | None:
    (quote, depth, i) = (None, 0, 0)
    while i < len(text):
        c = text[i]
        if quote:
            if c == quote:
                if quote == _text(42) and i + 1 < len(text) and (text[i + 1] == _text(42)):
                    i += 2
                    continue
                quote = None
        elif c in (_text(42), _text(41)):
            quote = c
        elif c == _text(43):
            depth += 1
        elif c == _text(44):
            depth = max(depth - 1, 0)
        elif depth == 0 and c in _text(58):
            op = next((x for x in (_text(59), _text(60), _text(61), _text(62), _text(14), _text(63), _text(64)) if text.startswith(x, i)), None)
            if op:
                (left, right) = (text[:i].strip(), text[i + len(op):].strip())
                if left and right:
                    return {_text(53): text, _text(65): left, _text(66): op, _text(67): right}
        i += 1
    return None

def component_extractions(text: str, *, url=None) -> dict:
    components = {}
    if url:
        components[_text(68)] = url
    if text and len(text) <= MAX_TEXT_CHARS:
        if text.lstrip().startswith((_text(46), _text(48))):
            try:
                obj = json.loads(text)
                if isinstance(obj, (dict, list)):
                    components[_text(69)] = obj
            except (ValueError, TypeError):
                pass
        functions = scan_function_calls(text) if _text(43) in text else []
        comparisons = sql_logical_parts(text)
        references = [{_text(70): m.group(1).upper(), _text(25): m.group(2), _text(50): m.start(2), _text(51): m.end(2)} for m in SQL_REFERENCE_RE.finditer(text)][:MAX_COMPONENTS]
        sql_like = bool(SQL_MARKER_RE.search(text)) or bool(re.search(_text(71), text))
        if sql_like and (not url):
            sql = {}
            if comparisons:
                sql[_text(72)] = comparisons
            elif (comparison := parse_simple_comparison(text)) is not None:
                sql[_text(73)] = comparison
            if functions:
                sql[_text(74)] = functions
            if references:
                sql[_text(75)] = references
            literals = scan_quoted_strings(text)
            if literals:
                sql[_text(76)] = literals
            if sql:
                components[_text(77)] = sql
        if (blocks := [{_text(78): m.group(0), _text(50): m.start(), _text(51): m.end()} for m in JSP_BLOCK_RE.finditer(text)][:MAX_COMPONENTS]):
            components[_text(79)] = blocks
        exec_calls = []
        for m in JAVA_EXEC_RE.finditer(text):
            open_at = text.rfind(_text(43), m.start(), m.end())
            close_at = find_closing_parenthesis(text, open_at)
            if close_at is not None:
                argument_text = text[open_at + 1:close_at]
                call = {_text(80): re.sub(_text(81), _text(30), text[m.start():open_at]), _text(52): split_top_level(argument_text), _text(53): text[m.start():close_at + 1], _text(50): m.start(), _text(51): close_at + 1}
                array_match = re.search(_text(82), argument_text)
                if array_match:
                    call[_text(83)] = split_top_level(array_match.group(1))
                exec_calls.append(call)
            if len(exec_calls) >= MAX_COMPONENTS:
                break
        if exec_calls:
            components[_text(84)] = exec_calls
        paths = unique((m.group(0) for m in WINDOWS_PATH_RE.finditer(text)))
        paths += [p for p in unique((m.group(0) for m in UNIX_PATH_RE.finditer(text))) if p not in paths]
        if paths:
            components[_text(85)] = paths[:MAX_COMPONENTS]
        commands = [{_text(86): m.group(0), _text(50): m.start(), _text(51): m.end()} for m in OS_COMMAND_RE.finditer(text)][:MAX_COMPONENTS]
        if commands:
            components[_text(87)] = commands
        if not url:
            urls = unique((m.group(0).rstrip(_text(88)) for m in EMBEDDED_URL_RE.finditer(text)))
            if urls:
                components[_text(89)] = urls[:MAX_COMPONENTS]
    return components

def inspect_parameter(pair, max_depth: int):
    nodes = []
    visited = set()

    def visit(value: str, transform: str, route: str, depth: int=0, raw_fallback: str | None=None, parent_node_id: int | None=None):
        if len(nodes) >= MAX_NODES or len(value) > MAX_TEXT_CHARS:
            return
        marker = (route, value)
        if marker in visited:
            return
        visited.add(marker)
        parsed = parsed_http_url(value)
        node_id = len(nodes)
        node = {_text(90): node_id, _text(91): parent_node_id, _text(92): transform, _text(93): route, _text(28): value}
        components = component_extractions(value, url=url_fields(value) if parsed else None)
        if components:
            node[_text(94)] = components
        nodes.append(node)
        if parsed:
            for child in query_pairs(parsed.query):
                visit(child[_text(28)], _text(95), route + ''.join([_text(96), format(child[_text(24)], ''), _text(97), format(child[_text(25)], ''), _text(49)]), depth, raw_fallback=unquote(child[_text(27)], encoding=_text(20), errors=_text(29)), parent_node_id=node_id)
        if depth >= max_depth:
            return
        decoded = b64_text(value)
        if decoded is None and raw_fallback is not None and (raw_fallback != value):
            decoded = b64_text(raw_fallback)
        if decoded is not None and decoded != value:
            visit(decoded, _text(98), route + _text(99), depth + 1, parent_node_id=node_id)
            if not parsed_http_url(decoded) and PERCENT_ESCAPE.search(decoded):
                readable = unquote(decoded, encoding=_text(20), errors=_text(29))
                if readable != decoded:
                    visit(readable, _text(100), route + _text(101), depth + 1, parent_node_id=node_id)
    visit(pair[_text(28)], _text(102), ''.join([_text(103), format(pair[_text(24)], ''), _text(97), format(pair[_text(25)], ''), _text(49)]), raw_fallback=unquote(pair[_text(27)], encoding=_text(20), errors=_text(29)))
    return nodes

# Request paths carrying injection syntax are analysed as a pseudo-parameter. Plain paths (letters, digits and
# the usual separators) are skipped so ordinary crawling does not become payload units.
PATH_PARAMETER = '(uri path)'
_PATH_SUSPICIOUS = re.compile(r"%[0-9A-Fa-f]{2}|\.\.|//|[^A-Za-z0-9/._~!*+,=:@-]")


def path_payload(path) -> bool:
    return isinstance(path, str) and len(path) >= 2 and bool(_PATH_SUSPICIOUS.search(path))


def coerce_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

def stable_event_id(result):
    key = json.dumps([result.get(_text(34)), result.get(_text(36)), result.get(_text(37))], ensure_ascii=False, separators=(_text(45), _text(97)))
    return _text(104) + hashlib.sha256(key.encode(_text(20), _text(105))).hexdigest()[:24]

def analyze_record(record, line: int, max_depth: int, include_unmatched: bool=False):
    result = record.get(_text(106), record)
    if not isinstance(result, dict):
        return
    event_id = stable_event_id(result)
    src = unique((str(x) for x in coerce_list(result.get(_text(107))) if x is not None))
    for (query_index, raw_query) in enumerate(coerce_list(result.get(_text(37)))):
        if not isinstance(raw_query, str):
            continue
        for parameter in query_pairs(raw_query):
            nodes = inspect_parameter(parameter, max_depth)
            has_resolution = any((n.get(_text(94)) or n[_text(92)] != _text(102) for n in nodes))
            has_resolution = has_resolution or parameter[_text(28)] != parameter[_text(27)]
            if not has_resolution and (not include_unmatched):
                continue
            payload_id = _text(108) + hashlib.sha256((event_id + _text(109) + str(query_index) + _text(109) + str(parameter[_text(24)]) + _text(109) + parameter[_text(26)] + _text(109) + parameter[_text(27)]).encode(_text(20), _text(105))).hexdigest()[:24]
            count = result.get(_text(110))
            try:
                count = int(count) if count is not None else None
            except (ValueError, TypeError):
                pass
            yield {_text(111): payload_id, _text(112): event_id, _text(113): line, _text(114): {_text(34): result.get(_text(34)), _text(36): result.get(_text(36))}, _text(115): {_text(118): src, _text(119): result.get(_text(124)), _text(120): result.get(_text(125)), _text(121): count, _text(122): coerce_list(result.get(_text(126))), _text(123): coerce_list(result.get(_text(127)))}, _text(116): {_text(128): query_index, _text(129): parameter[_text(24)], _text(25): parameter[_text(25)], _text(27): parameter[_text(27)], _text(130): parameter[_text(28)]}, _text(117): nodes}
    path = result.get(_text(36))
    if path_payload(path):
        parameter = {_text(24): 0, _text(25): PATH_PARAMETER, _text(26): PATH_PARAMETER, _text(27): path,
                     _text(28): unquote(path, encoding=_text(20), errors=_text(29))}
        nodes = inspect_parameter(parameter, max_depth)
        payload_id = _text(108) + hashlib.sha256((event_id + _text(109) + 'path' + _text(109) + path).encode(_text(20), _text(105))).hexdigest()[:24]
        count = result.get(_text(110))
        try:
            count = int(count) if count is not None else None
        except (ValueError, TypeError):
            pass
        yield {_text(111): payload_id, _text(112): event_id, _text(113): line, _text(114): {_text(34): result.get(_text(34)), _text(36): path}, _text(115): {_text(118): src, _text(119): result.get(_text(124)), _text(120): result.get(_text(125)), _text(121): count, _text(122): coerce_list(result.get(_text(126))), _text(123): coerce_list(result.get(_text(127)))}, _text(116): {_text(128): -1, _text(129): 0, _text(25): PATH_PARAMETER, _text(27): path, _text(130): parameter[_text(28)]}, _text(117): nodes}

def convert(source: Path, destination: Path, max_depth: int, include_unmatched: bool, interval: float, output_format: str=_text(69)):
    if output_format not in {_text(69), _text(131)}:
        raise ValueError(_text(132))
    total = decoded_size(source)
    read_bytes = lines = emitted = nodes = 0
    started = last = time.monotonic()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with paxio.open_binary_in(source) as stream, paxio.open_text_out(destination) as out:
        if output_format == _text(69):
            out.write(_text(133))
        for (lines, raw) in enumerate(stream, 1):
            read_bytes += len(raw)
            if not raw.strip():
                continue
            try:
                record = json.loads(raw.decode(_text(134)))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(''.join([_text(135), format(lines, ''), _text(136), format(exc, '')])) from exc
            if not isinstance(record, dict):
                raise ValueError(''.join([_text(137), format(lines, '')]))
            for item in analyze_record(record, lines, max_depth, include_unmatched):
                if output_format == _text(69):
                    if emitted:
                        out.write(_text(138))
                    formatted = json.dumps(item, ensure_ascii=False, indent=2)
                    out.write(_text(139).join((_text(140) + l for l in formatted.splitlines())))
                else:
                    out.write(json.dumps(item, ensure_ascii=False, separators=(_text(45), _text(97))) + _text(139))
                emitted += 1
                nodes += len(item[_text(117)])
            now = time.monotonic()
            if now - last >= interval:
                elapsed = max(now - started, 0.001)
                print(''.join([_text(141), format(read_bytes / max(total, 1) * 100, ''.join([_text(142)])), _text(143), format(read_bytes / 1048576, ''.join([_text(144)])), _text(16), format(total / 1048576, ''.join([_text(144)])), _text(145), format(lines, ''.join([_text(45)])), _text(146), format(emitted, ''.join([_text(45)])), _text(147), format(nodes, ''.join([_text(45)])), _text(148), format(read_bytes / 1048576 / elapsed, ''.join([_text(144)])), _text(149)]), file=sys.stderr, flush=True)
                last = now
        if output_format == _text(69):
            out.write(_text(150) if emitted else _text(151))
    elapsed = max(time.monotonic() - started, 0.001)
    print(''.join([_text(152), format(total / 1048576, ''.join([_text(144)])), _text(145), format(lines, ''.join([_text(45)])), _text(146), format(emitted, ''.join([_text(45)])), _text(147), format(nodes, ''.join([_text(45)])), _text(153), format(elapsed, ''.join([_text(144)])), _text(154), format(output_format, ''), _text(155), format(destination, '')]), file=sys.stderr)
    return emitted

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(_text(156), type=Path, help=_text(157))
    p.add_argument(_text(158), _text(159), type=Path, help=_text(160))
    p.add_argument(_text(161), choices=(_text(69), _text(131)), help=_text(162))
    p.add_argument(_text(163), type=int, default=4, help=_text(164))
    p.add_argument(_text(165), action=_text(166), help=_text(167))
    p.add_argument(_text(168), type=float, default=2, help=_text(169))
    p.add_argument(_text(170))
    args = p.parse_args(argv)
    paxio.configure_key(args.xor_key_hex)
    source = args.input.expanduser().resolve()
    destination = (args.output or source.with_name(_text(171))).expanduser().resolve()
    output_format = args.format or (_text(131) if paxio.logical_suffix(destination) == _text(172) else _text(69))
    if not source.is_file():
        p.error(''.join([_text(173), format(source, '')]))
    if source == destination:
        p.error(_text(174))
    if not 1 <= args.decode_depth <= 8:
        p.error(_text(175))
    if not 0.1 <= args.progress_interval <= 3600:
        p.error(_text(176))
    try:
        convert(source, destination, args.decode_depth, args.include_unmatched, args.progress_interval, output_format)
    except (OSError, ValueError) as exc:
        p.exit(1, ''.join([_text(177), format(exc, ''), _text(139)]))
if __name__ == _text(178):
    main()
