"""Offline evidence processing with encoded, nonexecutable JSON data."""
from __future__ import annotations
import base64 as _base64
import json as _json
import zlib as _zlib

CATALOGUE_BLOB = (
    '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'
)
_DATA = _json.loads(_zlib.decompress(_base64.b64decode(CATALOGUE_BLOB)))
def _text(index):
    return _DATA['strings'][index]

import argparse
import copy
import base64
import binascii
import hashlib
import gzip
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit
from contextlib import contextmanager
import importlib.util
import ipaddress
from functools import lru_cache
_spec = importlib.util.spec_from_file_location(_text(0), Path(__file__).with_name(_text(1)))
paxio = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(paxio)
ANALYZER_VERSION = '1.9.1'
TECHNIQUE_PRIORITY = (
    ('rce.',), ('file_access.',), ('sqli.out_of_band',), ('sqli.time_based',),
    ('sqli.error_based',), ('sqli.boolean_blind',), ('sqli.union_select',),
    ('sqli.metadata_enumeration', 'sqli.oracle_privilege_enumeration'),
    ('sqli.boolean_tautology',), ('sqli.stacked_query',),
    ('sqli.order_by_column_count',), ('sqli.obfuscation',), ('sqli.',), ('xss.',), ('ssrf.',),
)

def technique_priority(finding):
    return next((rank for rank, prefixes in enumerate(TECHNIQUE_PRIORITY)
                 if finding['rule_id'].startswith(prefixes)), len(TECHNIQUE_PRIORITY))

def technique_summary(purpose, findings):
    ordered = sorted(findings, key=technique_priority)
    names = dict.fromkeys(f['name'].lower() for f in ordered)
    summary = _text(375) + purpose + _text(376) + ', '.join(names) + '.'
    if ordered[0]['rule_id'] != 'sqli.error_based.divide_by_zero':
        summary += ' ' + ordered[0]['description']
    return summary

RULE_CATALOGUE_VERSION = _text(2)
CATEGORIES = (_text(3), _text(4), _text(5), _text(6), 'file_access', 'xss', 'ssrf')
# Determined attack categories, highest priority first.
DETERMINED_PRIORITY = ('rce', 'file_access', 'sqli', 'xss', 'ssrf')
ARTIFACT_KEYS = (_text(7), _text(8), _text(9), _text(10), _text(11), _text(12))
FORBIDDEN_RE = re.compile(_text(13), re.I)
SQL_CONTEXT = re.compile(_text(14), re.I)
SQL_KEYWORD = re.compile(_text(15), re.I)
SUSPICIOUS = re.compile(_text(16))
RECON = re.compile(_text(17), re.I)
INTERPRETER = re.compile(_text(18), re.I)
URL_RE = re.compile(_text(19), re.I)
PATH_RE = re.compile(_text(20))
_RULES = _DATA['rules']
CATALOGUE = tuple(({_text(21): rid, _text(22): rid.split(_text(26))[0], _text(23): name, _text(24): pattern, _text(25): handler} for (rid, name, pattern, handler) in _RULES))
COMPILED = tuple(((r, re.compile(r[_text(24)], re.I)) for r in CATALOGUE))

def closing(text, start):
    (depth, quote, i) = (0, None, start)
    while i < len(text):
        c = text[i]
        if quote:
            if c == _text(27):
                i += 2
                continue
            if c == quote:
                if quote == _text(28) and i + 1 < len(text) and (text[i + 1] == _text(28)):
                    i += 2
                    continue
                quote = None
        elif c in _text(29):
            quote = c
        elif c == _text(30):
            depth += 1
        elif c == _text(31):
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None

def call_at(text, match):
    start = text.find(_text(30), match.start(), match.end())
    if start < 0:
        return None
    if _text(32) in match.group():
        start = text.rfind(_text(30), match.start(), match.end())
    end = closing(text, start)
    if end is None:
        return None
    return (text[match.start():end + 1], text[start + 1:end], end)

def split_args(text):
    (args, depth, quote, start, i) = ([], 0, None, 0, 0)
    while i < len(text):
        c = text[i]
        if quote:
            if c == _text(27):
                i += 2
                continue
            if c == quote:
                if quote == _text(28) and i + 1 < len(text) and (text[i + 1] == _text(28)):
                    i += 2
                    continue
                quote = None
        elif c in _text(29):
            quote = c
        elif c in _text(33):
            depth += 1
        elif c in _text(34):
            depth -= 1
        elif c == _text(35) and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    args.append(text[start:].strip())
    return args

def string_literals(text):
    return [(m.group(1) if m.group(1) is not None else m.group(2), m.start(), m.end()) for m in re.finditer(_text(36), text)]

def exec_call_arguments(text):
    pattern = re.compile(_text(37))
    calls = []
    for match in pattern.finditer(text):
        call = call_at(text, match)
        if not call:
            continue
        literals = string_literals(call[1])
        values = [literal[0] for literal in literals]
        if not re.search(_text(38), call[0]):
            values = values[:1]
        calls.append((call[0], values))
    for match in re.finditer(_text(39), text):
        calls.append((match.group(), [match.group(1)]))
    return calls

def shell_words(command):
    (tokens, start, quote, i) = ([], None, None, 0)
    while i < len(command):
        c = command[i]
        if start is None and (not c.isspace()):
            start = i
        if c in (_text(27), _text(40)) and quote != _text(28) and (i + 1 < len(command)):
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in _text(29):
            quote = c
        elif c.isspace() and start is not None:
            tokens.append(command[start:i])
            start = None
        i += 1
    if start is not None:
        tokens.append(command[start:])
    return tokens

def tokenize_shell(text):
    (segments, start, operator, quote, i) = ([], 0, None, None, 0)

    def emit(end):
        value = text[start:end].strip()
        if value:
            words = shell_words(value)
            segments.append({_text(41): value, _text(42): words[0].strip(_text(47)), _text(43): words[1:], _text(44): operator, _text(45): start, _text(46): end})
    while i < len(text):
        c = text[i]
        if c in (_text(27), _text(40)) and quote != _text(28) and (i + 1 < len(text)):
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in _text(29):
            quote = c
            i += 1
            continue
        separator = next((s for s in (_text(48), _text(49), _text(50), _text(51), _text(52), _text(53), _text(54), _text(55)) if text.startswith(s, i)), None)
        if separator:
            emit(i)
            operator = separator
            i += len(separator)
            start = i
            continue
        if c == _text(31) and operator == _text(50):
            emit(i)
            i += 1
            start = i
            operator = None
            continue
        i += 1
    emit(len(text))
    return segments

def redirect_target(command):
    (quote, i) = (None, 0)
    while i < len(command):
        c = command[i]
        if c in (_text(27), _text(40)) and quote != _text(28) and (i + 1 < len(command)):
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
        elif c in _text(29):
            quote = c
        elif c == _text(56):
            words = shell_words(command[i + 1:].lstrip(_text(57)).strip())
            return (command[:i].strip(), words[0].strip(_text(47))) if words else None
        i += 1
    return None

def command_family(command):
    name = program(command).lower().rsplit(_text(58), 1)[-1]
    if name in (_text(59), _text(60), _text(61), _text(62), _text(63), _text(64)):
        return _text(65)
    if RECON.fullmatch(name):
        return _text(66)
    if name in (_text(67), _text(68)) or (name == _text(69) and _text(70) in command.lower()):
        return _text(71)
    if name in (_text(72), _text(73), _text(69), _text(74), _text(75), _text(76)):
        return _text(78) if re.search(_text(77), command, re.I) else _text(79)
    if name in (_text(80), _text(81), _text(82)):
        return _text(83)
    if name in (_text(84), _text(85), _text(86)):
        return _text(87)
    if name in (_text(88), _text(89)):
        return _text(79)
    return _text(90)

def command_segments(text, components):
    segments = []

    def add(value, position, origin):
        value = value.strip().strip(_text(47))
        if value and value in text:
            segments.append((value, position, origin))
    for call in components.get(_text(91), []):
        expression = call.get(_text(92), _text(93))
        if expression and expression not in text:
            continue
        args = call.get(_text(94))
        if args:
            for (i, arg) in enumerate(args):
                value = arg.strip().strip(_text(47))
                if i == 0 or (i > 0 and args[i - 1].strip().strip(_text(47)).lower() in (_text(95), _text(96), _text(97))):
                    add(value, text.find(value), _text(98))
        else:
            for argument in call.get(_text(43), []):
                literals = string_literals(argument)
                if literals:
                    add(literals[0][0], text.find(literals[0][0]), _text(98))
    java = bool(re.search(_text(99), text))
    if java:
        for m in re.finditer(_text(100), text):
            call = call_at(text, m)
            if call:
                args = call[1]
                literals = string_literals(args)
                if re.search(_text(101), args):
                    for (i, (value, _, _)) in enumerate(literals):
                        if i == 0 or literals[i - 1][0].lower() in (_text(95), _text(96), _text(97)):
                            add(value, text.find(value), _text(98))
                elif literals:
                    add(literals[0][0], text.find(literals[0][0]), _text(98))
        for m in re.finditer(_text(102), text):
            call = call_at(text, m)
            if call:
                literals = string_literals(call[1])
                for (i, (value, _, _)) in enumerate(literals):
                    if i == 0 or literals[i - 1][0].lower() in (_text(95), _text(96)):
                        add(value, text.find(value), _text(98))
    for (expression, arguments) in exec_call_arguments(text):
        for (i, argument) in enumerate(arguments):
            if i == 0 or arguments[i - 1].lower() in (_text(95), _text(96), _text(97)):
                add(argument, text.find(argument), _text(103))
    for m in INTERPRETER.finditer(text):
        suffix = text[m.end():].strip()
        if suffix and suffix[0] in _text(29):
            literals = string_literals(suffix)
            if literals:
                add(literals[0][0], m.end(), _text(65))
        else:
            add(re.split(_text(104), suffix, maxsplit=1)[0], m.end(), _text(65))
    if re.match(_text(105), text, re.I) and (not SQL_CONTEXT.search(text)):
        add(text, 0, _text(106))
    if not SQL_CONTEXT.search(text) and (not re.search(_text(107), text, re.I)) and not (re.fullmatch(_text(504), text) and all(command_family(part) == _text(90) for part in text.split(_text(52)))):
        for segment in tokenize_shell(text):
            if segment[_text(44)] is not None:
                # Java path parameters are not shell command separators.
                if (segment[_text(44)] == ';' and
                        re.search(r'(?:\.|%2e){2};$', text[:segment[_text(45)]], re.I) and
                        re.fullmatch(r'/[A-Za-z0-9/._~!+,=:@%()-]+', segment[_text(41)]) and
                        command_family(segment[_text(41)]) == _text(90)):
                    continue
                add(segment[_text(41)], segment[_text(45)], _text(108))
        if re.match(_text(109), text, re.I):
            add(text, 0, _text(106))
    unique = {}
    for segment in segments:
        unique.setdefault(segment[0], segment)
    return list(unique.values())

def program(command):
    m = re.match(_text(110), command)
    return m.group(1).strip(_text(47)) if m else _text(93)

class Prose:

    def __init__(self, nodes):
        (self.nodes, self.literals) = (nodes, set())

    def __call__(self, template, **bindings):
        if FORBIDDEN_RE.search(template):
            raise ValueError(_text(111))
        for value in bindings.values():
            if not isinstance(value, str) or not value or (not any((value in n[_text(112)] for n in self.nodes))):
                raise ValueError(_text(113))
            self.literals.add(value)
        return template.format(**bindings)

def conditional(text, delay_start):
    for m in re.finditer(_text(114), text, re.I):
        call = call_at(text, m)
        if call and m.start() < delay_start < call[2]:
            args = split_args(call[1])
            if len(args) >= 2:
                return args[0]
    for m in re.finditer(_text(115), text, re.I):
        if m.end() <= delay_start and (not re.search(_text(116), text[m.end():delay_start], re.I)):
            return m.group(1)
    return None

@lru_cache(maxsize=128)
def opaque_protocol_value(text, depth=0):
    """Return True for safe tokens, False for unsafe content, None if unrecognized."""
    if depth > 3 or len(text) > 65536:
        return None
    if re.fullmatch(r'[A-Za-z0-9]{32,}\|[A-Za-z0-9]{8,}', text):
        return True
    if not re.fullmatch(r'[A-Za-z0-9_+/\-]{24,}={0,2}', text):
        return None
    if re.search(r'/0+(?:[+/-]\d+)*$', text):
        return None
    try:
        raw = base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)
    except (ValueError, binascii.Error):
        return None
    try:
        inflater = _zlib.decompressobj(-15)
        expanded = inflater.decompress(raw, 65537)
        if len(expanded) > 65536 or inflater.unconsumed_tail:
            return False
        if not inflater.eof and not raw.endswith(b'\x00\x00\xff\xff'):
            expanded = b''
        if expanded.lstrip().startswith(b'<'):
            if inflater.unused_data:
                return False
            import xml.etree.ElementTree as ET
            xml = expanded.decode('utf-8')
            if re.search(r'<!\s*(?:DOCTYPE|ENTITY)', xml, re.I):
                return False
            try:
                root = ET.fromstring(xml)
            except ET.ParseError:
                return False
            if root.tag.rsplit('}', 1)[-1] not in ('AuthnRequest', 'LogoutRequest', 'Response'):
                return False
            for element in root.iter():
                if not element.tag.startswith(('{urn:oasis:names:tc:SAML:2.0:', '{http://www.w3.org/2000/09/xmldsig#}')):
                    return False
                for value in (*element.attrib.values(), element.text or '', element.tail or ''):
                    if value.strip() and _analyze([{'node_id': 0, 'value': value}])['category'] != 'not_attack':
                        return False
            return True
        if expanded and not inflater.unused_data:
            try:
                plain = expanded.decode('utf-8')
            except UnicodeDecodeError:
                return False
            return not suspicious_value(plain) and _analyze([{'node_id': 0, 'value': plain}])['category'] not in DETERMINED_PRIORITY
    except (UnicodeDecodeError, ValueError):
        return False
    except _zlib.error:
        pass
    try:
        decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
        return True
    if not decoded.isprintable():
        return True
    if opaque_protocol_value(decoded, depth + 1):
        return True
    return not suspicious_value(decoded) and not any(regex.search(decoded) for _, regex in COMPILED)


def suspicious_value(text):
    """Keep lexical hints without treating ordinary prose as SQL syntax."""
    if opaque_protocol_value(text):
        return False
    if opaque_protocol_value(text) is False:
        return True
    if re.fullmatch(r'[A-Za-z0-9]+(?:[/_.:-][A-Za-z0-9]+)*', text):
        return False
    if re.fullmatch(r'(?:\$\{[A-Za-z_]\w*\}|\{\{[A-Za-z_]\w*\}\}|\*\{[A-Za-z_]\w*\})', text):
        return False
    if re.fullmatch(r'\s*\d+(?:\.\d+)?\s*[<>]\s*\d+(?:\.\d+)?\s*', text):
        return False
    if re.fullmatch(r'https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[A-Za-z0-9_./~-]*)?(?:#[A-Za-z0-9_.:-]+)?', text):
        return False
    if re.fullmatch(r'[A-Za-z][A-Za-z0-9 .,!?-]*', text):
        return False
    if re.fullmatch(r'/(?:[A-Za-z0-9_.~!+,=:@() -]|%20|/)*', text) and not re.search(r'\.\.|//', text):
        return False
    return bool(SQL_KEYWORD.search(text) or SUSPICIOUS.search(text))


def internal_resource_kind(url):
    """Classify explicit internal destinations; never infer pseudonym scope."""
    host = ''
    try:
        host = urlsplit(url).hostname
        if not host:
            return None
        host = host.rstrip('.').lower()
        if host in ('metadata.google.internal', 'metadata.goog', 'instance-data.ec2.internal'):
            return 'metadata_url'
        address = ipaddress.ip_address(host)
    except ValueError:
        if host == 'localhost' or host.endswith(('.localhost', '.internal', '.local')):
            return 'internal_url'
        return None
    if str(address) in ('169.254.169.254', '169.254.170.2', '100.100.100.200', 'fd00:ec2::254'):
        return 'metadata_url'
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    networks = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') if address.version == 4 else ('fc00::/7',)
    if address.is_loopback or address.is_link_local or address.is_unspecified or any(address in ipaddress.ip_network(n) for n in networks):
        return 'internal_url'
    return None


def _analyze(nodes):
    if any((type(n.get(_text(117))) is not int or not isinstance(n.get(_text(112)), str) for n in nodes)):
        raise ValueError(_text(118))
    if len({n[_text(117)] for n in nodes}) != len(nodes):
        raise ValueError(_text(119))
    (prose, findings, steps, seen, step_seen) = (Prose(nodes), [], [], set(), set())
    encoded_derivations = []
    (shell_details, shell_seen) = ([], set())
    artifacts = {key: [] for key in ARTIFACT_KEYS}

    def add_artifact(key, value):
        if value and any((value in n[_text(112)] for n in nodes)) and (value not in artifacts[key]):
            artifacts[key].append(value)

    def evidence(node, *quotes):
        return [{_text(117): node[_text(117)], _text(120): q} for q in dict.fromkeys(quotes) if q]

    def step(node, rank, action, *quotes):
        key = (action, tuple(dict.fromkeys(quotes)))
        if key not in step_seen:
            step_seen.add(key)
            steps.append((node[_text(117)], rank, action, evidence(node, *quotes)))

    def subqueries(node, text, offset=0):
        for m in re.finditer(_text(121), text, re.I):
            quote = m.group()
            step(node, 30 + offset, prose(_text(122), query=quote), quote)
            break

    def found(rule, node, quote, purpose, description, position):
        key = (rule[_text(21)], quote)
        if key in seen:
            return False
        seen.add(key)
        findings.append({_text(123): rule[_text(21)], _text(23): rule[_text(23)], _text(124): description, _text(125): purpose, _text(126): evidence(node, quote), _text(127): (node[_text(117)], position)})
        return True
    depth = {}
    by_id = {n[_text(117)]: n for n in nodes}

    def node_depth(node, visiting=None):
        visiting = set() if visiting is None else visiting
        nid = node[_text(117)]
        if nid in visiting:
            raise ValueError(_text(128))
        if nid in depth:
            return depth[nid]
        parent = node.get(_text(129))
        if parent is not None and parent not in by_id:
            raise ValueError(_text(130))
        depth[nid] = 0 if parent is None else 1 + node_depth(by_id[parent], visiting | {nid})
        return depth[nid]
    ordered_nodes = sorted(nodes, key=lambda n: (-node_depth(n), n[_text(117)]))
    seen_values = set()
    for node in ordered_nodes:
        text = node[_text(112)]
        if text in seen_values:
            continue
        seen_values.add(text)
        segments = command_segments(text, node.get(_text(131), {}))
        for (command, at, origin) in segments:
            for part in tokenize_shell(command):
                if part[_text(41)] in shell_seen or part[_text(41)] not in text:
                    continue
                shell_seen.add(part[_text(41)])
                detail = {k: part[k] for k in (_text(42), _text(43), _text(44))}
                if detail[_text(44)] is None and origin == _text(108):
                    preceding = text[:at].rstrip()
                    op = re.search(_text(132), preceding)
                    detail[_text(44)] = op.group() if op else _text(133) if at and text[at - 1] == _text(54) else None
                detail.update(family=command_family(part[_text(41)]), evidence=evidence(node, part[_text(41)]))
                shell_details.append(detail)
        node_had_rule = False
        for (rule, regex) in COMPILED:
            handler = rule[_text(25)]
            command_handlers = {_text(134), _text(65), _text(66), _text(135), _text(78), _text(136), _text(137), _text(138), _text(139)}
            if handler in command_handlers:
                candidates = []
                if handler == _text(65):
                    candidates = [(m, text, 0, _text(140)) for m in regex.finditer(text)]
                else:
                    for (command, pos, origin) in segments:
                        for m in regex.finditer(command) if handler != _text(134) else [None]:
                            candidates.append((m, command, pos, origin))
            else:
                candidates = [(m, text, 0, _text(93)) for m in regex.finditer(text)]
            for (match, value, pos, origin) in candidates:
                quote = match.group() if match else value
                purpose = description = None
                local_steps = []
                position = pos + (match.start() if match else 0)
                call = None
                if handler in {_text(141), _text(142), _text(143), _text(144), _text(145), _text(146), _text(147)}:
                    call = call_at(value, match)
                if handler in ('file_access', 'include_wrapper_execution'):
                    templates = _DATA['file_access'][rule[_text(21)]]
                    purpose = templates[0]
                    description = prose(templates[1], path=quote)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(8), quote)
                elif handler in _DATA.get('generic_probe', {}):
                    if handler in ('internal_url', 'metadata_url'):
                        if internal_resource_kind(quote) != handler:
                            continue
                        # A wiki redirect directive does not request a server-side fetch.
                        if not quote.lower().startswith(('http://', 'https://')) and re.search(r'\{\{#externalredirect:[^}]*$', text[:match.start()], re.I):
                            continue
                    elif handler in ('sqli_literal_function_comparison', 'sqli_row_limit_probe', 'sqli_constant_condition_probe', 'sqli_values_expression', 'sqli_identity_function_comparison', 'sqli_database_timer_probe'):
                        searches = re.finditer(r'\b(?:text|summary|description|title)\s*~\s*(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')', text, re.I)
                        if any(m.start() <= match.start() < m.end() for m in searches):
                            continue
                        if handler == 'sqli_constant_condition_probe':
                            condition = unquote_plus(quote)
                            constants = re.fullmatch(r'\s*\(?\s*(\d+)\s*\)?\s*=\s*\(?\s*(\d+)\s*\)?\s*', condition)
                            if constants and constants[1].lstrip('0') == constants[2].lstrip('0'):
                                continue
                    elif handler == 'file_access_application_classes_path':
                        add_artifact('file_paths', quote)
                    elif handler in ('database_call', 'scalar_query', 'conditional_probe'):
                        if handler == 'conditional_probe' and re.match(r'CASE\b', quote, re.I):
                            end = re.search(r'\bEND\b', text[match.end():], re.I)
                            if not end:
                                continue
                            quote = text[match.start():match.end() + end.end()]
                            condition = re.split(r'\bTHEN\b', quote, maxsplit=1, flags=re.I)[0]
                        else:
                            call = call_at(text, match)
                            if not call:
                                continue
                            quote = call[0]
                            args = split_args(call[1])
                            condition = args[0] if args else ''
                            if handler == 'conditional_probe' and len(args) != 3:
                                continue
                        if handler == 'conditional_probe':
                            # Constant comparisons, subqueries and session context are probes;
                            # ordinary IF(price>3,...) and display-field transforms are not.
                            if not re.search(r'\bSELECT\b|@@\w+|\bSYS_CONTEXT\s*\(|\bUSER\s*(?:=|<>|IS)|\b\d+\s*(?:=|<>|!=|>|<)\s*\d+|\b(?:LENGTH|LEN|ASCII|ORD|CHAR_LENGTH)\s*\(\s*\(*\s*(?:(?:SUBSTR|SUBSTRING|MID)\s*\(\s*\(*)?\s*[\'\"]', condition, re.I):
                                continue
                    elif rule['id'] == 'xss.attribute_breakout':
                        opening = text.rfind('<', 0, match.start())
                        if opening >= 0 and text.rfind('>', 0, match.start()) < opening and text[opening + 1:].lower().startswith('jsp:'):
                            continue
                    templates = _DATA['generic_probe'][handler]
                    purpose = templates[0]
                    description = prose(templates[1], expr=quote)
                    local_steps.append((25, description, quote))
                elif handler in _DATA['python_probe']:
                    bindings = {'expr': quote}
                    if handler == 'python_delay':
                        bindings['seconds'] = match.group('seconds')
                    templates = _DATA['python_probe'][handler]
                    purpose = prose(templates[0], **bindings)
                    description = prose(templates[1], **bindings)
                    local_steps.append((25, description, quote))
                elif handler == _text(507):
                    if opaque_protocol_value(text):
                        continue
                    if any(m.start() <= match.start() < m.end() for m in URL_RE.finditer(text)):
                        continue
                    if re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*(?:/[A-Za-z0-9_-]+){2,}', text) and not SQL_KEYWORD.search(text):
                        continue
                    if re.match(r'[A-Za-z]+\s*\(', quote):
                        call = call_at(text, match)
                        if not call:
                            continue
                        quote = call[0]
                        if handler and re.match(_text(224), quote, re.I):
                            if SQL_CONTEXT.search(text) and re.search(_text(225), quote, re.I):
                                continue
                            if not string_literals(quote):
                                continue
                    comparison = re.match(_text(180), text[match.start() + len(quote):])
                    if comparison:
                        quote += comparison.group()
                    condition_match = re.search(_text(115), quote, re.I) or re.search(_text(518), quote, re.I)
                    condition = condition_match.group(1) if condition_match else None
                    if condition:
                        description = prose(_text(510), expr=quote, condition=condition)
                    elif re.match(_text(511), quote, re.I):
                        description = prose(_text(512), expr=quote)
                    elif re.match(_text(513), quote, re.I):
                        description = prose(_text(514), expr=quote)
                    else:
                        description = prose(_text(515), expr=quote)
                    purpose = _text(516) + description[:-1]
                    boolean = next((f for f in findings if f[_text(123)].startswith('sqli.boolean_tautology') and f[_text(127)][0] == node[_text(117)]), None)
                    if boolean and _text(200) in boolean[_text(124)] and description == prose(_text(515), expr=quote):
                        condition_quote = boolean[_text(126)][0][_text(120)]
                        purpose = prose(_text(517), condition=condition_quote, expr=quote)
                    local_steps.append((45, description, quote))
                elif handler == _text(148):
                    if not (SQL_CONTEXT.search(text) or re.search(_text(149), text, re.I)):
                        continue
                    if re.fullmatch(_text(150), quote, re.I):
                        if len(re.findall(_text(151), text, re.I)) < 2 or not re.search(_text(152), text, re.I):
                            continue
                        quote = text
                    else:
                        call = call_at(text, match)
                        if not call:
                            continue
                        quote = call[0]
                    purpose = prose(_text(153), expr=quote)
                    description = prose(_text(154), expr=quote)
                    condition = conditional(text, match.start())
                    if condition:
                        description += prose(_text(155), condition=condition)
                        local_steps.append((20, prose(_text(156), condition=condition), condition))
                    local_steps.append((60, prose(_text(157), expr=quote), quote))
                elif handler in {_text(158), _text(159), _text(160), _text(161), _text(162)}:
                    if handler == _text(158):
                        if re.search(_text(163), text):
                            continue
                        if quote.startswith(_text(55)):
                            command = quote[1:-1]
                            if not command.strip():
                                continue
                        else:
                            call = call_at(text, match)
                            if not call:
                                continue
                            quote = call[0]
                            if re.match(_text(164), quote, re.I) and (not re.search(_text(165), call[1], re.I)):
                                continue
                    elif handler == _text(159):
                        if not re.search(_text(166), text):
                            continue
                        call = call_at(text, match)
                        if not call:
                            continue
                        quote = call[0]
                        if re.match(_text(167), quote) and (not re.search(_text(168), text[call[2] + 1:])):
                            continue
                        if re.match(_text(167), quote):
                            tail = re.match(_text(168), text[call[2] + 1:])
                            at = call[2] + 1
                            end = closing(text, at + tail.end() - 1)
                            if end is not None:
                                quote = text[match.start():end + 1]
                    elif handler == _text(160):
                        call = call_at(text, match)
                        at = text.rfind(_text(30), match.start(), match.end())
                        end = closing(text, at)
                        if end is None:
                            continue
                        quote = text[match.start():end + 1]
                    elif handler == _text(161):
                        if not re.search(_text(169), quote, re.I):
                            continue
                    elif handler == _text(162):
                        if not re.search(_text(170), quote, re.I):
                            continue
                    language = {_text(158): _text(171), _text(159): _text(172), _text(160): _text(173), _text(161): _text(161), _text(162): _text(174)}[handler]
                    purpose = prose(_text(175) + language + _text(176), expr=quote)
                    description = prose(_text(177) + language + _text(178), expr=quote)
                    local_steps.append((25, description, quote))
                    for (expression, arguments) in exec_call_arguments(quote):
                        for command in arguments:
                            add_artifact(_text(7), command)
                            local_steps.append((35, prose(_text(179), command=command), expression))
                elif handler in {_text(141), _text(142)}:
                    if not call or not SQL_CONTEXT.search(text):
                        continue
                    comparison = re.match(_text(180), value[call[2] + 1:])
                    if not comparison:
                        continue
                    quote = value[match.start():call[2] + 1 + comparison.end()]
                    comp = comparison.group(1) + _text(181) + comparison.group(2)
                    (op, number) = (comparison.group(1), comparison.group(2))
                    expr = call[1]
                    if handler == _text(142):
                        inner = re.match(_text(182), expr, re.I)
                        inner_call = call_at(expr, inner) if inner else None
                        args = split_args(inner_call[1]) if inner_call else []
                        if len(args) < 2 or not re.fullmatch(_text(183), args[1]):
                            continue
                        (target, index) = (args[0], args[1])
                        purpose = prose(_text(184), index=index, expr=target)
                        description = prose(_text(185), expr=target, index=index, op=op, number=number)
                        local_steps += [(35, prose(_text(186), index=index, expr=target), quote), (40, prose(_text(187), function=value[match.start():match.end() - 1].strip()), quote)]
                    else:
                        target = expr
                        if re.search(_text(188), expr, re.I) and re.search(_text(189), expr, re.I):
                            purpose = _text(190)
                        else:
                            purpose = prose(_text(191), expr=target)
                        description = prose(_text(192), expr=target, op=op, number=number)
                        local_steps.append((40, prose(_text(193), expr=target), quote))
                    subqueries(node, expr)
                    local_steps.append((50, prose(_text(194), op=op, number=number), quote))
                    position = 40
                elif handler == _text(195):
                    if not re.search(_text(196), text[:match.start()], re.I):
                        continue
                    if not text[:match.start()].strip() and not SQL_CONTEXT.search(text):
                        continue
                    (left, right) = (match.group(_text(197)), match.group(_text(198)))
                    quoted = left[0] in _text(29)
                    if quoted:
                        if right[0] != left[0]:
                            continue
                        delimiter = left[0]
                        right_value = right[1:-1] if right.endswith(delimiter) and len(right) > 1 else right[1:]
                        equal = left[1:-1].replace(delimiter * 2, delimiter) == right_value.replace(delimiter * 2, delimiter)
                    else:
                        if right[0] in _text(29):
                            continue
                        equal = int(left) == int(right)
                    label = _text(200) if equal else _text(201)
                    purpose = prose(_text(202), condition=quote)
                    description = prose(_text(203) + label + _text(204), condition=quote)
                    local_steps.append((20, description, quote))
                elif handler == _text(143):
                    if rule[_text(21)].endswith(_text(205)):
                        args = split_args(call[1]) if call else []
                        seconds = args[-1] if len(args) >= 2 else _text(93)
                    elif re.search(_text(206), quote, re.I):
                        duration = re.match(_text(207), text[match.end():])
                        if not duration:
                            continue
                        seconds = duration.group(1)
                        quote += duration.group()
                    else:
                        seconds = call[1].strip() if call else _text(93)
                    if not seconds or (_text(208) not in seconds and (not re.fullmatch(_text(209), seconds))):
                        continue
                    if call:
                        quote = call[0]
                    condition = conditional(text, match.start())
                    unit = _text(210) if _text(208) in seconds else _text(211)
                    purpose = prose(_text(212) + unit, seconds=seconds)
                    if condition:
                        purpose += prose(_text(213), condition=condition)
                        description = prose(_text(214), condition=condition, call=quote)
                        local_steps.append((20, prose(_text(215), condition=condition), condition))
                        subqueries(node, condition)
                    else:
                        description = prose(_text(216), call=quote)
                    local_steps.append((60, prose(_text(217) + unit + _text(26), seconds=seconds), quote))
                    position = 60
                elif handler in {_text(218), _text(219)}:
                    purpose = prose(_text(220) + (_text(221) if handler == _text(218) else _text(222)), sql=quote)
                    description = prose(_text(223), sql=quote)
                    local_steps.append((20, description, quote))
                elif handler == _text(144):
                    if not call:
                        continue
                    if re.match(_text(224), quote, re.I) and (not re.search(_text(225), call[1], re.I)):
                        continue
                    if not SQL_CONTEXT.search(text) and (not re.search(_text(226), quote, re.I)):
                        continue
                    quote = call[0]
                    purpose = prose(_text(227), expr=quote)
                    description = prose(_text(228), expr=quote)
                    subqueries(node, call[1])
                    local_steps.append((45, prose(_text(229), expr=quote), quote))
                elif handler == _text(230):
                    purpose = _text(231)
                    description = _text(232)
                    local_steps.append((30, description, quote))
                    add_artifact(_text(10), _text(233))
                elif handler == _text(147):
                    if re.match(_text(234), quote, re.I) and (not call):
                        tail = text[match.end():]
                        literal = re.match(_text(207), tail)
                        if not literal:
                            continue
                        quote += literal.group()
                    elif not call:
                        continue
                    else:
                        quote = call[0]
                    if re.match(_text(235), quote, re.I) and (not re.search(_text(236), quote)):
                        continue
                    if re.match(_text(237), quote, re.I) and _text(49) not in quote:
                        continue
                    purpose = prose(_text(238), expr=quote)
                    description = prose(_text(239), expr=quote)
                    local_steps.append((50, description, quote))
                    for (literal, _, _) in string_literals(quote):
                        if re.fullmatch(_text(240), literal) and _text(26) in literal:
                            add_artifact(_text(12), literal)
                elif handler == _text(241):
                    if not SQL_CONTEXT.search(text):
                        continue
                    if re.fullmatch(_text(242), quote, re.I) and (not re.search(_text(225), text, re.I)):
                        continue
                    if quote.upper().startswith(_text(243)):
                        call = call_at(text, match)
                        if not call or not re.search(_text(244), call[1], re.I):
                            continue
                        quote = call[0]
                    purpose = prose(_text(245), object=quote)
                    description = prose(_text(246), object=quote)
                    local_steps.append((30, description, quote))
                    add_artifact(_text(10), quote)
                elif handler == _text(247):
                    purpose = prose(_text(248), clause=quote)
                    description = prose(_text(249), clause=quote)
                    local_steps.append((40, description, quote))
                elif handler in {_text(145), _text(146)}:
                    if not call:
                        continue
                    quote = call[0]
                    purpose = prose(_text(220) + (_text(250) if handler == _text(145) else _text(251)), call=quote)
                    description = prose(_text(252), call=quote)
                    embedded = bool(re.search(_text(253), text, re.I))
                    local_steps.append((40 if embedded else 25, prose((_text(254) if embedded else _text(255)) + _text(256), call=quote), quote))
                elif handler == _text(257):
                    path = next((v for v in match.groupdict().values() if v))
                    block = re.search(_text(258), text, re.I)
                    if not block:
                        continue
                    quote = path
                    purpose = prose(_text(259), path=path)
                    description = prose(_text(260), path=path)
                    local_steps.append((15, prose(_text(261), path=path), path))
                    local_steps.append((20, description, path, block.group()))
                    for parameter in re.finditer(_text(262), block.group()):
                        local_steps.append((30, prose(_text(263), parameter=parameter.group(1)), parameter.group()))
                    if re.search(_text(100), block.group()) and (not re.search(_text(264), block.group())):
                        local_steps.append((40, _text(265), block.group()))
                    output = re.search(_text(266), block.group())
                    if output:
                        local_steps.append((60, _text(267), output.group()))
                    add_artifact(_text(8), path)
                elif handler == _text(268):
                    if not re.search(_text(269), quote, re.I):
                        continue
                    purpose = prose(_text(270), expr=quote)
                    description = prose(_text(271), expr=quote)
                    local_steps.append((15, description, quote))
                elif handler == _text(272):
                    method = re.search(_text(273), text)
                    if not method:
                        continue
                    purpose = _text(274)
                    description = prose(_text(275), call=quote)
                    local_steps.append((20, description, quote))
                    local_steps.append((25, _text(276), method.group()))
                elif handler == _text(277):
                    engine = re.search(_text(278), text)
                    evaluation = re.search(_text(279), text)
                    if not engine or not evaluation:
                        continue
                    engine_call = call_at(text, engine)
                    eval_call = call_at(text, evaluation)
                    if not engine_call or not eval_call:
                        continue
                    quote = text[match.start():eval_call[2] + 1]
                    purpose = prose(_text(280), engine=engine_call[0])
                    description = prose(_text(281), engine=engine_call[0], script=eval_call[0])
                    local_steps += [(20, prose(_text(282), engine=engine_call[0]), engine_call[0]), (30, prose(_text(283), script=eval_call[0]), eval_call[0])]
                elif handler == _text(284):
                    resolved = resolve_lookup(quote)
                    if not re.search(_text(285), resolved, re.I) or not re.search(_text(286), resolved, re.I):
                        continue
                    purpose = prose(_text(287), expr=quote)
                    description = prose(_text(288), expr=quote)
                    if resolved != quote:
                        description += _text(289)
                        encoded_derivations.append({_text(117): node[_text(117)], _text(120): quote, _text(290): _text(292), _text(291): resolved})
                    local_steps.append((30, description, quote))
                    for lookup in re.finditer(_text(293), quote, re.I):
                        if _text(294) not in lookup.group():
                            local_steps.append((25, prose(_text(295), lookup=lookup.group()), lookup.group()))
                    callback = re.search(_text(296), quote, re.I)
                    if callback:
                        url = callback.group()
                        if url.endswith(_text(297)):
                            url = url[:-1]
                        add_artifact(_text(9), url)
                        host = url.split(_text(298), 1)[1].split(_text(58), 1)[0]
                        add_artifact(_text(12), host.split(_text(208), 1)[0] if _text(299) not in host else host)
                elif handler == _text(134):
                    if origin != _text(108):
                        continue
                    name = program(value)
                    if not re.fullmatch(_text(300), name) or not re.search(_text(301), name):
                        continue
                    if command_family(value) == _text(90) and not re.search(_text(505), name, re.I) and not re.match(_text(506), value):
                        continue
                    quote = value
                    purpose = prose(_text(302), program=name, command=quote)
                    description = prose(_text(303), command=quote)
                    local_steps.append((30 + pos, description, quote))
                    add_artifact(_text(7), quote)
                    add_artifact(_text(7), name)
                elif handler == _text(65):
                    suffix = text[match.end():].strip()
                    args = string_literals(suffix) if suffix.startswith((_text(304), _text(28))) else []
                    command = args[0][0] if args else re.split(_text(305), suffix, maxsplit=1)[0].strip()
                    if not command:
                        continue
                    quote = text[match.start():match.end()] + (suffix[:args[0][2]] if args else command)
                    if quote not in text:
                        quote = match.group().strip()
                    purpose = prose(_text(306), command=command, interpreter=match.group().strip())
                    description = prose(_text(307), invocation=quote)
                    local_steps.append((20, description, quote))
                    if re.search(_text(308), match.group(), re.I):
                        try:
                            decoded = base64.b64decode(command, validate=True).decode(_text(309))
                        except (ValueError, UnicodeDecodeError, binascii.Error):
                            decoded = None
                        description += _text(310)
                        if decoded is not None:
                            description += _text(311) + json.dumps(decoded, ensure_ascii=False) + _text(26)
                            prose.literals.add(decoded)
                            encoded_derivations.append({_text(117): node[_text(117)], _text(120): command, _text(290): _text(312), _text(291): decoded})
                        local_steps.append((25, _text(313), command))
                    else:
                        local_steps.append((30, prose(_text(314), command=command), command))
                    add_artifact(_text(7), command)
                elif handler == _text(66):
                    if not RECON.fullmatch(program(value)) or match.start() != value.find(program(value)):
                        continue
                    quote = value
                    purpose = prose(_text(315), command=quote)
                    description = prose(_text(316), command=quote)
                    local_steps.append((35 + pos, description, quote))
                    add_artifact(_text(7), program(value))
                elif handler == _text(135):
                    if not re.match(_text(317), value, re.I):
                        continue
                    quote = match.group()
                    purpose = prose(_text(318), command=quote)
                    description = prose(_text(319), command=quote)
                    (left, right) = quote.split(_text(52), 1)
                    local_steps += [(30, prose(_text(320), command=left.strip()), left.strip()), (40, prose(_text(321), shell=right.strip()), right.strip())]
                    add_artifact(_text(7), quote)
                elif handler == _text(78):
                    if not (re.match(_text(322), value, re.I) or re.search(_text(323), value, re.I)):
                        continue
                    if re.match(_text(324), value, re.I) and (not re.search(_text(325), value)):
                        continue
                    if re.match(_text(326), value, re.I) and (not re.search(_text(327), value)):
                        continue
                    quote = value
                    purpose = prose(_text(328), command=quote)
                    description = prose(_text(329), command=quote)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(7), quote)
                elif handler == _text(136):
                    name = program(value).lower()
                    if name not in (_text(89), _text(88), _text(72), _text(73)):
                        continue
                    if name == _text(72) and re.search(_text(330), value) or (name == _text(73) and re.search(_text(331), value)) or _text(52) in value:
                        continue
                    host_match = re.search(_text(332), value)
                    if not host_match:
                        continue
                    quote = value
                    purpose = prose(_text(333), host=host_match.group(1))
                    description = prose(_text(334), command=quote)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(12), host_match.group(1))
                    add_artifact(_text(7), quote)
                elif handler == _text(335):
                    call = call_at(text, match)
                    literals = string_literals(call[1]) if call else []
                    if not literals or not re.search(_text(336), literals[0][0], re.I):
                        continue
                    path = literals[0][0]
                    quote = call[0]
                    purpose = prose(_text(337), path=path)
                    description = prose(_text(338), expression=quote)
                    if re.search(_text(339), path, re.I):
                        description += _text(340)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(8), path)
                elif handler == _text(139):
                    if not (re.match(_text(341), value, re.I) or re.match(_text(342), value, re.I) or re.match(_text(343), value, re.I)):
                        continue
                    quote = value
                    purpose = prose(_text(344), command=quote)
                    description = prose(_text(345), command=quote)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(7), quote)
                elif handler == _text(137):
                    if program(value).lower() not in (_text(80), _text(81), _text(82)):
                        continue
                    path = re.search(_text(346), value, re.I)
                    if not path:
                        continue
                    quote = value
                    purpose = prose(_text(347), path=path.group())
                    description = prose(_text(348), command=quote)
                    if re.search(_text(339), path.group(), re.I):
                        description += _text(340)
                    local_steps.append((35, description, quote))
                    add_artifact(_text(8), path.group())
                    add_artifact(_text(7), quote)
                elif handler == _text(138):
                    if not re.match(_text(349), value, re.I):
                        continue
                    quote = match.group()
                    redirection = redirect_target(quote)
                    if redirection is None:
                        continue
                    (source, path) = redirection
                    if not path:
                        continue
                    purpose = prose(_text(350), path=path)
                    description = prose(_text(351), path=path)
                    local_steps += [(35, prose(_text(352), command=source), quote), (60, description, path)]
                    add_artifact(_text(8), path)
                    add_artifact(_text(7), quote)
                if purpose is None:
                    continue
                if found(rule, node, quote, purpose, description, position):
                    node_had_rule = True
                    for (rank, action, *quotes) in local_steps:
                        step(node, rank, action, *quotes)
                    if handler in {_text(272), _text(277)}:
                        for (_, _, *quotes) in local_steps:
                            findings[-1][_text(126)].extend(evidence(node, *quotes))
        if node_had_rule:
            sql_rule = any((f[_text(123)].startswith(_text(353)) and f[_text(127)][0] == node[_text(117)] for f in findings))
            if sql_rule:
                prefix = re.match(_text(354), text, re.I)
                if prefix:
                    token = prefix.group(1)
                    step(node, 0, prose(_text(355) + (_text(356) if token[0] in _text(29) else _text(357)) + _text(358), token=token), token)
                for m in re.finditer(_text(359), text, re.I):
                    step(node, 10, prose(_text(360), operator=m.group(1)), m.group())
                    break
                comment = re.search(_text(361), text)
                if comment:
                    step(node, 10000, _text(362), comment.group())
            for m in URL_RE.finditer(text):
                url = m.group()
                if _text(299) in url and url.count(_text(299)) != url.count(_text(297)):
                    continue
                add_artifact(_text(9), url)
                try:
                    host = urlsplit(url).hostname
                    add_artifact(_text(12), host)
                except ValueError:
                    pass
            for m in re.finditer(_text(363), text):
                add_artifact(_text(12), m.group(1))
            for m in PATH_RE.finditer(text):
                add_artifact(_text(8), m.group().rstrip(_text(364)))
            if sql_rule:
                for m in re.finditer(_text(365), text, re.I):
                    add_artifact(_text(10), m.group(1))
            for m in re.finditer(_text(366), text):
                add_artifact(_text(11), m.group(1))
    category = next((category for category in DETERMINED_PRIORITY if any(f['rule_id'].startswith(category + '.') for f in findings)), _text(6) if any((suspicious_value(n[_text(112)]) or n.get(_text(368)) == _text(369) and not opaque_protocol_value(n[_text(112)]) for n in nodes)) else _text(5))
    findings.sort(key=lambda f: (f[_text(127)], f[_text(123)]))
    purposes = list(dict.fromkeys((f[_text(125)] for f in findings)))
    primary = min(findings, key=technique_priority) if findings else None
    if primary:
        purpose = primary[_text(125)]
        summary = technique_summary(purpose, findings)
    else:
        purpose = _text(378) if category == _text(5) else _text(379)
        summary = _text(380)
    for f in findings:
        del f[_text(127)]
    ordered_steps = []
    for (_, _, action, ev) in sorted(steps, key=lambda s: (s[0], s[1])):
        ordered_steps.append({_text(381): len(ordered_steps) + 1, _text(382): action, _text(126): ev})
    hints = []
    joined = _text(54).join((n[_text(112)] for n in nodes))
    for (label, pattern) in [(_text(383), _text(384)), (_text(385), _text(386)), (_text(387), _text(388)), (_text(389), _text(390))]:
        if re.search(pattern, joined, re.I):
            hints.append(label)
    result = {_text(22): category, _text(125): purpose, _text(391): summary, _text(392): findings, _text(393): ordered_steps, _text(394): artifacts, _text(395): hints[0] if len(hints) == 1 else None, _text(396): list(dict.fromkeys((f[_text(123)] for f in findings))), _text(397): _text(401) if findings else _text(402) if category == _text(6) else None, _text(398): sorted(prose.literals), _text(399): encoded_derivations, _text(400): shell_details}
    validate(result, nodes)
    return result
SQL_WORDS = set(_text(403).split())

def normalize_sql(text):
    (chars, spans, mechanisms) = ([], [], [])
    i = 0
    while i < len(text):
        if text[i] in _text(29):
            (quote, start) = (text[i], i)
            i += 1
            while i < len(text):
                if text[i] == _text(27):
                    i += 2
                    continue
                if text[i] == quote:
                    if i + 1 < len(text) and text[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            for at in range(start, min(i, len(text))):
                chars.append(text[at])
                spans.append((at, at + 1))
            continue
        comment = re.match(_text(404), text[i:])
        if comment:
            end = i + comment.end()
            mechanisms.append((_text(405), text[i:end]))
            if comment.group(1):
                start = i + comment.start(2)
                for at in range(start, i + comment.end(2)):
                    chars.append(text[at])
                    spans.append((at, at + 1))
            else:
                before = re.search(_text(406), _text(93).join(chars))
                after = re.match(_text(407), text[end:])
                merged = (before.group() + after.group()).lower() if before and after else _text(93)
                if merged not in SQL_WORDS:
                    chars.append(_text(181))
                    spans.append((i, end))
            i = end
            continue
        whitespace = re.match(_text(408), text[i:], re.I)
        if whitespace:
            end = i + whitespace.end()
            if not chars or chars[-1] != _text(181):
                chars.append(_text(181))
                spans.append((i, end))
            elif spans:
                spans[-1] = (spans[-1][0], end)
            if _text(409) in whitespace.group() or whitespace.group() != _text(181):
                mechanisms.append((_text(410), whitespace.group()))
            i = end
            continue
        word = re.match(_text(407), text[i:])
        if word:
            token = word.group()
            folded = token.lower() if token.lower() in SQL_WORDS else token
            if token != token.upper() and token != token.lower() and (token.lower() in SQL_WORDS):
                mechanisms.append((_text(411), token))
            for (offset, c) in enumerate(folded):
                chars.append(c)
                spans.append((i + offset, i + offset + 1))
            i += len(token)
            continue
        chars.append(text[i])
        spans.append((i, i + 1))
        i += 1
    return (_text(93).join(chars), spans, mechanisms)

def resolve_lookup(expression):
    text = expression
    for _ in range(32):

        def replace(match):
            body = match.group(1)
            if body.lower().startswith(_text(412)):
                return body[6:].lower()
            if body.lower().startswith(_text(413)):
                return body[6:].upper()
            if _text(294) in body:
                return body.rsplit(_text(294), 1)[1]
            return match.group()
        updated = re.sub(_text(414), replace, text)
        if updated == text:
            return text
        text = updated
    return text

def resolve_sql_literal(expression):
    expression = expression.strip()
    if re.fullmatch(_text(415), expression):
        raw = bytes.fromhex(expression[2:])
        return raw.decode(_text(416))
    pieces = re.split(_text(417), expression)
    result = []
    for piece in pieces:
        match = re.fullmatch(_text(418), piece, re.I)
        if not match:
            raise ValueError(_text(419))
        numbers = [int(number.strip()) for number in match.group(1).split(_text(35))]
        if any((number > 1114111 or 55296 <= number <= 57343 for number in numbers)):
            raise ValueError(_text(420))
        result.extend((chr(number) for number in numbers))
    return _text(93).join(result)

def analyze(nodes):
    (views, maps, mechanisms) = ([], {}, [])
    for node in nodes:
        text = node[_text(112)]
        if isinstance(text, str) and not opaque_protocol_value(text) and (SQL_CONTEXT.search(text) or SQL_KEYWORD.search(text)) and (not re.search(_text(421), text, re.I)):
            (normalized, spans, changes) = normalize_sql(text)
        else:
            (normalized, spans, changes) = (text, [(i, i + 1) for i in range(len(text))], [])
        view = dict(node, value=normalized)
        views.append(view)
        maps[node[_text(117)]] = (text, normalized, spans)
        mechanisms.extend(((node, label, quote) for (label, quote) in changes))
    result = _analyze(views)

    def original(nid, quote):
        (text, normalized, spans) = maps[nid]
        if quote in text:
            return quote
        start = normalized.find(quote)
        if start < 0 or not quote:
            raise ValueError(_text(422))
        return text[spans[start][0]:spans[start + len(quote) - 1][1]]
    replacements = {}
    derived = {d[_text(291)] for d in result[_text(399)]}
    for literal in result[_text(398)]:
        if literal in derived:
            continue
        for view in views:
            if literal in view[_text(112)]:
                replacements[literal] = original(view[_text(117)], literal)
                break
    for entry in result[_text(392)] + result[_text(393)] + result.get(_text(400), []):
        for ev in entry[_text(126)]:
            ev[_text(120)] = original(ev[_text(117)], ev[_text(120)])
    for (old, new) in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if old == new:
            continue
        pattern = re.escape(old)
        if old[0].isalnum():
            pattern = _text(423) + pattern
        if old[-1].isalnum():
            pattern += _text(424)

        def restore(text):
            return re.sub(pattern, lambda _: new, text)
        for field in (_text(125), _text(391)):
            result[field] = restore(result[field])
        for entry in result[_text(392)] + result[_text(393)]:
            for field in (_text(125), _text(124), _text(382)):
                if field in entry:
                    entry[field] = restore(entry[field])
    result[_text(398)] = sorted({replacements.get(s, s) for s in result[_text(398)]})
    for (key, literals) in result[_text(394)].items():
        restored = []
        for literal in literals:
            if any((literal in node[_text(112)] for node in nodes)):
                restored.append(literal)
            else:
                for view in views:
                    if literal in view[_text(112)]:
                        restored.append(original(view[_text(117)], literal))
                        break
        result[_text(394)][key] = list(dict.fromkeys(restored))
    for node in nodes:
        if not (SQL_CONTEXT.search(node[_text(112)]) or SQL_KEYWORD.search(node[_text(112)])):
            continue
        for match in re.finditer(_text(425), node[_text(112)], re.I):
            try:
                resolved = resolve_sql_literal(match.group())
            except (ValueError, UnicodeDecodeError, OverflowError):
                continue
            if resolved and all((c.isprintable() for c in resolved)):
                mechanisms.append((node, _text(426), match.group()))
                result[_text(399)].append({_text(117): node[_text(117)], _text(120): match.group(), _text(290): _text(427), _text(291): resolved})
                result[_text(398)].extend([match.group(), resolved])
    if mechanisms and result[_text(22)] in (_text(3), _text(4)):
        seen = set()
        (evidence, labels, sentences) = ([], [], [])
        for (node, label, quote) in mechanisms:
            if (label, quote) in seen:
                continue
            seen.add((label, quote))
            labels.append(label)
            evidence.append({_text(117): node[_text(117)], _text(120): quote})
            result[_text(398)].append(quote)
        for d in result[_text(399)]:
            if d[_text(290)] == _text(427):
                sentences.append(d[_text(120)] + _text(428) + json.dumps(d[_text(291)], ensure_ascii=False) + _text(26))
        description = _text(429) + _text(430).join(dict.fromkeys(labels)) + _text(377) + _text(181).join(sentences)
        result[_text(392)].append({_text(123): _text(431), _text(23): _text(432), _text(125): _text(433), _text(124): description.strip(), _text(126): evidence})
        result[_text(396)].append(_text(431))
    if result[_text(392)]:
        result[_text(391)] = technique_summary(result[_text(125)], result[_text(392)])
    result[_text(398)] = sorted(set(result[_text(398)]))
    validate_json_leaf_extractions(nodes)
    validate(result, nodes)
    return result

def validate_json_leaf_extractions(nodes):
    by_id = {n['node_id']: n for n in nodes}
    for node in nodes:
        if node.get('transform') == 'json_leaf_extract':
            parent = by_id.get(node.get('parent_node_id'))
            context = ' route={} parent_node_id={}'.format(node.get('route'), node.get('parent_node_id'))
            if parent is None:
                raise ValueError('Unknown extraction parent' + context)
            try:
                leaves = json_structure(json.loads(parent['value'], parse_constant=reject_json_constant, parse_float=finite_json_float))[1]
            except (ValueError, KeyError, TypeError, IndexError, RecursionError) as exc:
                raise ValueError('Invalid extraction parent' + context) from exc
            if node.get('route') not in leaves:
                raise ValueError('Unknown extraction route' + context)
            leaf = leaves[node['route']]
            if node['value'] != (leaf if isinstance(leaf, str) else stable_json(leaf)):
                raise ValueError('Incorrect extracted value' + context)

def validate(result, nodes):
    values = {n[_text(117)]: n[_text(112)] for n in nodes}
    derived = set()
    for derivation in result.get(_text(399), []):
        quote = derivation[_text(120)]
        if quote not in values.get(derivation[_text(117)], _text(93)) or derivation[_text(290)] not in (_text(312), _text(427), _text(292)):
            raise ValueError(_text(434))
        try:
            if derivation[_text(290)] == _text(427):
                decoded = resolve_sql_literal(quote)
            elif derivation[_text(290)] == _text(292):
                decoded = resolve_lookup(quote)
            else:
                decoded = base64.b64decode(quote, validate=True).decode(_text(309))
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise ValueError(_text(435)) from exc
        if decoded != derivation[_text(291)]:
            raise ValueError(_text(436))
        derived.add(decoded)
    literals = result.get(_text(398), [])
    for literal in literals:
        if not literal or not (any((literal in v for v in values.values())) or literal in derived):
            raise ValueError(_text(113))
    texts = [result[_text(125)], result[_text(391)], result[_text(397)] or _text(93)]
    for entry in result[_text(392)] + result[_text(393)] + result.get(_text(400), []):
        texts.extend((entry.get(k, _text(93)) for k in (_text(23), _text(124), _text(382), _text(125))))
        if not entry[_text(126)]:
            raise ValueError(_text(437))
        for ev in entry[_text(126)]:
            if type(ev[_text(117)]) is not int or not ev[_text(120)] or ev[_text(120)] not in values.get(ev[_text(117)], _text(93)):
                raise ValueError(_text(438))
    for entries in result[_text(394)].values():
        for value in entries:
            if not value or not any((value in v for v in values.values())):
                raise ValueError(_text(439))
    for text in texts:
        for literal in sorted(literals, key=len, reverse=True):
            text = text.replace(literal, _text(440))
            text = text.replace(json.dumps(literal, ensure_ascii=False), _text(440))
        if FORBIDDEN_RE.search(text):
            raise ValueError(_text(111))
    if [s[_text(381)] for s in result[_text(393)]] != list(range(1, len(result[_text(393)]) + 1)):
        raise ValueError(_text(441))

def load_resolutions(path):
    with paxio.open_text_in(path) as stream:
        if paxio.logical_suffix(path) == _text(442):
            for (line, text) in enumerate(stream, 1):
                if text.strip():
                    try:
                        yield json.loads(text, parse_constant=lambda name: name)
                    except ValueError as exc:
                        raise ValueError(''.join([_text(443), format(line, ''), _text(444), format(exc, '')])) from exc
        else:
            data = json.load(stream, parse_constant=lambda name: name)
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise ValueError(_text(445))
            yield from data

def timestamp_key(value):
    if value is None:
        return (2, _text(93))
    try:
        return (0, float(value))
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(str(value).replace(_text(446), _text(447)))
            if parsed.tzinfo is not None:
                return (0, parsed.timestamp())
        except ValueError:
            pass
    return (1, str(value))

def decoding_chain(nodes):
    by_id = {n[_text(117)]: n for n in nodes}
    chains = []
    for node in nodes:
        (out, seen) = ([], set())
        while node is not None:
            if node[_text(117)] in seen:
                raise ValueError(_text(128))
            seen.add(node[_text(117)])
            out.append(node[_text(368)])
            parent = node.get(_text(129))
            if parent is not None and parent not in by_id:
                raise ValueError(_text(130))
            node = by_id.get(parent)
        chains.append(list(reversed(out)))
    return max(chains, key=len, default=[])

def reject_json_constant(value):
    raise ValueError('Non-finite JSON number')


def finite_json_float(value):
    number = float(value)
    if number in (float('inf'), float('-inf')):
        raise ValueError('Non-finite JSON number')
    return number


def stable_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def json_structure(value, path='', leaves=None):
    leaves = {} if leaves is None else leaves
    if isinstance(value, dict):
        shape = ['object', [[key, json_structure(value[key], path + '.' + key if re.fullmatch(r'[A-Za-z_]\w*', key) else path + '[' + json.dumps(key) + ']', leaves)[0]] for key in sorted(value)]]
    elif isinstance(value, list):
        shape = ['array', [json_structure(child, path + '[' + str(i) + ']', leaves)[0] for i, child in enumerate(value)]]
    else:
        leaves[path or '$'] = value
        shape = 'scalar'
    return shape, leaves


def series_value(unit):
    nodes = unit['decoding_nodes']
    by_id = {n['node_id']: n for n in nodes}
    def depth(node):
        seen = set()
        while node.get('parent_node_id') is not None:
            if node['node_id'] in seen:
                raise ValueError('Cycle in decoding nodes')
            seen.add(node['node_id'])
            node = by_id[node['parent_node_id']]
        return len(seen)
    for node in sorted(nodes, key=lambda n: (-depth(n), n['node_id'])):
        try:
            value = json.loads(node['value'], parse_constant=reject_json_constant, parse_float=finite_json_float)
        except (ValueError, TypeError):
            continue
        if not isinstance(value, (dict, list)):
            continue
        shape, leaves = json_structure(value)
        return {'kind': 'json', 'shape': shape, 'leaves': leaves, 'node': node,
                'value': stable_json(value)}
    value = unit['occurrences'][0]['dec_value']
    try:
        parsed = json.loads(value, parse_constant=reject_json_constant, parse_float=finite_json_float)
    except ValueError:
        return {'kind': 'text', 'value': value}
    if not isinstance(parsed, (dict, list)):
        return {'kind': 'text', 'value': value}
    # Preserve an explicit derivation if the URL-decoded occurrence is not a node.
    parent = next((n for n in nodes if n['value'] == unit['url_decoded_value']), None)
    nid = max(by_id, default=-1) + 1
    node = {'node_id': nid, 'parent_node_id': parent['node_id'] if parent else None,
            'transform': 'url_decode', 'value': value}
    nodes.append(node)
    shape, leaves = json_structure(parsed)
    return {'kind': 'json', 'shape': shape, 'leaves': leaves, 'node': node,
            'value': stable_json(parsed)}


def common_edges(values):
    prefix = os.path.commonprefix(values)
    suffix = os.path.commonprefix([v[len(prefix):][::-1] for v in values])[::-1]
    boundaries = set(" \t\r\n\"'()=,&")
    while prefix and prefix[-1] not in boundaries:
        prefix = prefix[:-1]
    while suffix and suffix[0] not in boundaries:
        suffix = suffix[1:]
    return prefix, suffix


def determined(unit):
    return bool(unit['analysis'] and unit['analysis']['category'] in DETERMINED_PRIORITY)


def build_series(units):
    buckets, values = {}, {}
    for unit in units:
        unit['series_id'] = None
        unit['effective_category'] = unit['analysis']['category'] if unit['analysis'] else CATEGORIES[3]
        if unit['analysis_status'] == 'error':
            continue
        value = values[unit['unit_id']] = series_value(unit)
        if value['kind'] == 'json':
            value['leaf_keys'] = {p: stable_json(v) for p, v in value['leaves'].items()}
        # Scope comes from each occurrence, never from a representative unit.
        for occurrence in unit['occurrences']:
            target = occurrence.get('target') or {}
            scope = (target.get('site'), target.get('uri_path'), unit['parameter_name'])
            buckets.setdefault(scope, {})[unit['unit_id']] = unit
    result = []
    for bucket_index, (scope, bucket) in enumerate(sorted(buckets.items(), key=lambda item: stable_json(item[0])), 1):
        rows = sorted(bucket.values(), key=lambda u: (timestamp_key(u['first_seen']), u['unit_id']))
        candidates = {}
        text_rows, shapes = [], {}
        for unit in rows:
            value = values[unit['unit_id']]
            if value['kind'] == 'text':
                text_rows.append(unit)
            else:
                shapes.setdefault(stable_json(value['shape']), []).append(unit)
        if len({values[u['unit_id']]['value'] for u in text_rows}) >= 3:
            prefix, suffix = common_edges([values[u['unit_id']]['value'] for u in text_rows])
            template = {'kind': 'text', 'prefix': prefix, 'suffix': suffix}
            candidates[stable_json(template)] = (template, text_rows)
        for shape_rows in shapes.values():
            first = values[shape_rows[0]['unit_id']]
            varying = set()
            for unit in shape_rows[1:]:
                leaf_keys = values[unit['unit_id']]['leaf_keys']
                varying.update(p for p, v in first['leaf_keys'].items() if leaf_keys[p] != v)
                if len(varying) > 32:
                    break
            if not varying or len(varying) > 32:
                continue
            if len(varying) <= 2:
                template = {'kind': 'json', 'shape': first['shape'],
                            'fixed': {p: v for p, v in first['leaves'].items() if p not in varying},
                            'paths': sorted(varying)}
                candidates[stable_json(template)] = (template, shape_rows)
                continue
            paths = sorted(first['leaves'])
            for point in sorted(varying):
                groups = {}
                for unit in shape_rows:
                    value = values[unit['unit_id']]
                    key = tuple(value['leaf_keys'][p] for p in paths if p != point)
                    groups.setdefault(key, []).append(unit)
                for matches in groups.values():
                    if len({values[u['unit_id']]['leaf_keys'][point] for u in matches}) < 3:
                        continue
                    value = values[matches[0]['unit_id']]
                    template = {'kind': 'json', 'shape': value['shape'],
                                'fixed': {p: v for p, v in value['leaves'].items() if p != point},
                                'paths': [point]}
                    candidates[stable_json(template)] = (template, matches)
        assigned = set()
        for key, (template, matches) in sorted(candidates.items(), key=lambda item: (-len(item[1][1]), item[0])):
            matches = [u for u in matches if u['unit_id'] not in assigned]
            distinct = {values[u['unit_id']]['value'] for u in matches}
            if len(distinct) < 3:
                continue
            if template['kind'] == 'text':
                prefix, suffix = common_edges(list(distinct))
                template = dict(template, prefix=prefix, suffix=suffix)
                points = [{'prefix': prefix, 'suffix': suffix}] if prefix or suffix else ['whole value']
            else:
                points = template['paths']
            sid = 'series_' + hashlib.sha256(stable_json([scope, template]).encode('utf-8')).hexdigest()
            matches.sort(key=lambda u: (timestamp_key(u['first_seen']), u['unit_id']))
            injected = {}
            for unit in matches:
                uid = unit['unit_id']
                value = values[uid]
                original_nodes = copy.deepcopy(unit['decoding_nodes'])
                original_analysis = copy.deepcopy(unit['analysis'])
                original_status = unit['analysis_status']
                route = '-'
                injected[uid] = value['value']
                try:
                    nodes = unit['decoding_nodes']
                    if template['kind'] == 'json':
                        route = ', '.join(points)
                        by_id = {n['node_id']: n for n in nodes}
                        parent = by_id[value['node']['node_id']]
                        leaves = json_structure(json.loads(parent['value'], parse_constant=reject_json_constant, parse_float=finite_json_float))[1]
                        extracted = {p: leaves[p] for p in points}
                        injected[uid] = next(iter(extracted.values())) if len(points) == 1 else extracted
                        for path, leaf in extracted.items():
                            route = path
                            nodes.append({'node_id': max(n['node_id'] for n in nodes) + 1,
                                          'parent_node_id': parent['node_id'],
                                          'transform': 'json_leaf_extract', 'route': path,
                                          'value': leaf if isinstance(leaf, str) else stable_json(leaf)})
                    else:
                        text = value['value']
                        segment = text[len(prefix):len(text) - len(suffix) if suffix else len(text)]
                        injected[uid] = segment
                        parent = next((n for n in nodes if segment in n['value']), None)
                        if parent is not None:
                            nodes.append({'node_id': max(n['node_id'] for n in nodes) + 1,
                                          'parent_node_id': parent['node_id'], 'transform': 'text_segment_extract',
                                          'route': points[0], 'value': segment})
                    unit['analysis'] = analyze(nodes)
                    unit['analysis_status'] = 'undetermined' if unit['analysis']['category'] == CATEGORIES[3] else 'analysed'
                except (ValueError, KeyError, TypeError, IndexError, RecursionError) as exc:
                    unit['decoding_nodes'] = original_nodes
                    unit['analysis'] = original_analysis
                    unit['analysis_status'] = original_status
                    unit['series_error'] = '{}: {}'.format(type(exc).__name__, exc)
                    print('[Series] error unit={} route={}: {}'.format(uid, route, unit['series_error']), file=sys.stderr, flush=True)
            count = sum(determined(u) for u in matches)
            families, members, ips, occurrences = set(), [], set(), []
            if template['kind'] == 'json':
                point_label = ', '.join(points)
            else:
                point_label = 'the varying text' if prefix or suffix else 'whole value'
                if prefix:
                    point_label += ' after ' + repr(prefix)
                if suffix:
                    point_label += ' before ' + repr(suffix)
            # Count each determined member once per family; require a 5% share.
            family_counts, category_counts = {}, {}
            for unit in matches:
                if determined(unit):
                    category = unit['analysis']['category']
                    category_counts[category] = category_counts.get(category, 0) + 1
                    for family in {r.split('.')[0] for r in unit['analysis']['rule_ids']}:
                        family_counts[family] = family_counts.get(family, 0) + 1
            families = {family for family, support in family_counts.items() if support * 20 >= count}
            priority = {c: i for i, c in enumerate(DETERMINED_PRIORITY)}
            substantial = [c for c, support in category_counts.items() if support * 20 >= count]
            dominant = min(substantial, key=lambda c: (-category_counts[c], priority.get(c, len(priority)), c), default=None)
            file_series = 'file_access' in families
            for unit in matches:
                uid = unit['unit_id']
                own = determined(unit)
                probe = isinstance(injected[uid], str) and injected[uid].strip().casefold() in _DATA['series_keywords']
                path_probe = file_series and isinstance(injected[uid], str) and re.fullmatch(_DATA['filesystem_path'], injected[uid], re.I) is not None
                role = 'determined' if count and own else 'path_probe' if path_probe and not unit.get('series_error') else 'keyword_probe' if count and probe and not unit.get('series_error') else 'variant'
                unit.update(series_id=sid, series_role=role)
                if count and not own:
                    if role in ('keyword_probe', 'path_probe'):
                        unit['determined_via'] = 'series'
                    unit['series_description'] = "Submits the {} {} at injection point {}, one of {} values sent to the same field.".format(
                        'path probe' if role == 'path_probe' else 'keyword probe' if probe else 'variant', repr(injected[uid]), point_label, len(distinct))
                analysis = unit['analysis']
                if role in ('keyword_probe', 'path_probe'):
                    families.add(role)
                unit['effective_category'] = 'file_access' if role == 'path_probe' else dominant if role == 'keyword_probe' else analysis['category']
                members.append({'unit_id': uid, 'injected_value': injected[uid], 'series_role': role,
                                'category': unit['effective_category'], 'own_category': analysis['category'],
                                'rule_ids': analysis['rule_ids']})
                for occurrence in unit['occurrences']:
                    occurrences.append(occurrence)
                    activity = occurrence.get('activity') or {}
                    source_ips = activity.get('source_ips') or []
                    ips.update(source_ips if isinstance(source_ips, list) else [source_ips])
                assigned.add(uid)
            dates = lambda field: [o['activity'][field] for o in occurrences if o.get('activity') and o['activity'].get(field) is not None]
            first, last = dates('first_seen'), dates('last_seen')
            names = sorted({t['name'] for u in matches for t in u['analysis']['techniques']})
            summary = 'A series of {} values was sent to injection point {} of parameter {} on {}; it includes '.format(
                len(distinct), point_label, scope[2], scope[1])
            summary += '{} determined value{}'.format(count, '' if count == 1 else 's') if count else 'no determined values'
            if names:
                summary += ' (' + ', '.join(names) + ')'
            keyword_count = sum(m['series_role'] == 'keyword_probe' for m in members)
            if keyword_count:
                summary += ' and {} keyword probe{}'.format(keyword_count, '' if keyword_count == 1 else 's')
            path_count = sum(m['series_role'] == 'path_probe' for m in members)
            if path_count:
                summary += ' and {} path probe{}'.format(path_count, '' if path_count == 1 else 's')
            summary += '.'
            result.append({'series_id': sid, 'target': {'site': scope[0], 'uri_path': scope[1]},
                           'parameter_name': scope[2], 'injection_points': points, 'source_ips': sorted(ips),
                           'source_ip_overlap': sorted(set.intersection(*(set((o.get('activity') or {}).get('source_ips') or []) for o in occurrences))) if occurrences else [],
                           'first_seen': min(first, key=timestamp_key) if first else None,
                           'last_seen': max(last, key=timestamp_key) if last else None,
                           'value_count': len(distinct), 'determined_count': count,
                           'families': sorted(families), 'members': members, 'summary': summary})
        if bucket_index % 500 == 0 or bucket_index == len(buckets):
            print('[Series] buckets={}/{} series={}'.format(bucket_index, len(buckets), len(result)), file=sys.stderr, flush=True)
    if not buckets:
        print('[Series] buckets=0/0 series=0', file=sys.stderr, flush=True)
    return sorted(result, key=lambda s: s['series_id'])


def determined_report(report):
    selected = [u for u in report['units'] if determined(u) or u.get('determined_via') == 'series']
    selected_ids = {u['unit_id'] for u in selected}
    excluded = [u for u in report['units'] if u['unit_id'] not in selected_ids]
    filtered = {key: value for key, value in report.items() if key != 'unmatched'}
    filtered.update(units=selected, series=[s for s in report['series'] if s['determined_count'] > 0],
                    meta=dict(report['meta'], filter='determined_only', units_emitted=len(selected),
                              excluded_units=report['meta'].get('excluded_units', 0) + len(excluded),
                              excluded_requests=report['meta'].get('excluded_requests', 0) + sum(
                                  (o.get('activity') or {}).get('request_count') or 0
                                  for u in excluded for o in u['occurrences'])))
    return filtered


def build_report(items, source=_text(93), source_sha256=_text(93), exclude_not_attack=False, generated_at=None):
    units = {}
    for (index, item) in enumerate(items, 1):
        sp = item[_text(448)]
        nodes = copy.deepcopy(item[_text(449)])
        node_digest = hashlib.sha256(json.dumps([n.get(_text(112)) for n in nodes], ensure_ascii=False, separators=(_text(35), _text(208))).encode(_text(416), _text(450))).hexdigest()
        target = item.get('target') or {}
        key = [sp[_text(23)], sp[_text(451)], node_digest,
               target.get('site'), target.get('uri_path')]
        uid = _text(452) + hashlib.sha256(json.dumps(key, ensure_ascii=False, separators=(_text(35), _text(208))).encode(_text(416), _text(450))).hexdigest()
        unit = units.get(uid)
        if unit is None:
            unit = units[uid] = {_text(453): uid, _text(454): sp[_text(23)], _text(451): sp[_text(451)], _text(449): nodes, _text(455): []}
        occurrence = {k: item.get(k) for k in (_text(456), _text(457), _text(458), _text(459), _text(460))}
        occurrence.update({k: sp.get(k) for k in (_text(461), _text(462), _text(463))})
        occurrence['dec_value'] = unquote_plus(sp[_text(463)], encoding='utf-8', errors='replace')
        unit[_text(455)].append(occurrence)
        if index % 1000 == 0:
            print(''.join([_text(464), format(index, ''.join([_text(35)])), _text(465), format(len(units), ''.join([_text(35)]))]), file=sys.stderr, flush=True)
    (counts, output, unmatched, errors) = (dict.fromkeys(CATEGORIES, 0), [], [], [])
    for analysed_index, unit in enumerate(units.values(), 1):
        try:
            unit['final_decoded_value'] = unit[_text(451)]
            unit[_text(466)] = decoding_chain(unit[_text(449)])
            nodes = unit[_text(449)]
            if nodes:
                by_id = {n['node_id']: n for n in nodes}
                def depth(node):
                    count = 0
                    while node.get('parent_node_id') is not None:
                        node = by_id[node['parent_node_id']]
                        count += 1
                    return count
                deepest = min(nodes, key=lambda n: (-depth(n), n['node_id']))
                unit['final_decoded_value'] = deepest['value']
            unit[_text(467)] = analyze(unit[_text(449)])
            category = unit[_text(467)][_text(22)]
            unit[_text(468)] = _text(6) if category == _text(6) else _text(469)
        except (ValueError, KeyError, TypeError, IndexError, RecursionError) as exc:
            category = _text(6)
            unit.update(analysis_status=_text(144), analysis_error=''.join([format(type(exc).__name__, ''), _text(444), format(exc, '')]), analysis=None)
            unit.setdefault(_text(466), [])
            errors.append(unit[_text(453)])
            print(''.join([_text(470), format(unit[_text(453)], ''), _text(181), format(unit[_text(471)], '')]), file=sys.stderr, flush=True)
        counts[category] += 1
        unit[_text(455)].sort(key=lambda o: timestamp_key((o.get(_text(460)) or {}).get(_text(472))))
        for (field, chooser) in [(_text(472), min), (_text(473), max)]:
            dates = [(o.get(_text(460)) or {}).get(field) for o in unit[_text(455)]]
            dates = [d for d in dates if d is not None]
            unit[field] = chooser(dates, key=timestamp_key) if dates else None
        if category == _text(6):
            unmatched.append(unit[_text(453)])
        if not exclude_not_attack or category != _text(5):
            output.append(unit)
        if analysed_index % 2000 == 0:
            print('[Analyze] analysed={}/{}'.format(analysed_index, len(units)), file=sys.stderr, flush=True)
    series = build_series(list(units.values()))
    counts = dict.fromkeys(CATEGORIES, 0)
    unmatched, output = [], []
    for unit in units.values():
        category = unit['analysis']['category'] if unit['analysis'] else CATEGORIES[3]
        counts[category] += 1
        if category == CATEGORIES[3]:
            unmatched.append(unit['unit_id'])
        if not exclude_not_attack or category != CATEGORIES[2] or unit.get('determined_via') == 'series':
            output.append(unit)
    output.sort(key=lambda u: (timestamp_key(u[_text(472)]), u[_text(453)]))
    emitted_ids = {u['unit_id'] for u in output}
    return {'series': series, _text(474): {_text(477): source, _text(478): source_sha256, _text(479): generated_at or datetime.now(timezone.utc).isoformat(timespec=_text(211)), _text(480): ANALYZER_VERSION, _text(481): RULE_CATALOGUE_VERSION, _text(482): counts, _text(483): len(units), _text(484): len(output), _text(485): len(errors), _text(486): sorted(errors), 'effective_category_counts': {c: sum(u['effective_category'] == c for u in units.values()) for c in CATEGORIES}, 'excluded_units': len(units) - len(output), 'excluded_requests': sum((o.get('activity') or {}).get('request_count') or 0 for u in units.values() if u['unit_id'] not in emitted_ids for o in u['occurrences'])}, _text(475): output, _text(476): sorted(unmatched)}

def atomic_write_json(path, obj):
    print('[Write] {}'.format(path), file=sys.stderr, flush=True)
    with paxio.open_text_out(path) as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write(_text(54))

@contextmanager
def pipeline_resolutions(source, destination, keep, key, decode_depth, matched_only=False):
    assessor = load_assessor()
    assessor.paxio.configure_key(key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.resolutions-', suffix='.json.pax', dir=destination.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        assessor.convert(source, temporary, decode_depth, not matched_only, 2)
        if keep is not None:
            print('[Write] {}'.format(keep), file=sys.stderr, flush=True)
            if paxio.logical_suffix(keep) == '.jsonl':
                with paxio.open_text_out(keep) as stream:
                    for item in load_resolutions(temporary):
                        stream.write(json.dumps(item, ensure_ascii=False) + '\n')
            else:
                with paxio.open_binary_in(temporary) as incoming, paxio.open_binary_out(keep) as outgoing:
                    for chunk in iter(lambda: incoming.read(1 << 20), b''):
                        outgoing.write(chunk)
        yield temporary
    finally:
        temporary.unlink(missing_ok=True)


_PERCENT = re.compile(r'%[0-9A-Fa-f]{2}')


def _decode_tokens(text, plus=False):
    """Split percent-encoded TEXT into (decoded character, original representation) pairs."""
    tokens, pos = [], 0
    for m in re.finditer(r'(?:%[0-9A-Fa-f]{2})+', text):
        tokens += [(' ', '+') if plus and c == '+' else (c, c) for c in text[pos:m.start()]]
        run, data, i = m.group(), bytes.fromhex(m.group().replace('%', '')), 0
        while i < len(data):
            b = data[i]
            n = 2 if 0xC0 <= b < 0xE0 else 3 if 0xE0 <= b < 0xF0 else 4 if 0xF0 <= b < 0xF8 else 1
            char = data[i:i + n].decode('utf-8', errors='replace')
            if len(char) != 1 or i + n > len(data):
                n, char = 1, data[i:i + 1].decode('utf-8', errors='replace')
            tokens.append((char, run[3 * i:3 * (i + n)]))
            i += n
        pos = m.end()
    return tokens + [(' ', '+') if plus and c == '+' else (c, c) for c in text[pos:]]


def _encoded_spans(text, spans, plus=False):
    """Run SPANS on the decoded TEXT and map its replacements back, encoding them like the text they replace."""
    from urllib.parse import quote
    tokens = _decode_tokens(text, plus)
    starts = [0]
    for _, original in tokens:
        starts.append(starts[-1] + len(original))
    decoded = ''.join(c for c, _ in tokens)
    result = []
    for start, end, replacement in _narrow(decoded, spans(decoded)):
        literal = {c for c, o in tokens[start:end] if c == o} - set('%&#+')
        encoded = {c for c, o in tokens[start:end] if c != o}
        result.append((starts[start], starts[end], ''.join(
            c if c in literal or (c not in encoded and c.isascii() and (c.isalnum() or c in '-._~'))
            else '+' if plus and c == ' ' else quote(c, safe='') for c in replacement)))
    return result


def _narrow(text, spans):
    """Split each replacement into the parts that actually differ, so unchanged characters keep their encoding."""
    import difflib
    for start, end, replacement in spans:
        original = text[start:end]
        if len(original) + len(replacement) > 4000:
            yield start, end, replacement
            continue
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, original, replacement, autojunk=False).get_opcodes():
            if op != 'equal':
                yield start + i1, start + i2, replacement[j1:j2]


def _apply_spans(text, spans):
    parts, pos = [], 0
    for start, end, replacement in spans:
        parts += [text[pos:start], replacement]
        pos = end
    return ''.join(parts) + text[pos:]


def _sanitizer(fixed=frozenset()):
    """Shared pseudonymisation core: one consistent entity table plus the text rewriting helpers.

    Values in FIXED (pseudonyms of an earlier pass, used for verification) are never replaced."""
    import ipaddress
    from types import SimpleNamespace
    table, counts = {}, {}

    def assign(original, kind, make):
        if original in fixed:
            return original
        if original not in table:
            counts[kind] = counts.get(kind, 0) + 1
            table[original] = make(counts[kind])
        return table[original]

    def label(name):
        return assign(name, 'host', lambda n: 'host{}'.format(n))

    public = {'w3.org', 'schemas.microsoft.com', 'schemas.xmlsoap.org', 'google.com', 'microsoft.com', 'github.com'}
    # A dotted name ending in a common file extension is a file name, not a domain.
    file_ext = {'json', 'xml', 'html', 'htm', 'php', 'asp', 'aspx', 'ashx', 'asmx', 'jsp', 'js', 'css', 'txt',
                'log', 'config', 'conf', 'ini', 'exe', 'dll', 'bat', 'cmd', 'ps1', 'sh', 'py', 'sql', 'bak',
                'zip', 'rar', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv',
                'rptx', 'rlf', 'jar', 'war', 'class', 'cs', 'java', 'tmp', 'dat', 'db', 'mdb', 'yml', 'yaml'}

    # In free text a dotted name is a domain only with a known TLD (any 2-letter country code needs a
    # first label of 2+ chars), so SQL schema.table / package.function names stay intact.
    generic_tld = {'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io', 'app', 'dev',
                   'cloud', 'online', 'site', 'xyz', 'top', 'tech', 'pro', 'mobi', 'asia', 'shop',
                   'local', 'lan', 'corp', 'internal', 'intra', 'intranet', 'home', 'arpa'}

    def domain_like(low):
        labels = low.split('.')
        tld = labels[-1]
        return tld in generic_tld or (len(tld) == 2 and tld.isalpha() and len(labels[0]) >= 2)

    def entity(value, context=False):
        """IP, email or domain -> pseudonym; anything else unchanged. context=True: known host position."""
        if '@' in value:
            return assign(value, 'email', lambda n: 'user{}@example.invalid'.format(n))
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            low = value.lower().rstrip('.')
            if (low == 'localhost' or low in public or low.endswith(('.invalid', '.example', '.test'))
                    or (not context and (low.rsplit('.', 1)[-1] in file_ext or not domain_like(low)))):
                return value
            return assign(value, 'host', lambda n: 'host{}.invalid'.format(n))
        if ip.is_loopback or ip.is_unspecified:
            return value
        if ip.version == 4:
            return assign(value, 'ipv4', lambda n: str(ipaddress.IPv4Address('198.18.0.0') + n)
                          if n < 131072 else 'ipv4-{}.invalid'.format(n))
        return assign(value, 'ipv6', lambda n: '2001:db8::' + format(n, 'x'))

    def site(value):
        return entity(value, True) if ('.' in value or ':' in value) else label(value)

    # Well-known OS and public software folder names stay readable (paths split at spaces too).
    keep = {s.casefold() for s in (
        'Windows', 'System32', 'SysWOW64', 'drivers', 'etc', 'Program', 'Files', 'Program Files',
        'Program Files (x86)', 'ProgramData', 'Common Files', 'Users', 'Public', 'Default', 'AppData',
        'Local', 'Roaming', 'Temp', 'tmp', 'inetpub', 'wwwroot', 'inetsrv', 'LogFiles', 'Microsoft',
        'Microsoft.NET', 'Framework', 'Framework64', 'Config', 'conf', 'logs', 'bin', 'lib', 'Apache',
        'Software', 'Foundation', 'Tomcat', 'webapps', 'ROOT', 'WEB-INF', 'META-INF', 'htdocs', 'xampp',
        'nginx', 'Java', 'jdk', 'jre', 'Oracle', 'MySQL', 'boot', 'repair', 'debug', 'Fonts', 'Tasks')}
    canaries = [rx for rule, rx in COMPILED if rule[_text(21)].startswith('file_access.') and 'canary' in rule[_text(21)]]
    ent = (r'(?P<email>[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,})'
           r'|(?P<ip4>(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d))'
           r'|(?P<ip6>(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:]))'
           r'|(?P<fqdn>(?<![\w-])(?<![\w-]\.)(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}(?![\w-]))')
    ent_re = re.compile(ent)
    main_re = re.compile(
        r'''(?P<url>[A-Za-z][\w+.-]*://[^\s<>"']*)'''
        r'''|(?P<win>(?:\\\\[\w.$-]+|(?<![A-Za-z])[A-Za-z]:(?=[\\/]))(?:[\\/]+[^\s<>"'|;&()\\/,]+)*[\\/]?)'''
        r'''|(?P<unix>(?<![\w/:.-])/[^\s<>"'?#;,()|&]+)'''
        r'|' + ent)
    uris = set()

    def uri(value):
        return assign(value, 'uri', lambda n: '/path{}'.format(n))

    def win_path(path):
        hits = [m.group() for rx in canaries if (m := rx.search(path))]
        parts = re.split(r'([\\/]+)', path)
        unc = path.startswith('\\\\')
        for i, part in enumerate(parts):
            if i % 2 or not part or i == 0:
                continue
            if unc and i == 2:
                parts[i] = part if part.casefold() in keep else site(part)
            elif len(part) >= 2 and part not in ('..',) and part.casefold() not in keep and not any(part in h for h in hits):
                ext = re.search(r'\.[A-Za-z][A-Za-z0-9]{0,4}$', part)
                parts[i] = assign(part, 'segment', lambda n: 'seg{}'.format(n) + (ext.group() if ext else ''))
        return ''.join(parts)

    def ent_sub(m):
        return entity(m.group())

    def sub(m):
        text = m.group()
        if m.group('url'):
            # scheme://[credentials@]host[:port][/path][?query]; the rest of the URL gets the entity scan.
            scheme, rest = text.split('://', 1)
            cred, host, tail = re.match(r'([^/?#@]*@)?(\[[^\]/]*\]?|[^/?#:\[]*)(.*)', rest, re.S).groups()
            core = host.strip('[]')
            port, path, query = re.match(r'(:\d+)?(/[^?#]*)?(.*)', tail, re.S).groups()
            if path in uris:
                tail = (port or '') + uri(path) + ent_re.sub(ent_sub, query)
            else:
                tail = ent_re.sub(ent_sub, tail)
            return (ent_re.sub(ent_sub, scheme) + '://' + ent_re.sub(ent_sub, cred or '')
                    + (host.replace(core, entity(core, True)) if core else host) + tail)
        if m.group('win'):
            return win_path(text)
        if m.group('unix'):
            core = text.rstrip('.')
            return uri(core) + text[len(core):] if core in uris else ent_re.sub(ent_sub, text)
        return entity(text)

    def percent_aware(spans):
        # Percent-encoded text: replace entities found in the decoded text; everything else keeps its encoding.
        return lambda t: _encoded_spans(t, spans) if _PERCENT.search(t) else spans(t)

    def regex_spans(rx, fn):
        return lambda t: [(m.start(), m.end(), r) for m in rx.finditer(t) if (r := fn(m)) != m.group()]
    clean_spans = percent_aware(regex_spans(main_re, sub))

    def names_spans():
        """Whole-word replacement spans of learned single-label host names (UNC servers, bare sites), or None."""
        names = {k: v for k, v in table.items() if v.startswith('host') and not v.endswith('.invalid') and len(k) >= 3}
        if not names:
            return None
        return percent_aware(regex_spans(re.compile(r'[A-Za-z0-9_$-]+'), lambda m: names.get(m.group(), m.group())))

    def names_pass():
        spans = names_spans()
        return spans and (lambda t: _apply_spans(t, spans(t)))
    def payload_path(path):
        """A request path carrying injection syntax: plain segments get pseudonyms, the syntax stays readable
        and entities inside the other segments are pseudonymised (percent-encoding is kept)."""
        from urllib.parse import unquote as _uq
        plain = _uq(path)
        hits = [m.group() for rx in canaries if (m := rx.search(plain))]
        parts = re.split(r'(/+)', path)
        for i, part in enumerate(parts):
            if i % 2 or not part:
                continue
            if (re.fullmatch(r'[A-Za-z0-9_~-]+(?:\.[A-Za-z0-9_~-]+)*', part) and part.casefold() not in keep
                    and len(part) >= 2 and not any(part in h for h in hits)):
                ext = re.search(r'\.[A-Za-z][A-Za-z0-9]{0,4}$', part)
                parts[i] = assign(part, 'segment', lambda n: 'seg{}'.format(n) + (ext.group() if ext else ''))
            else:
                parts[i] = _apply_spans(part, clean_spans(part))
        return ''.join(parts)

    return SimpleNamespace(table=table, counts=counts, uris=uris, entity=entity, site=site, payload_path=payload_path,
                           uri=uri, clean=lambda t: _apply_spans(t, clean_spans(t)), clean_spans=clean_spans,
                           names_spans=names_spans, names_pass=names_pass)


def sanitize_report(report, only_series=False):
    """Pseudonymise IPs, emails, domains, URL hosts, target URI paths and Windows/UNC path segments."""
    if only_series:
        ids = {m['unit_id'] for s in report.get('series', []) for m in s['members']}
        report = dict(report, units=[u for u in report.get('units', []) if u['unit_id'] in ids])
    protected = {'rule_id', 'rule_ids', 'category', 'categories', 'own_category', 'effective_category',
                 'series_role', 'determined_via', 'unit_id', 'series_id', 'payload_id', 'event_id',
                 'source_sha256', 'source_container_sha256', 'analysis_status', 'generated_at',
                 'first_seen', 'last_seen', 'analyzer_version', 'catalogue_version',
                 'rule_catalogue_version', 'status', 'statuses', 'transform',
                 'route', 'injection_points', 'category_counts', 'effective_category_counts'}
    san = _sanitizer()
    uris, clean, site, uri = san.uris, san.clean, san.site, san.uri

    def collect(value, key=None):
        if key in protected:
            return
        if isinstance(value, dict):
            target = value.get('target')
            if isinstance(target, dict) and len(target.get('uri_path') or '') >= 2:
                uris.add(target['uri_path'])
            for k, v in value.items():
                collect(v, k)
        elif isinstance(value, list):
            for v in value:
                collect(v, key)
    collect(report)
    cache = {}

    def walk(value, fn, key=None):
        if key in protected:
            return value
        if isinstance(value, dict):
            result = {k: walk(v, fn, k) for k, v in value.items()}
            target = value.get('target')
            if fn is clean and isinstance(target, dict):
                if target.get('site'):
                    result['target']['site'] = site(target['site'])
                if target.get('uri_path') in uris:
                    result['target']['uri_path'] = uri(target['uri_path'])
            return result
        if isinstance(value, list):
            return [walk(v, fn, key) for v in value]
        if isinstance(value, str):
            if value not in cache:
                cache[value] = fn(value)
            return cache[value]
        return value
    result = walk(report, clean)
    # Single-label host names (UNC servers, bare site names) are replaced as whole words everywhere.
    names = san.names_pass()
    if names:
        cache = {}
        result = walk(result, names)
    print('[Sanitize] table={} entries'.format(len(san.table)), file=sys.stderr, flush=True)
    return result, san.table, san.counts


INPUT_FIELDS = ('site', 'uri_path', 'uri_query', 'src', 'count', 'et', 'lt', 'status', 'action')


def load_assessor():
    spec = importlib.util.spec_from_file_location('payload_assessor', Path(__file__).with_name('payload_assessor.py'))
    assessor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assessor)
    return assessor


def _inflate_b64(text, limit=1 << 20):
    """Decode a Base64 value holding compressed UTF-8 text (raw DEFLATE as in SAML redirect binding, zlib or
    gzip). Returns (text, wbits, urlsafe, padded) or None."""
    if len(text) < 16 or not re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}', text):
        return None
    urlsafe = '-' in text or '_' in text
    try:
        raw = _base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_' if urlsafe else None, validate=True)
    except (ValueError, binascii.Error):
        return None
    for wbits in (-15, 15, 31):
        inflater = _zlib.decompressobj(wbits)
        try:
            data = inflater.decompress(raw, limit)
        except _zlib.error:
            continue
        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            continue
        try:
            plain = data.decode('utf-8')
        except UnicodeDecodeError:
            return None
        return (plain, wbits, urlsafe, text.endswith('=')) if plain.isprintable() or '\n' in plain else None
    return None


def _deflate_b64(plain, wbits, urlsafe, padded):
    packer = _zlib.compressobj(9, _zlib.DEFLATED, wbits)
    raw = packer.compress(plain.encode('utf-8')) + packer.flush()
    encoded = (_base64.urlsafe_b64encode if urlsafe else _base64.b64encode)(raw).decode('ascii')
    return encoded if padded else encoded.rstrip('=')


def sanitize_input(records, assessor, decode_depth=4):
    """Pseudonymise raw web-request export records (the pipeline input) for sharing.

    RECORDS is a list of parsed JSONL lines (None for blank lines). Only the fields the assessor reads are
    kept. Query names/values are URL-decoded, rewritten and re-encoded; whole-value Base64 layers (the ones
    the assessor decodes) are decoded, rewritten and re-encoded too. Returns (records, table, counts,
    residual_lines): lines whose decoded assessor nodes still contain a replaceable entity.
    """
    from urllib.parse import unquote, unquote_plus
    san = _sanitizer()
    results = []
    for record in records:
        result = record.get('result', record) if isinstance(record, dict) else None
        results.append(result if isinstance(result, dict) else None)
    for result in results:
        if result and isinstance(result.get('uri_path'), str) and len(result['uri_path']) >= 2:
            san.uris.add(result['uri_path'])

    def deep(text, spans, depth=0):
        """Replacement spans of TEXT; a whole-value Base64 layer is decoded, rewritten and re-encoded."""
        if depth < decode_depth:
            decoded = assessor.b64_text(text)
            if decoded is not None and decoded != text:
                new = _apply_spans(decoded, deep(decoded, spans, depth + 1))
                if new == decoded:
                    return []
                urlsafe = '-' in text or '_' in text
                encoded = (_base64.urlsafe_b64encode if urlsafe else _base64.b64encode)(new.encode('utf-8')).decode('ascii')
                return [(0, len(text), encoded if text.endswith('=') else encoded.rstrip('='))]
            packed = _inflate_b64(text)
            if packed is not None:
                new = _apply_spans(packed[0], deep(packed[0], spans, depth + 1))
                return [] if new == packed[0] else [(0, len(text), _deflate_b64(new, *packed[1:]))]
        return spans(text)

    cache = {}

    def piece(raw, spans):
        if not raw:
            return raw
        if (raw, spans) not in cache:
            # Query semantics: '+' is a space. The assessor also tries Base64 on the plain unquoted form.
            found = _encoded_spans(raw, lambda d: deep(d, spans), plus=True)
            alt = unquote(raw)
            if not found and alt != unquote_plus(raw) and assessor.b64_text(alt) is not None:
                found = _encoded_spans(raw, lambda d: deep(d, spans))
            cache[raw, spans] = _apply_spans(raw, found)
        return cache[raw, spans]

    def query(value, fn):
        if not isinstance(value, str):
            return value
        mark = '?' if value.startswith('?') else ''
        parts = []
        for fragment in value[len(mark):].split('&'):
            name, eq, rest = fragment.partition('=')
            parts.append(piece(name, fn) + eq + piece(rest, fn))
        return mark + '&'.join(parts)

    def each(value, fn):
        return [fn(v) for v in value] if isinstance(value, list) else fn(value)

    def text_only(fn):
        return lambda v: fn(v) if isinstance(v, str) else v

    out = []
    for result in results:
        if result is None:
            out.append(None)
            continue
        rec = {k: result[k] for k in INPUT_FIELDS if k in result}
        if isinstance(rec.get('site'), str) and rec['site']:
            rec['site'] = san.site(rec['site'])
        if hasattr(assessor, 'path_payload') and assessor.path_payload(rec.get('uri_path')):
            rec['uri_path'] = san.payload_path(rec['uri_path'])
        elif rec.get('uri_path') in san.uris:
            rec['uri_path'] = san.uri(rec['uri_path'])
        for key in ('src', 'action'):
            if key in rec:
                rec[key] = each(rec[key], text_only(san.clean))
        if 'uri_query' in rec:
            rec['uri_query'] = each(rec['uri_query'], lambda q: query(q, san.clean_spans))
        out.append(rec)
    names = san.names_pass()
    names_spans = san.names_spans()
    if names:
        for rec in out:
            if rec is None:
                continue
            for key in ('action',):
                if key in rec:
                    rec[key] = each(rec[key], text_only(names))
            if 'uri_query' in rec:
                rec['uri_query'] = each(rec['uri_query'], lambda q: query(q, names_spans))
    # Verification: every node the assessor decodes must already be clean (pseudonyms are fixed points).
    check = _sanitizer(fixed=set(san.table.values()))
    residual = []
    for line, rec in enumerate(out, 1):
        queries = (rec or {}).get('uri_query')
        values = [q for q in (queries if isinstance(queries, list) else [queries]) if isinstance(q, str)]
        nodes = [node['value'] for q in values for pair in assessor.query_pairs(q)
                 for node in assessor.inspect_parameter(pair, decode_depth)]
        path = (rec or {}).get('uri_path')
        if hasattr(assessor, 'path_payload') and assessor.path_payload(path):
            nodes.append(unquote(path))
        # The assessor does not inflate compressed Base64 layers; check those too.
        nodes += [p[0] for p in map(_inflate_b64, nodes) if p is not None]
        if any(check.clean(v) != v for v in nodes):
            residual.append(line)
    print('[Sanitize] table={} entries'.format(len(san.table)), file=sys.stderr, flush=True)
    return out, san.table, san.counts, residual


def sanitize_main(argv):
    parser = argparse.ArgumentParser(description='Pseudonymise an analyzer report (best-effort).')
    parser.add_argument('input', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    parser.add_argument('--only-series', action='store_true')
    parser.add_argument('--mapping', type=Path)
    parser.add_argument('--xor-key-hex')
    args = parser.parse_args(argv)
    paths = [p.resolve() for p in (args.input, args.output, args.mapping) if p is not None]
    if len(set(paths)) != len(paths):
        parser.error('Input, output and mapping paths must differ')
    if args.output.suffix.lower() not in ('.json', '.pax'):
        parser.error('Output must use .json or .pax')
    try:
        paxio.configure_key(args.xor_key_hex)
        with paxio.open_text_in(args.input) as stream:
            report = json.load(stream)
        sanitized, mapping, counts = sanitize_report(report, args.only_series)
        atomic_write_json(args.output, sanitized)
        if args.mapping:
            atomic_write_json(args.mapping, mapping)
        print('[Sanitize] ' + json.dumps(counts, sort_keys=True), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, 'ERROR: {}\n'.format(exc))
    return 0


def sanitize_input_main(argv):
    parser = argparse.ArgumentParser(description='Pseudonymise the raw JSONL web-request export (pipeline input) for sharing.')
    parser.add_argument('input', type=Path)
    parser.add_argument('-o', '--output', required=True, type=Path)
    parser.add_argument('--mapping', type=Path)
    parser.add_argument('--xor-key-hex')
    args = parser.parse_args(argv)
    paths = [p.resolve() for p in (args.input, args.output, args.mapping) if p is not None]
    if len(set(paths)) != len(paths):
        parser.error('Input, output and mapping paths must differ')
    try:
        paxio.configure_key(args.xor_key_hex)
        records = []
        with paxio.open_binary_in(args.input) as stream:
            for line, raw in enumerate(stream, 1):
                if not raw.strip():
                    records.append(None)
                    continue
                try:
                    records.append(json.loads(raw.decode('utf-8-sig')))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError('Invalid JSONL at line {}: {}'.format(line, exc)) from exc
        out, mapping, counts, residual = sanitize_input(records, load_assessor())
        print('[Write] {}'.format(args.output), file=sys.stderr, flush=True)
        with paxio.open_text_out(args.output) as stream:
            for rec in out:
                stream.write('' if rec is None else json.dumps(rec, ensure_ascii=False, separators=(',', ':')))
                stream.write('\n')
        if args.mapping:
            atomic_write_json(args.mapping, mapping)
        print('[Sanitize] records={} '.format(sum(r is not None for r in out)) + json.dumps(counts, sort_keys=True), file=sys.stderr)
        if residual:
            print('[Sanitize] WARNING: {} records still decode to a replaceable entity (lines {}{}); '
                  'review or remove them before sharing'.format(len(residual), ', '.join(map(str, residual[:20])),
                                                                ', ...' if len(residual) > 20 else ''), file=sys.stderr)
        else:
            print('[Sanitize] verification: no replaceable entity in any decoded query node', file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, 'ERROR: {}\n'.format(exc))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'sanitize':
        return sanitize_main(argv[1:])
    if argv and argv[0] == 'sanitize-input':
        return sanitize_input_main(argv[1:])
    pipeline = bool(argv and argv[0] == 'pipeline')
    if pipeline:
        argv.pop(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(_text(487), type=Path)
    parser.add_argument(_text(488), _text(489), type=Path, default=Path(_text(490)))
    parser.add_argument(_text(491), action=_text(492))
    parser.add_argument(_text(493))
    parser.add_argument('--determined-output', type=Path)
    parser.add_argument('--no-determined-output', action='store_true')
    if pipeline:
        parser.add_argument('--keep-resolutions', type=Path)
        parser.add_argument('--assessor-matched-only', action='store_true')
        parser.add_argument('--decode-depth', type=int, choices=range(1, 9), default=4)
    args = parser.parse_args(argv)
    (source, destination) = (args.input.resolve(), args.output.resolve())
    if pipeline and args.keep_resolutions is not None:
        args.keep_resolutions = args.keep_resolutions.resolve()
        if args.keep_resolutions in (source, destination):
            parser.error('Resolutions path must differ from input and output')
    suffixes = ''.join(destination.suffixes)
    determined = (args.determined_output or destination.with_name(destination.name[:-len(suffixes)] + '.determined' + suffixes if suffixes else destination.name + '.determined')).resolve()
    if not args.no_determined_output and determined in (source, destination, getattr(args, 'keep_resolutions', None)):
        parser.error('Determined output must differ from input, output and retained resolutions')
    if source == destination:
        parser.error(_text(494))
    try:
        paxio.configure_key(args.xor_key_hex)
        print(_text(495), file=sys.stderr, flush=True)
        (digest, container_digest) = (hashlib.sha256(), hashlib.sha256())
        with paxio.open_binary_in(source) as stream:
            for chunk in iter(lambda : stream.read(1 << 20), b''):
                digest.update(chunk)
        with source.open(_text(496)) as stream:
            for chunk in iter(lambda : stream.read(1 << 20), b''):
                container_digest.update(chunk)
        if pipeline:
            with pipeline_resolutions(source, destination, args.keep_resolutions, args.xor_key_hex, args.decode_depth, args.assessor_matched_only) as resolutions:
                report = build_report(load_resolutions(resolutions), str(source), digest.hexdigest(), args.exclude_not_attack)
        else:
            report = build_report(load_resolutions(source), str(source), digest.hexdigest(), args.exclude_not_attack)
        if container_digest.digest() != digest.digest():
            report[_text(474)][_text(497)] = container_digest.hexdigest()
        if not args.no_determined_output:
            filtered = determined_report(report)
            atomic_write_json(determined, filtered)
        atomic_write_json(destination, report)
        print(''.join([_text(498), format(report[_text(474)][_text(483)], ''), _text(499), format(report[_text(474)][_text(485)], ''), _text(500), format(report[_text(474)][_text(482)], ''), _text(501), format(destination, '')]), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, ''.join([_text(502), format(exc, ''), _text(54)]))
    return 0
if __name__ == _text(503):
    sys.exit(main())
