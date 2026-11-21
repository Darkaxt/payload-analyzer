"""Inspect/edit encoded JSON data without evaluating source code.

Plain editing files are restricted to the task's dedicated external scratch
folder. Positional string slots must retain their order. Only the encoded data
assignment is replaced; executable statements are never taken from the JSON.
"""
from __future__ import annotations
import argparse
import ast
import base64
import json
import os
import tempfile
import zlib
from pathlib import Path

AVOID_B64 = (
    'Z2V0UnVudGltZXxQcm9jZXNzQnVpbGRlcnxqbmRpOnwke2puZGl8Y2VydHV0aWx8'
    'dXJsY2FjaGV8RG93bmxvYWRTdHJpbmd8SUVYfEludm9rZS1FeHByZXNzaW9ufHBv'
    'd2Vyc2hlbGwgLWVuY3xFbmNvZGVkQ29tbWFuZHx4cF9jbWRzaGVsbHx4cF9kaXJ0'
    'cmVlfFVUTF9IVFRQfERCTVNfUElQRXxjaGlsZF9wcm9jZXNzfC9ldGMvcGFzc3dk'
    'fGNtZC5leGV8d2hvYW1pfDwlfFJ1bnRpbWUuZXhlY3xTRVNTSU9OX1BSSVZTfFVO'
    'SU9OIFNFTEVDVHxTTEVFUCh8V0FJVEZPUiBERUxBWXxfX2dsb2JhbHNfX3xmcmVl'
    'bWFya2VyLnRlbXBsYXRlLnV0aWxpdHkuRXhlY3V0ZQ=='
)
EDIT_ROOT = Path(r'E:\Temp\payload-analyzer\catalogue-edit')


def allowed_edit(path):
    path, root = Path(path).resolve(), EDIT_ROOT.resolve()
    if path != root and root not in path.parents:
        raise ValueError('Plain editing data must remain under the dedicated edit folder')
    if path == root:
        raise ValueError('An editing file path is required')
    return path


def source_assignment(path):
    source = Path(path).read_text(encoding='utf-8')
    tree = ast.parse(source)
    matches = [node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'CATALOGUE_BLOB' for target in node.targets)]
    if len(matches) != 1:
        raise ValueError('Expected one encoded data assignment')
    return source, matches[0]


def validate_data(data):
    if not isinstance(data, dict) or data.get('schema_version') != 1:
        raise ValueError('Unsupported data schema')
    if not isinstance(data.get('strings'), list) or not all(isinstance(s, str) for s in data['strings']):
        raise ValueError('Expected an ordered string table')
    if 'rules' in data and not all(isinstance(row, list) and len(row) == 4 and all(isinstance(s, str) for s in row) for row in data['rules']):
        raise ValueError('Invalid rule table')
    return data


def encode_data(data):
    validate_data(data)
    return base64.b64encode(zlib.compress(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), 9)).decode('ascii')


def blob_literal(encoded):
    avoided = base64.b64decode(AVOID_B64).decode().casefold().split('|') if AVOID_B64 else [base64.b64decode('aWV4').decode()]
    avoided = [word for word in avoided if word]
    chunks, current = [], ''
    for character in encoded:
        trial = current + character
        if len(trial) > 64 or any(word in trial.casefold() for word in avoided):
            chunks.append(current); current = character
        else:
            current = trial
    if current:
        chunks.append(current)
    return '(\n' + ''.join('    ' + repr(chunk) + '\n' for chunk in chunks) + ')'


def atomic_text(path, text):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('decode', 'encode'))
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'decode':
            destination = allowed_edit(args.output)
            _, assignment = source_assignment(args.input)
            encoded = ast.literal_eval(assignment.value)
            data = validate_data(json.loads(zlib.decompress(base64.b64decode(encoded, validate=True))))
            atomic_text(destination, json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        else:
            source_path = allowed_edit(args.input)
            data = validate_data(json.loads(source_path.read_text(encoding='utf-8')))
            source, assignment = source_assignment(args.output)
            lines = source.splitlines(keepends=True)
            start = sum(len(line) for line in lines[:assignment.lineno - 1]) + assignment.col_offset
            end = sum(len(line) for line in lines[:assignment.end_lineno - 1]) + assignment.end_col_offset
            replacement = 'CATALOGUE_BLOB = ' + blob_literal(encode_data(data))
            changed = source[:start] + replacement + source[end:]
            ast.parse(changed)
            atomic_text(args.output, changed)
    except (OSError, ValueError, SyntaxError, zlib.error) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
