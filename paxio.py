"""Streaming text evidence containers. The keyed format is obfuscation only.

Its header is a four-byte identifier and a version byte. The remaining bytes
are a deterministic compressed stream transformed with a repeating key. This
provides no confidentiality or authenticity guarantee. Use approved storage.
"""
from __future__ import annotations
import argparse
import gzip
import io
import os
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

MAGIC = b'PAX1'
VERSION = 1
DEFAULT_KEY = bytes.fromhex('a62dc05b118fa40cb7d936e358ea7192f0483e67ab0591dc72c8f4e119b6503d')
_KEY = None


def configure_key(value=None):
    global _KEY
    value = value if value is not None else os.environ.get('PAX_KEY_HEX')
    if value is None:
        _KEY = DEFAULT_KEY
        return
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError('Key must be a hexadecimal string') from exc
    if not key or len(key) > 4096:
        raise ValueError('Key must contain between 1 and 4096 bytes')
    _KEY = key


def current_key():
    if _KEY is None:
        configure_key()
    return _KEY


class _Transform(io.RawIOBase):
    def __init__(self, raw, key):
        super().__init__()
        self.raw, self.key, self.offset = raw, key, 0

    def readable(self):
        return self.raw.readable()

    def writable(self):
        return self.raw.writable()

    def readinto(self, buffer):
        data = self.raw.read(len(buffer))
        if not data:
            return 0
        transformed = self._apply(data)
        buffer[:len(transformed)] = transformed
        return len(transformed)

    def write(self, data):
        transformed = self._apply(bytes(data))
        self.raw.write(transformed)
        return len(data)

    def _apply(self, data):
        key, offset = self.key, self.offset
        result = bytes(value ^ key[(offset + index) % len(key)] for index, value in enumerate(data))
        self.offset += len(data)
        return result

    def flush(self):
        if not self.raw.closed:
            self.raw.flush()


def logical_suffix(path):
    name = Path(path).name.lower()
    if name.endswith(('.pax', '.gz')):
        name = name.rsplit('.', 1)[0]
    return Path(name).suffix


@contextmanager
def open_binary_in(path):
    path = Path(path)
    with path.open('rb') as raw:
        if path.suffix.lower() == '.pax':
            if raw.read(4) != MAGIC or raw.read(1) != bytes([VERSION]):
                raise ValueError('Unsupported evidence container header')
            transformed = _Transform(raw, current_key())
            with gzip.GzipFile(fileobj=transformed, mode='rb') as stream:
                yield stream
        elif path.suffix.lower() == '.gz':
            with gzip.GzipFile(fileobj=raw, mode='rb') as stream:
                yield stream
        else:
            yield raw


@contextmanager
def open_text_in(path):
    with open_binary_in(path) as binary:
        text = io.TextIOWrapper(binary, encoding='utf-8-sig', newline=None)
        try:
            yield text
        finally:
            text.detach()


@contextmanager
def open_binary_out(path):
    """Atomically replace path; every temporary byte has the final encoding."""
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=path.parent)
    raw = os.fdopen(fd, 'wb')
    compressed = None
    try:
        target = raw
        if path.suffix.lower() in ('.gz', '.pax'):
            if path.suffix.lower() == '.pax':
                raw.write(MAGIC + bytes([VERSION]))
                target = _Transform(raw, current_key())
            compressed = gzip.GzipFile(fileobj=target, mode='wb', filename='', mtime=0)
            target = compressed
        yield target
        if compressed is not None:
            compressed.close()
            compressed = None
        raw.flush()
        os.fsync(raw.fileno())
        raw.close()
        os.replace(temporary, path)
    finally:
        try:
            if compressed is not None:
                compressed.close()
        finally:
            raw.close()
            if os.path.exists(temporary):
                os.unlink(temporary)


@contextmanager
def open_text_out(path):
    with open_binary_out(path) as binary:
        text = io.TextIOWrapper(binary, encoding='utf-8', newline='\n')
        try:
            yield text
            text.flush()
        finally:
            text.detach()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('pack', 'unpack', 'cat'))
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--xor-key-hex')
    args = parser.parse_args(argv)
    try:
        configure_key(args.xor_key_hex)
        if args.operation == 'cat':
            if args.output is not None:
                parser.error('cat writes only to standard output')
            with open_text_in(args.input) as source:
                for block in iter(lambda: source.read(65536), ''):
                    sys.stdout.write(block)
            return 0
        if args.output is None:
            parser.error('An output path is required')
        if args.input.resolve() == args.output.resolve():
            parser.error('Input and output must differ')
        if args.operation == 'pack' and args.output.suffix.lower() not in ('.gz', '.pax'):
            parser.error('pack output must use .gz or .pax')
        if args.operation == 'unpack' and args.output.suffix.lower() in ('.gz', '.pax'):
            parser.error('unpack output must be plain text')
        with open_binary_in(args.input) as source, open_binary_out(args.output) as destination:
            for block in iter(lambda: source.read(65536), b''):
                destination.write(block)
    except (OSError, ValueError, EOFError, UnicodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
