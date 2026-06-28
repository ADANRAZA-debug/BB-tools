"""
deobfuscator.py — Static deobfuscation for minified/obfuscated JS.

All transforms are pure regex + decode operations — nothing is executed/eval'd,
so this is safe to run on untrusted JS source.

Handles:
  - Hex escapes:        \\x41\\x49           → AI
  - Unicode escapes:    \\u0041\\u0049       → AI
  - String concat:      "AIza"+"SyD1"        → "AIzaSyD1"
  - atob() calls:       atob("QUl6YQ==")     → decoded plaintext
  - Bare base64:        _k="QUl6YQ=="        → decoded if high-entropy+printable
  - String.fromCharCode(65,73,...)            → decoded string
  - Webpack array KV:   n[0]="val",n[1]="KEY" → KEY:"val" (reassembled)
  - Octal escapes:      \\101\\111           → AI
"""

import re
import base64
from entropy import shannon_entropy


_KEY_NAME_RE = re.compile(
    r'^[A-Z][A-Z0-9_]{3,}'
    r'(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|CLIENT_ID|CLIENT_SECRET|'
    r'API_KEY|APP_ID|APP_KEY|AUTH|ACCESS|SID|PRIVATE_KEY|SITE_KEY)$'
)


def _decode_hex_escapes(text: str) -> str:
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)


def _decode_unicode_escapes(text: str) -> str:
    return re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)


def _decode_octal_escapes(text: str) -> str:
    # \101 = 'A' (octal). Only match 3-digit octal to avoid false matches on \1 backrefs.
    def _rep(m):
        try:
            code = int(m.group(1), 8)
            if 32 <= code < 127:
                return chr(code)
        except ValueError:
            pass
        return m.group(0)
    return re.sub(r'\\([0-3][0-7]{2})', _rep, text)


def _collapse_string_concat(text: str, max_iter: int = 20) -> str:
    """"AIza"+"SyD1"+"2345" → "AIzaSyD12345" (iterative, handles long chains)."""
    r = text
    for _ in range(max_iter):
        prev = r
        r = re.sub(r'"\s*\+\s*"', '', r)
        r = re.sub(r"'\s*\+\s*'", '', r)
        if r == prev:
            break
    return r


def _decode_atob_calls(text: str) -> str:
    def _rep(m: re.Match) -> str:
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            if decoded and all(32 <= ord(c) < 127 for c in decoded):
                return f'"{decoded}"'
        except Exception:
            pass
        return m.group(0)
    return re.sub(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']\s*\)', _rep, text)


def _decode_bare_base64(text: str) -> str:
    """Decode standalone quoted base64 strings if they decode to a plausible secret."""
    def _rep(m: re.Match) -> str:
        s = m.group(1)
        if not (re.search(r'[A-Z]', s) and re.search(r'[a-z]', s)):
            return m.group(0)
        try:
            decoded = base64.b64decode(s + "==").decode("utf-8", errors="replace")
            if (len(decoded) >= 16
                    and all(32 <= ord(c) < 127 for c in decoded)
                    and shannon_entropy(decoded) > 3.0):
                return f'"{decoded}"'
        except Exception:
            pass
        return m.group(0)
    return re.sub(r'"([A-Za-z0-9+/]{28,}={0,2})"', _rep, text)


def _decode_charcode(text: str) -> str:
    def _rep(m: re.Match) -> str:
        try:
            codes = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            if len(codes) < 10:
                return m.group(0)
            decoded = "".join(chr(c) for c in codes if 32 <= c < 127)
            if len(decoded) >= 10 and shannon_entropy(decoded) > 2.5:
                return f'"{decoded}"'
        except Exception:
            pass
        return m.group(0)
    return re.sub(r'String\.fromCharCode\(([0-9,\s]{15,})\)', _rep, text)


def _reassemble_array_kv(text: str) -> str:
    """
    Webpack/minifier array pattern:
        n[42]="<value>",n[43]="<KEY_NAME>"
    Appends KEY_NAME:"<value>" so downstream patterns can match it.
    """
    tokens = list(re.finditer(r'"([^"]{8,160})"', text))
    inserts = []
    for i in range(len(tokens) - 1):
        a_val = tokens[i].group(1)
        b_val = tokens[i + 1].group(1)
        if _KEY_NAME_RE.match(a_val) and shannon_entropy(b_val) > 3.2:
            inserts.append(f'{a_val}:"{b_val}"')
        elif _KEY_NAME_RE.match(b_val) and shannon_entropy(a_val) > 3.2:
            inserts.append(f'{b_val}:"{a_val}"')
    if inserts:
        text = text + "\n" + "\n".join(inserts)
    return text


def deobfuscate(text: str) -> str:
    """
    Run the full deobfuscation pipeline on JS/HTML source text.
    Returns processed text ready for pattern matching.
    Idempotent and safe — no eval, no code execution.
    """
    r = text
    r = _decode_hex_escapes(r)
    r = _decode_unicode_escapes(r)
    r = _decode_octal_escapes(r)
    r = _collapse_string_concat(r)
    r = _decode_atob_calls(r)
    r = _decode_bare_base64(r)
    r = _decode_charcode(r)
    r = _reassemble_array_kv(r)
    return r
