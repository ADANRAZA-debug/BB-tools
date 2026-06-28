"""
entropy.py — Shannon entropy scoring and false-positive filtering for
generic (non-branded) secret patterns.

Branded patterns (sk_live_, AIza, ghp_, etc) skip this filter entirely —
their fixed prefix already gives near-zero false-positive rate.
Generic patterns (KEY="value") run through this gate before being reported.
"""

import re
import math
import collections


def shannon_entropy(s: str) -> float:
    if not s or len(s) < 4:
        return 0.0
    freq = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ── Known-safe literal values ────────────────────────────────────────────────

_FP_VALUES = {
    "staging", "production", "development", "localhost", "true", "false",
    "undefined", "null", "none", "example", "placeholder", "your_key_here",
    "changeme", "xxxxxxxxxxxxxxxx", "0000000000000000", "insert_here",
    "your-api-key", "your_api_key", "api_key_here", "replace_me",
    "dummy", "test", "sample", "default", "enabled", "disabled",
}

_FP_PREFIX = re.compile(
    r'^(https?://|www\.|localhost|127\.|0\.0\.0\.0|example\.(com|org|net)|'
    r'your[_\-]|xxx+|000+|test[_\-]?key|dummy|placeholder|changeme|'
    r'insert[_\-]|replace[_\-]|<|>|\$\{|\#\{)',
    re.IGNORECASE,
)

_GA_TRACKING   = re.compile(r'^UA-\d+-\d+$')
_GTM_ID        = re.compile(r'^GTM-[A-Z0-9]{4,8}$')
_SEMVER        = re.compile(r'^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?$')
_HEX_COLOR     = re.compile(r'^[0-9a-f]{6}$', re.IGNORECASE)
_DATE_LIKE     = re.compile(r'^\d{4}-\d{2}-\d{2}')
_UUID_BUT_PLAIN= re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# JS variable / property reference  e.g. g.HEAD_REQUEST_KEY, obj.method
_JS_VAR_REF  = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z]')
# camelCase identifier sequence (likely a JS property name, not a secret)
_CAMEL_WORDS = re.compile(r'[a-z]{3,}[A-Z][a-z]{3,}')
# kebab-case config string  e.g. mode-watcher-mode
_KEBAB_CFG   = re.compile(r'^[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*){2,}$')

_KNOWN_JS_KEYWORDS = {
    "spaceseparated", "commaseparated", "boolean", "string", "number",
    "object", "null", "undefined", "true", "false", "function",
    "prototype", "constructor", "symbol", "array", "promise",
}


def is_false_positive(value: str, key_name: str = "") -> bool:
    """
    Returns True if `value` should be discarded as a non-secret.
    Used ONLY for generic structural patterns (UPPER_SNAKE / assignment) —
    branded patterns with fixed prefixes never call this.
    """
    v = value.strip().strip('"\'')
    vl = v.lower()

    if vl in _FP_VALUES or vl in _KNOWN_JS_KEYWORDS:
        return True
    if _FP_PREFIX.search(v):
        return True
    if _GA_TRACKING.match(v) or _GTM_ID.match(v):
        return True
    if _SEMVER.match(v) or _HEX_COLOR.match(v) or _DATE_LIKE.match(v):
        return True

    # JS variable/property reference — e.g. g.HEAD_REQUEST_KEY
    if _JS_VAR_REF.match(v):
        return True
    # Starts uppercase + contains dot → JS class/method reference
    if v and v[0].isupper() and "." in v:
        return True
    # Function call or object/array literal
    if "(" in v or "{" in v or "[" in v:
        return True
    # camelCase identifier at low entropy → JS property name, not a secret
    if _CAMEL_WORDS.search(v) and shannon_entropy(v) < 4.0:
        return True
    # kebab-case config string
    if _KEBAB_CFG.match(v):
        return True
    # A bare UUID with no surrounding context is usually a record ID, not a secret
    if _UUID_BUT_PLAIN.match(v):
        return True

    # ── Entropy gates ──────────────────────────────────────────────────────
    ent = shannon_entropy(v)
    if ent < 2.8:
        return True
    # Low character variety relative to length → padding/placeholder
    if len(set(v)) < 5 and len(v) < 30:
        return True
    # Looks like a sentence
    if " " in v and len(v.split()) > 3:
        return True
    # Repeating short pattern (aaaa1111aaaa1111...)
    if len(v) >= 16:
        half = len(v) // 2
        if v[:half] == v[half:half*2]:
            return True

    return False


def confidence_score(value: str, pattern_name: str, is_branded: bool) -> float:
    """
    0.0–1.0 confidence that this is a real secret.
    Branded patterns start high; generic patterns are entropy-weighted.
    """
    if is_branded:
        return 0.95

    ent = shannon_entropy(value)
    # Normalize entropy (typical secret entropy range ~3.0-5.5)
    base = min(1.0, max(0.0, (ent - 2.5) / 3.0))

    # Bonus for mixed character classes (upper+lower+digit+symbol = likely real secret)
    classes = sum([
        bool(re.search(r'[A-Z]', value)),
        bool(re.search(r'[a-z]', value)),
        bool(re.search(r'[0-9]', value)),
        bool(re.search(r'[^A-Za-z0-9]', value)),
    ])
    base += classes * 0.05

    return round(min(1.0, base), 2)
