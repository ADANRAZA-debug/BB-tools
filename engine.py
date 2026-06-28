"""
engine.py — Core secret detection engine.
Runs deobfuscation, applies all 150+ patterns, filters false positives,
scores confidence, and deduplicates — including cross-pattern dedup so a
single secret matched by multiple overlapping patterns is reported once
under its most specific/highest-confidence label.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from patterns import ALL_PATTERNS, GENERIC_PATTERN_NAMES, SEVERITY_RANK
from entropy import is_false_positive, confidence_score
from deobfuscator import deobfuscate


@dataclass
class Finding:
    domain: str
    pattern_name: str
    value_masked: str
    value_raw: str           # full unmasked value — internal/report use only
    source_url: str
    source_type: str         # HTML, JS, Config, Git, etc
    severity: str
    confidence: float
    context: str = ""
    line_number: int = 0


def _mask(value: str) -> str:
    if len(value) > 14:
        return value[:8] + "..." + value[-4:]
    return value[:4] + "..." if len(value) > 4 else value


def _line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(text: str, source_url: str, source_type: str, domain: str,
              deobfuscate_input: bool = True) -> list:
    """
    Run full pattern set against `text` and return list of Finding objects,
    one per unique secret value (cross-pattern deduplicated).
    """
    # value -> best Finding seen so far for that value
    by_value: dict = {}

    targets = [(text, False)]
    if deobfuscate_input:
        processed = deobfuscate(text)
        if processed != text:
            targets.append((processed, True))

    for scan_variant, was_deobfuscated in targets:
        for pattern_name, (regex, severity, group_idx) in ALL_PATTERNS.items():
            is_generic = pattern_name in GENERIC_PATTERN_NAMES
            is_branded = not is_generic

            for match in regex.finditer(scan_variant):
                raw_match = match.group(0)
                value = match.group(group_idx) if group_idx > 0 else raw_match
                if value is None:
                    continue

                if is_generic and is_false_positive(value):
                    continue

                conf = confidence_score(value, pattern_name, is_branded)

                # Cross-pattern dedup key: same domain + value (first 40 chars)
                vkey = (domain, value[:40])

                start = max(0, match.start() - 100)
                end   = min(len(scan_variant), match.end() + 100)
                ctx   = scan_variant[start:end].replace("\n", " ").strip()
                tag   = " [deobfuscated]" if was_deobfuscated else ""

                candidate = Finding(
                    domain=domain,
                    pattern_name=pattern_name + tag,
                    value_masked=_mask(value),
                    value_raw=value,
                    source_url=source_url,
                    source_type=source_type,
                    severity=severity,
                    confidence=conf,
                    context=ctx[:300],
                    line_number=_line_number(scan_variant, match.start()),
                )

                existing = by_value.get(vkey)
                if existing is None:
                    by_value[vkey] = candidate
                else:
                    # Prefer: branded over generic, then higher confidence,
                    # then higher severity (lower rank number = more severe)
                    existing_is_branded = existing.pattern_name.split(" [")[0] not in GENERIC_PATTERN_NAMES
                    if is_branded and not existing_is_branded:
                        by_value[vkey] = candidate
                    elif is_branded == existing_is_branded:
                        existing_rank = SEVERITY_RANK.get(existing.severity, 9)
                        new_rank = SEVERITY_RANK.get(severity, 9)
                        if new_rank < existing_rank or (
                            new_rank == existing_rank and conf > existing.confidence
                        ):
                            by_value[vkey] = candidate

    return list(by_value.values())


def sort_findings(findings: list) -> list:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 9), -f.confidence),
    )
