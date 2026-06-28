"""
reporter.py — Output findings to JSON, CSV, and plain-text formats.
"""

import json
import csv
from pathlib import Path
from datetime import datetime


def generate_reports(all_results: list, output_dir: Path, timestamp: str,
                     show_raw: bool = False) -> dict:
    """
    all_results: list of DomainResult objects (from scraper.py)
    Returns dict of {format: path}
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {}

    all_findings = []
    for r in all_results:
        all_findings.extend(r.findings)

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = output_dir / f"scan_{timestamp}.json"
    findings_json = []
    for f in all_findings:
        entry = {
            "domain": f.domain,
            "pattern": f.pattern_name,
            "severity": f.severity,
            "confidence": f.confidence,
            "value_masked": f.value_masked,
            "source_type": f.source_type,
            "source_url": f.source_url,
            "line_number": f.line_number,
            "context": f.context,
        }
        if show_raw:
            entry["value_raw"] = f.value_raw
        findings_json.append(entry)

    summary = {
        "scan_time": timestamp,
        "domains_total": len(all_results),
        "domains_ok": sum(1 for r in all_results if r.status == "ok"),
        "domains_error": sum(1 for r in all_results if r.status == "error"),
        "total_paths_scanned": sum(r.paths_scanned for r in all_results),
        "total_js_files_scanned": sum(r.js_files_scanned for r in all_results),
        "findings_total": len(all_findings),
        "by_severity": {
            "CRITICAL": sum(1 for f in all_findings if f.severity == "CRITICAL"),
            "HIGH":     sum(1 for f in all_findings if f.severity == "HIGH"),
            "MEDIUM":   sum(1 for f in all_findings if f.severity == "MEDIUM"),
            "LOW":      sum(1 for f in all_findings if f.severity == "LOW"),
        },
    }

    with open(json_path, "w") as fh:
        json.dump({"summary": summary, "findings": findings_json}, fh, indent=2)
    paths["json"] = json_path

    # ── CSV ───────────────────────────────────────────────────────────────────
    csv_path = output_dir / f"scan_{timestamp}.csv"
    fields = ["severity", "confidence", "pattern", "domain", "value_masked",
              "source_type", "source_url", "line_number"]
    if show_raw:
        fields.append("value_raw")

    with open(csv_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for f in all_findings:
            row = {
                "severity": f.severity, "confidence": f.confidence,
                "pattern": f.pattern_name, "domain": f.domain,
                "value_masked": f.value_masked, "source_type": f.source_type,
                "source_url": f.source_url, "line_number": f.line_number,
            }
            if show_raw:
                row["value_raw"] = f.value_raw
            writer.writerow(row)
    paths["csv"] = csv_path

    # ── Plain text (quick grep-able) ─────────────────────────────────────────
    txt_path = output_dir / f"scan_{timestamp}.txt"
    with open(txt_path, "w") as fh:
        for f in all_findings:
            val = f.value_raw if show_raw else f.value_masked
            fh.write(f"[{f.severity}] {f.pattern_name} | {f.domain} | {val} | {f.source_url}\n")
    paths["txt"] = txt_path

    return paths
