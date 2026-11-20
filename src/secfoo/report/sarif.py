"""Serialize exported structured findings as SARIF 2.1.0, without I/O."""

from __future__ import annotations

import json
import re
from pathlib import PureWindowsPath
from urllib.parse import quote

from secfoo.__about__ import __version__

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
# Scores represent secfoo's categorical severity, not calculated CVSS scores.
_SEVERITIES = {
    "critical": ("error", "9.0"),
    "high": ("error", "7.0"),
    "medium": ("warning", "4.0"),
    "low": ("note", "1.0"),
    "info": ("note", "0.0"),
    "informational": ("note", "0.0"),
}


def _line_number(value: object) -> int | None:
    # Stored legacy/model-authored lines are not guaranteed to be numeric --
    # or short: int() refuses more than 4300 digits (#121), and no source
    # file has a billion lines.
    line = str(value or "").strip()
    digits = line.lstrip("0")  # "0000000042" is line 42; the length cap is on the value
    if re.fullmatch(r"[0-9]+", line) and 1 <= len(digits) <= 9:
        return int(digits)
    return None


def _physical_location(file_path: object, start: object, end: object = None) -> dict | None:
    path = str(file_path or "").strip().replace("\\", "/")
    if not path:
        return None
    if PureWindowsPath(path).is_absolute():
        uri = PureWindowsPath(path).as_uri()
    elif path.startswith("/"):
        uri = "file://" + quote(path, safe="/")
    else:
        uri = quote(path, safe="/")
    physical = {"artifactLocation": {"uri": uri}}
    start_line = _line_number(start)
    if start_line is not None:
        physical["region"] = {"startLine": start_line}
        end_line = _line_number(end)
        if end_line is not None and end_line > start_line:
            physical["region"]["endLine"] = end_line
    return {"physicalLocation": physical}


def _sites(record: dict) -> list[dict]:
    """Every site a record names: its `locations` list (#112; stored as a
    JSON string, or already decoded), else the single location_file/line."""
    sites = record.get("locations")
    if isinstance(sites, str):
        try:
            sites = json.loads(sites)
        except ValueError:
            sites = None
    if isinstance(sites, list) and sites and all(isinstance(site, dict) for site in sites):
        return sites
    return [{"file": record.get("location_file"), "start_line": record.get("location_line")}]


def _location(record: dict) -> dict | None:
    """The record's first site -- the primary location."""
    locations = _locations(record)
    return locations[0] if locations else None


def _locations(record: dict) -> list[dict]:
    locations = []
    for site in _sites(record):
        location = _physical_location(site.get("file"), site.get("start_line"), site.get("end_line"))
        if location is not None and location not in locations:
            locations.append(location)
    return locations


def findings_to_sarif(records: list[dict], *, runtime_priority: bool = False) -> dict:
    """Build one run; group rules by skill, CWE and severity.

    Severity is part of the rule identity because GitHub reads security-severity
    from the rule, while findings with the same CWE can have different levels.
    Only explicit result fields are copied: internal IDs and secret evidence
    are not needed by code scanning.

    A record carrying "runtime" (#80) gets it as properties.secfoo.runtime,
    so PR annotations can say "reached in production via POST /upload";
    with runtime_priority, a finding reached in production is raised to
    level "error".
    """
    rules = []
    rule_indices = {}
    results = []
    for record in records:
        skill = record["skill_id"]
        severity = str(record.get("severity") or "").strip().lower()
        level, score = _SEVERITIES.get(severity, ("warning", None))
        severity_key = "info" if severity == "informational" else severity
        severity_key = severity_key if severity_key in _SEVERITIES else "unknown"
        cwes = sorted(set(re.findall(r"\bCWE-[1-9][0-9]*\b", str(record.get("cwe") or "").upper())))
        rule_id = "/".join([skill, *cwes, severity_key])
        if rule_id not in rule_indices:
            properties = {"tags": ["security", *[f"external/cwe/{cwe.lower()}" for cwe in cwes]]}
            if score is not None:
                properties["security-severity"] = score
            rule_indices[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f"{skill} finding ({', '.join(cwes) or 'unclassified'}, {severity_key})"},
                "defaultConfiguration": {"level": level},
                "properties": properties,
            })
        title = record.get("title") or record.get("issue") or record.get("secret_type") or f"{skill} finding"
        description = record.get("description") or record.get("construct")
        message = str(title) + (f"\n\n{description}" if description else "")
        runtime = record.get("runtime")
        if runtime and runtime.get("state") == "reached":
            routes = ", ".join(r["route"] for r in runtime.get("routes", [])[:3])
            message += f"\n\nReached in production via {routes}." if routes else "\n\nReached in production."
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": "error" if runtime_priority and runtime and runtime.get("state") == "reached" else level,
            "message": {"text": message},
        }
        if runtime:
            result["properties"] = {"secfoo": {"runtime": runtime}}
        locations = _locations(record)
        if locations:
            result["locations"] = locations
        results.append(result)
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secfoo",
                "version": __version__,
                "informationUri": "https://github.com/secfoo-com/secfoo",
                "rules": rules,
            }},
            "results": results,
        }],
    }
