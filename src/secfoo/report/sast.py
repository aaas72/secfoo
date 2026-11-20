"""Extracts SAST-report-specific structured data from a report's raw
Markdown: the Findings Register (the actual findings table), and the
Detailed Findings block per finding (Description/Recommendation). Mirrors
`report/sca.py`'s extraction idiom exactly. Best-effort only -- a report
that doesn't carry these just yields an empty list/dict rather than
raising, so the dashboard degrades gracefully instead of erroring.

Also owns the per-run finding fingerprint (`fingerprint_for_row`), the one
piece of this whole feature genuinely new to this app: every other
dashboard in secfoo is recomputed fresh from report text on every request,
with zero persistent per-finding identity. Real open/closed tracking needs
a stable identity for "the same bug" across two separate runs, which this
report's own `Fn` IDs cannot provide -- they restart at F1 every run.

The fingerprint is skill id + CWE + normalized file path + a hash of the
source *code region* around the reported line (when the scan target is
available on disk). It is deliberately NOT the finding's title,
description, or raw line number:

- Title/description are prose the model regenerates each run; keying on them
  would treat paraphrase as "fixed + new finding."
- Line number alone is unstable when unrelated edits shift line numbers.
- When `workdir` is passed (local `secfoo run`), `code_region.hash_code_region`
  hashes a small normalized window of actual source at the reported line so
  two distinct issues in the same file stay separate even with the same CWE.
- When `workdir` is unavailable (e.g. cloud ingest with report only), the
  fingerprint falls back to CWE + path plus the same-run line-bucket collision
  guard documented below.

Known failure modes: CWE reclassification or file rename still look like
close+reopen; a fix that changes the hashed snippet closes correctly; cloud-
only ingest without the repo on disk cannot compute a region hash.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import NamedTuple

from secfoo.report.code_region import hash_code_region
from secfoo.report.markdown import detail_blocks, example_finding_ids, prose_source
from secfoo.report.markdown import section as _extract_section

SKILL_ID = "sast"

# Findings Register: | ID | Finding | Severity | CWE | OWASP | CVSS Vector |
# Location | Verdict |. Anchored on an "Fn" ID so header/separator rows
# never match.
_FINDINGS_REGISTER_ROW_RE = re.compile(
    r"^\|\s*(?P<id>F\d+)\s*\|(?P<title>[^|]*)\|(?P<severity>[^|]*)\|(?P<cwe>[^|]*)\|"
    r"(?P<owasp>[^|]*)\|(?P<cvss_vector>[^|]*)\|(?P<location>[^|]*)\|(?P<verdict>[^|]*)\|\s*$",
    re.MULTILINE,
)

# Detailed Findings heading: "### [SEVERITY] F1: Finding title"
_DETAIL_HEADING_RE = re.compile(r"^###\s*\[[A-Za-z]+\]\s*(?P<id>F\d+):", re.MULTILINE)

_DESCRIPTION_FIELD_RE = re.compile(r"\*\*Description:\*\*\s*([^\n]+)")
_RECOMMENDATION_FIELD_RE = re.compile(r"\*\*Recommendation:\*\*\s*([^\n]+)")
# Code-free one-line description of the vulnerable construct, stored on
# the structured findings tables and emitted by `secfoo findings export`.
# It is the one per-finding field written to be comparable across repos
# (no paths, identifiers, or code). Absent from reports that predate this
# contract field.
_CONSTRUCT_FIELD_RE = re.compile(r"\*\*Construct:\*\*\s*([^\n]+)")

# "`app/db.py:42`" -> ("app/db.py", "42"); the line group is optional since
# a location without one ("`app/db.py`") should still parse.
_LOCATION_RE = re.compile(r"`?(?P<file>[^:`]+?)(?::(?P<line>\d+))?`?\s*$")


def extract_findings_register_rows(report_markdown: str) -> list[dict[str, str]]:
    """One dict per row of the SAST contract's Findings Register table --
    id/title/severity/cwe/owasp/cvss_vector/location/verdict, all stripped
    strings. Reports from other skills, or predating this contract
    version (no CVSS Vector column), simply yield an empty list -- this
    module never falls back to guessing a vector for an older report.
    """
    section = prose_source(_extract_section(report_markdown, "Findings Register"))
    rows = []
    for match in _FINDINGS_REGISTER_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    # Keep legacy register rows without narratives, but never persist an
    # identifier whose only detail heading belongs to a quoted/code example.
    examples = example_finding_ids(report_markdown)
    real_ids = {key for key, _ in _iter_detail_blocks(report_markdown)}
    rows = [row for row in rows if row["id"] not in examples or row["id"] in real_ids]
    return rows


def _iter_detail_blocks(report_markdown: str) -> list[tuple[str, str]]:
    """(Fn, block_text) for each Detailed Findings entry -- the text
    between one `### [SEVERITY] Fn:` heading and the next.
    """
    section = _extract_section(report_markdown, "Detailed Findings")
    return [(key, prose_source(block)) for key, block in detail_blocks(section, _DETAIL_HEADING_RE)]


def extract_description_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Description:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _DESCRIPTION_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def extract_recommendation_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Recommendation:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _RECOMMENDATION_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


def extract_construct_by_id(report_markdown: str) -> dict[str, str]:
    """Fn -> the report's own `**Construct:**` text."""
    result: dict[str, str] = {}
    for finding_id, block in _iter_detail_blocks(report_markdown):
        match = _CONSTRUCT_FIELD_RE.search(block)
        if match:
            result[finding_id] = match.group(1).strip()
    return result


class Site(NamedTuple):
    """One place a finding points at: a file and an optional line range."""

    file: str
    start_line: str | None = None
    end_line: str | None = None


# One site: an optional Windows drive, a path, then an optional `:start` or
# `:start-end`. A bare `:61` / `61` / `61-70` (no path) continues the
# previous site's file, as in "app/data/user-dao.js:25, :61".
_DRIVE = r"(?:[A-Za-z]:[\\/])?"
_SITE_RE = re.compile(r"^(?P<file>" + _DRIVE + r"[^:]*?)(?::(?P<start>\d+)(?:\s*[-–]\s*(?P<end>\d+))?)?$")
_LINE_ONLY_RE = re.compile(r"^:?(?P<start>\d+)(?:\s*[-–]\s*(?P<end>\d+))?$")


def parse_locations(location: str) -> list[Site]:
    """Every site in a Findings Register location cell.

    Agents write ranges and multi-site locations often:
    "config/env/all.js:8-9", "server.js:78-102, app/routes/session.js:116",
    "app/data/user-dao.js:25, :61", "`server.js:135-137`, `layout.html:75`".
    Sites are separated by commas or semicolons; backticks are Markdown
    code-span syntax, never part of a path. Text that holds no usable
    site degrades to one site with the whole cell as the file, as before.
    """
    stripped = location.strip().replace("`", "")
    sites: list[Site] = []
    for token in (part.strip() for part in re.split(r"[,;]", stripped)):
        if not token:
            continue
        line_only = _LINE_ONLY_RE.match(token)
        if line_only and sites:
            sites.append(Site(sites[-1].file, line_only["start"], line_only["end"]))
            continue
        match = _SITE_RE.match(token)
        if match and match["file"].strip():
            start, end = match["start"], match["end"]
            if start is not None and end is not None and int(end) < int(start):
                end = None  # "40-12" is not a range a model meant; keep the start line
            sites.append(Site(match["file"].strip(), start, end if end != start else None))
    return sites or [Site(stripped)]


def parse_location(location: str) -> tuple[str, str | None]:
    """"`app/db.py:42`" -> ("app/db.py", "42") -- the first site of
    parse_locations(), which is what location_file/location_line and the
    fingerprint use. A cell with no line number keeps (file, None).
    """
    first = parse_locations(location)[0]
    return first.file, first.start_line


def _legacy_parse_location(location: str) -> tuple[str, str | None]:
    """The single-site parser before #112: anything but `file:line` became
    the whole cell as the file. Only used to find open rows stored under
    that key so they can be re-keyed instead of closed and re-opened."""
    stripped = location.strip()
    match = _LOCATION_RE.match(stripped)
    if not match:
        return stripped.replace("`", ""), None
    return match.group("file").strip(), match.group("line")


def sites_as_records(sites: list[Site]) -> list[dict[str, str | None]]:
    """JSON-ready form stored in the `locations` column and exported."""
    return [{"file": s.file, "start_line": s.start_line, "end_line": s.end_line} for s in sites]


def _normalize_path(file_path: str) -> str:
    return file_path.strip().lstrip("./").lower()


def _fingerprint(cwe: str, file_path: str, *, line_bucket: str | None, region_hash: str | None) -> str:
    parts = [SKILL_ID, cwe.strip().lower(), _normalize_path(file_path)]
    if region_hash:
        parts.append(region_hash)
    elif line_bucket is not None:
        parts.append(f"linebucket:{line_bucket}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint_for_row(
    row: dict[str, str],
    *,
    line_bucket: str | None = None,
    region_hash: str | None = None,
) -> str:
    """Stable cross-run identity from contract fields + optional source hash.
    A multi-site location is keyed on its first site only."""
    file_path, _line = parse_location(row["location"])
    return _fingerprint(row.get("cwe", ""), file_path, line_bucket=line_bucket, region_hash=region_hash)


def legacy_fingerprint_for_row(row: dict[str, str], *, line_bucket: str | None = None) -> str:
    """Identity before region hashes and before multi-site parsing (#112):
    CWE + the old single-site path [+ line bucket]. Used to rekey open rows
    on upgrade, so a range or multi-site location already stored under the
    whole cell as its "file" is moved to the new key instead of being
    closed and re-opened."""
    file_path, line = _legacy_parse_location(row["location"])
    return _fingerprint(
        row.get("cwe", ""), file_path, line_bucket=line_bucket if line is not None else None, region_hash=None
    )


def findings_with_fingerprints(
    report_markdown: str,
    *,
    workdir: Path | None = None,
) -> list[dict[str, str]]:
    """One dict per Findings Register row, joined with its Detailed
    Findings block (description/recommendation) and its fingerprint --
    computed with the per-run collision guard: only rows that share both
    CWE and file with at least one other row *in this same report* get a
    line-bucket appended to their fingerprint, so two real findings never
    silently collapse into one lifecycle entry. This is what both
    runner.py's post-run lifecycle hook and web/sast_dashboard.py consume,
    so the join logic lives in exactly one place.
    """
    rows = extract_findings_register_rows(report_markdown)
    descriptions = extract_description_by_id(report_markdown)
    recommendations = extract_recommendation_by_id(report_markdown)
    constructs = extract_construct_by_id(report_markdown)

    # Group indices by (cwe, file) to detect same-run collisions before
    # computing any fingerprint.
    groups: dict[tuple[str, str], list[int]] = {}
    parsed_sites: list[list[Site]] = []
    for row in rows:
        sites = parse_locations(row["location"])
        parsed_sites.append(sites)
        file_path = sites[0].file
        key = (row.get("cwe", "").strip().lower(), _normalize_path(file_path))
        groups.setdefault(key, []).append(len(parsed_sites) - 1)

    results = []
    for index, row in enumerate(rows):
        sites = parsed_sites[index]
        file_path, line = sites[0].file, sites[0].start_line
        key = (row.get("cwe", "").strip().lower(), _normalize_path(file_path))
        region_hash = None
        if workdir is not None and line is not None:
            region_hash = hash_code_region(workdir, file_path, line)

        line_bucket = None
        if region_hash is None and len(groups[key]) > 1 and line is not None:
            line_bucket = str(int(line) // 20)
        fingerprint = fingerprint_for_row(row, line_bucket=line_bucket, region_hash=region_hash)
        legacy_fingerprint = legacy_fingerprint_for_row(row, line_bucket=line_bucket)

        results.append(
            {
                **row,
                "location_file": file_path,
                "location_line": line,
                "locations": sites_as_records(sites),
                "code_region_hash": region_hash,
                "fingerprint": fingerprint,
                "legacy_fingerprint": legacy_fingerprint,
                "description": descriptions.get(row["id"], ""),
                "recommendation": recommendations.get(row["id"], ""),
                "construct": constructs.get(row["id"], ""),
            }
        )
    return results
