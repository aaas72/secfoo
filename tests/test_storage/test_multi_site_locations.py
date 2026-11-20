"""#112: range and multi-site locations are stored as every site, keyed on
the first, and an open row stored under the old whole-cell key survives the
upgrade instead of being closed and re-opened."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from secfoo.report.sast import findings_with_fingerprints, legacy_fingerprint_for_row
from secfoo.runner import update_sast_findings, update_secret_findings
from secfoo.storage.repository import RunRepository

SAMPLE = Path(__file__).resolve().parents[2] / "examples/sample-output/nodegoat"


def _run(repo: RunRepository, skill_id: str) -> tuple[int, int]:
    project_id = repo.upsert_project(identifier="/tmp/nodegoat", display_name="nodegoat", kind="local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=skill_id, skill_name=skill_id, agent_id="claude", confluence_urls=[]
    )
    return project_id, repo.get_run(run_uuid).id


def test_sast_findings_store_every_site(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _run(repo, "sast")
    update_sast_findings(
        repo, project_id=project_id, run_id=run_id, report_text=(SAMPLE / "sast-report.md").read_text()
    )
    by_ref = {f.current_ref: f for f in repo.list_sast_findings(status="open")}
    assert len(by_ref) == 12
    f12 = by_ref["F12"]
    assert (f12.location_file, f12.location_line) == ("server.js", "78")
    assert [site["file"] for site in json.loads(f12.locations)] == [
        "server.js", "app/routes/session.js", "app/routes/error.js",
    ]
    assert f12.site_labels == ["server.js:78-102", "app/routes/session.js:116", "app/routes/error.js:10-12"]
    assert by_ref["F7"].site_labels == ["app/data/user-dao.js:25", "app/data/user-dao.js:61"]
    repo.close()


def test_open_row_stored_under_the_whole_cell_is_rekeyed_not_reopened(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _run(repo, "sast")
    report = (SAMPLE / "sast-report.md").read_text()
    f6 = next(row for row in findings_with_fingerprints(report) if row["id"] == "F6")
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint=legacy_fingerprint_for_row(f6), current_ref="F6", title=f6["title"],
        severity="High", cwe="CWE-79", owasp=None, verdict=None,
        location_file="server.js:135-137, app/views/layout.html:75", location_line=None,
        cvss_vector=None, cvss_score=None, run_id=run_id,
    )
    first_seen = repo.list_sast_findings(status="open")[0].first_seen_at

    update_sast_findings(repo, project_id=project_id, run_id=run_id, report_text=report)

    rows = [f for f in repo.list_sast_findings() if f.current_ref == "F6"]
    assert len(rows) == 1
    assert rows[0].status == "open"
    assert rows[0].fingerprint == f6["fingerprint"]
    assert rows[0].location_file == "server.js"
    assert rows[0].first_seen_at == first_seen
    repo.close()


def test_secret_findings_store_every_site(tmp_path):
    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id, run_id = _run(repo, "secret-scanning")
    update_secret_findings(
        repo, project_id=project_id, run_id=run_id,
        report_text=(SAMPLE / "secret-scanning-report.md").read_text(),
    )
    multi = [f for f in repo.list_secret_findings(status="open") if len(f.site_labels) > 1]
    assert multi
    for finding in multi:
        assert finding.site_labels[0].startswith(finding.location_file)
        assert all("," not in label for label in finding.site_labels)
    repo.close()


def test_locations_column_is_added_to_an_existing_database(tmp_path):
    db_path = tmp_path / "db.sqlite"
    RunRepository(db_path=db_path).close()
    conn = sqlite3.connect(db_path)
    for table in ("sast_findings", "secret_findings"):
        conn.execute(f"ALTER TABLE {table} DROP COLUMN locations")
    conn.commit()
    conn.close()

    repo = RunRepository(db_path=db_path)
    for table in ("sast_findings", "secret_findings"):
        columns = {row["name"] for row in repo._conn.execute(f"PRAGMA table_info({table})")}
        assert "locations" in columns
    repo.close()
