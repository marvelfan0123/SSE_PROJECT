from db_utils import connect_sqlite, DB_PATH as SHARED_DB_PATH
"""Persistent container-image asset inventory used by VulnX discovery."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from pathlib import Path

DB_PATH = SHARED_DB_PATH
CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
ASSESSMENT_FACTORS = {
    "data_sensitivity": "Data sensitivity",
    "business_importance": "Business importance",
    "availability_impact": "Availability impact",
    "dependency_impact": "Dependency impact",
}
FACTOR_DESCRIPTIONS = {
    1: "Very limited impact",
    2: "Low impact",
    3: "Moderate impact",
    4: "High impact",
    5: "Severe / organization-wide impact",
}


@contextmanager
def _db():
    connection = connect_sqlite(DB_PATH)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def suggest_criticality(factor_scores):
    """Return an explainable suggested level from four 1–5 business-impact scores."""
    if not isinstance(factor_scores, dict) or set(ASSESSMENT_FACTORS) - set(factor_scores):
        raise ValueError("Complete all four business-impact assessment factors.")
    values = {}
    for key in ASSESSMENT_FACTORS:
        value = factor_scores[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value or not 1 <= int(value) <= 5:
            raise ValueError(f"{ASSESSMENT_FACTORS[key]} must be a whole number from 1 to 5.")
        values[key] = int(value)
    average = sum(values.values()) / len(values)
    if average < 2:
        level = "Low"
    elif average < 3:
        level = "Medium"
    elif average < 4:
        level = "High"
    else:
        level = "Critical"
    return {"factor_scores": values, "average_score": round(average, 2), "suggested_criticality": level}


def image_asset_from_report(scan_data, report_name=""):
    """Return a stable logical image asset from Trivy report metadata."""
    if not isinstance(scan_data, dict):
        return None
    metadata = scan_data.get("Metadata") or {}
    image_ref = str(
        scan_data.get("ArtifactName")
        or metadata.get("Reference")
        or ((metadata.get("RepoTags") or [None])[0])
        or report_name
        or "Unknown image"
    ).strip()
    if not image_ref or image_ref == "Unknown image":
        return None
    asset_id = "image:" + hashlib.sha256(image_ref.lower().encode("utf-8")).hexdigest()[:20]
    repo_digests = metadata.get("RepoDigests") or []
    return {
        "asset_id": asset_id,
        "asset_name": image_ref,
        "asset_type": "Container image",
        "image_id": str(metadata.get("ImageID") or ""),
        "image_digest": str(repo_digests[0] if repo_digests else ""),
        "last_seen_report": str(report_name or ""),
    }


def initialize_asset_table():
    with _db() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS asset_profiles (
            asset_id TEXT PRIMARY KEY,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL DEFAULT 'Container image',
            criticality TEXT NOT NULL DEFAULT 'Unassigned',
            environment TEXT NOT NULL DEFAULT 'Development',
            owner TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            image_id TEXT NOT NULL DEFAULT '',
            image_digest TEXT NOT NULL DEFAULT '',
            last_seen_report TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT '',
            factor_scores_json TEXT NOT NULL DEFAULT '{}',
            suggested_criticality TEXT NOT NULL DEFAULT '',
            assessment_average REAL,
            assessment_status TEXT NOT NULL DEFAULT 'Unassessed',
            confirmed_by TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}'
        )""")
        # Safe in-place migration for databases created by earlier VulnX versions.
        columns = {row[1] for row in connection.execute("PRAGMA table_info(asset_profiles)")}
        migrations = {
            "factor_scores_json": "TEXT NOT NULL DEFAULT '{}'",
            "suggested_criticality": "TEXT NOT NULL DEFAULT ''",
            "assessment_average": "REAL",
            "assessment_status": "TEXT NOT NULL DEFAULT 'Unassessed'",
            "confirmed_by": "TEXT NOT NULL DEFAULT ''",
            "evidence_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, declaration in migrations.items():
            if column not in columns:
                connection.execute(f"ALTER TABLE asset_profiles ADD COLUMN {column} {declaration}")
        # Earlier automatic defaults were Medium with no editor identity. They were
        # not assessed by a person, so explicitly mark only those defaults Unassigned.
        connection.execute("""UPDATE asset_profiles SET criticality='Unassigned',
            assessment_status='Unassessed'
            WHERE criticality='Medium' AND COALESCE(updated_by, '')='' 
              AND COALESCE(factor_scores_json, '{}')='{}'""")


def register_discovered_asset(asset):
    """Register/update image metadata without overwriting user-assigned context."""
    if not asset or not asset.get("asset_id"):
        return None
    initialize_asset_table()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db() as connection:
        connection.execute("""INSERT INTO asset_profiles
            (asset_id, asset_name, asset_type, criticality, environment, owner, notes,
             image_id, image_digest, last_seen_report, first_seen_at, updated_at, updated_by)
            VALUES (?, ?, ?, 'Unassigned', 'Development', '', '', ?, ?, ?, ?, ?, '')
            ON CONFLICT(asset_id) DO UPDATE SET
                asset_name=excluded.asset_name,
                image_id=CASE WHEN excluded.image_id != '' THEN excluded.image_id ELSE asset_profiles.image_id END,
                image_digest=CASE WHEN excluded.image_digest != '' THEN excluded.image_digest ELSE asset_profiles.image_digest END,
                last_seen_report=excluded.last_seen_report""",
            (asset["asset_id"], asset["asset_name"], asset.get("asset_type", "Container image"),
             asset.get("image_id", ""), asset.get("image_digest", ""), asset.get("last_seen_report", ""), now, now))
    return get_asset(asset["asset_id"])


def list_assets():
    initialize_asset_table()
    with _db() as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM asset_profiles ORDER BY asset_name COLLATE NOCASE").fetchall()
    assets = [dict(row) for row in rows]
    for asset in assets:
        try:
            asset["factor_scores"] = json.loads(asset.get("factor_scores_json") or "{}")
            asset["assessment_evidence"] = json.loads(asset.get("evidence_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            asset["factor_scores"] = {}
            asset["assessment_evidence"] = {}
    return assets


def get_asset(asset_id):
    initialize_asset_table()
    with _db() as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM asset_profiles WHERE asset_id=?", (asset_id,)).fetchone()
    if not row:
        return None
    asset = dict(row)
    try:
        asset["factor_scores"] = json.loads(asset.get("factor_scores_json") or "{}")
        asset["assessment_evidence"] = json.loads(asset.get("evidence_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        asset["factor_scores"] = {}
        asset["assessment_evidence"] = {}
    return asset


def update_asset_profile(asset_id, criticality, environment="Development", owner="", notes="", updated_by="",
                         factor_scores=None, suggested=None, average=None, assessment_status=None, evidence=None):
    if criticality not in (*CRITICALITY_LEVELS, "Unassigned"):
        raise ValueError("Choose a valid asset criticality level.")
    if environment not in {"Development", "Testing", "Staging", "Production"}:
        raise ValueError("Choose a valid environment.")
    if criticality != "Unassigned" and not factor_scores:
        # Backward compatibility for existing callers/tests that manually set a level.
        status = assessment_status or "Manually confirmed"
    else:
        status = assessment_status or ("Confirmed" if criticality != "Unassigned" else "Unassessed")
    normalized = None
    if factor_scores and set(ASSESSMENT_FACTORS).issubset(factor_scores):
        normalized = suggest_criticality(factor_scores)
    if normalized:
        suggested = normalized["suggested_criticality"]
        average = normalized["average_score"]
        factor_scores = normalized["factor_scores"]
    elif criticality != "Unassigned" and status == "Confirmed":
        raise ValueError("Complete the business-impact assessment before confirming a criticality.")
    initialize_asset_table()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db() as connection:
        cursor = connection.execute("""UPDATE asset_profiles SET
            criticality=?, environment=?, owner=?, notes=?, updated_at=?, updated_by=?,
            factor_scores_json=?, suggested_criticality=?, assessment_average=?,
            assessment_status=?, confirmed_by=?, evidence_json=? WHERE asset_id=?""",
            (criticality, environment, str(owner or "").strip()[:120], str(notes or "").strip()[:1000], now,
             str(updated_by or "")[:120], json.dumps(factor_scores or {}, sort_keys=True),
             suggested or "", average, status,
             str(updated_by or "")[:120] if status == "Confirmed" else "",
             json.dumps(evidence or {}, sort_keys=True), asset_id))
        if cursor.rowcount != 1:
            raise ValueError("Asset was not found. Refresh the asset inventory and try again.")
    return get_asset(asset_id)


def criticality_map():
    """Map stable asset IDs to confirmed criticality or Unassigned."""
    return {asset["asset_id"]: asset["criticality"] for asset in list_assets()}
