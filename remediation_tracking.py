"""Persist human remediation actions; never mark a fix verified without a rescan."""
from assessment_manager import _db, _now

STATUSES = {"Open", "In Progress", "Ready for Rescan"}


def initialize():
    with _db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS remediation_actions (
            assessment_id TEXT NOT NULL, finding_id TEXT NOT NULL,
            updated_by TEXT NOT NULL, status TEXT NOT NULL, notes TEXT NOT NULL,
            updated_at TEXT NOT NULL, PRIMARY KEY(assessment_id, finding_id),
            FOREIGN KEY(assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE)""")


def set_action(assessment_id, finding_id, username, status, notes=""):
    if status not in STATUSES:
        raise ValueError("Unsupported remediation state")
    if not assessment_id or not finding_id or not username:
        raise ValueError("Assessment, finding and user are required")
    initialize()
    with _db() as con:
        match = con.execute("SELECT 1 FROM assessment_findings WHERE assessment_id=? AND finding_id=?", (assessment_id, finding_id)).fetchone()
        if not match:
            raise ValueError("Finding does not belong to the assessment")
        con.execute("""INSERT INTO remediation_actions VALUES (?,?,?,?,?,?)
            ON CONFLICT(assessment_id, finding_id) DO UPDATE SET
            updated_by=excluded.updated_by,status=excluded.status,
            notes=excluded.notes,updated_at=excluded.updated_at""",
            (assessment_id, finding_id, username, status, notes[:2000], _now()))


def get_actions(assessment_id):
    initialize()
    with _db() as con:
        rows = con.execute("SELECT finding_id, status, notes, updated_by, updated_at FROM remediation_actions WHERE assessment_id=? ORDER BY updated_at DESC", (assessment_id,)).fetchall()
    return [dict(zip(("finding_id", "status", "notes", "updated_by", "updated_at"), row)) for row in rows]
