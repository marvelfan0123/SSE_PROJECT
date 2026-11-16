from security_controls import csv_cell
"""Phase 4: assessment-scoped, role-controlled remediation tickets and verification.

No scan absence alone marks a finding resolved. All changes are auditable.
"""
import csv
import io
import json
from datetime import datetime, timezone
from assessment_manager import _db, initialize as initialize_assessments
from auth import require_permission
from assessment_comparison import finding_match_key

STATES = ('Open', 'Pending Approval', 'Approved', 'In Progress', 'Ready for Rescan', 'Resolved', 'Rejected')
TRANSITIONS = {
    'Open': {'Pending Approval'},
    'Pending Approval': {'Approved', 'Rejected'},
    'Approved': {'In Progress', 'Rejected'},
    'In Progress': {'Ready for Rescan'},
    'Ready for Rescan': {'In Progress', 'Resolved'},
    'Rejected': {'Pending Approval'},
    'Resolved': set(),
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def initialize():
    initialize_assessments()
    with _db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS remediation_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT NOT NULL, finding_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open', owner TEXT NOT NULL DEFAULT '',
            due_date TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
            requested_by TEXT NOT NULL, approved_by TEXT NOT NULL DEFAULT '',
            verified_by TEXT NOT NULL DEFAULT '', verification_assessment TEXT NOT NULL DEFAULT '',
            verification_evidence TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, UNIQUE(assessment_id,finding_id),
            FOREIGN KEY(assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE)''')
        db.execute('''CREATE TABLE IF NOT EXISTS remediation_ticket_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL,
            actor TEXT NOT NULL, actor_role TEXT NOT NULL, old_status TEXT NOT NULL,
            new_status TEXT NOT NULL, detail TEXT NOT NULL, at TEXT NOT NULL,
            FOREIGN KEY(ticket_id) REFERENCES remediation_tickets(id) ON DELETE CASCADE)''')


def _row(db, ticket_id):
    db.row_factory = __import__('sqlite3').Row
    record = db.execute('SELECT * FROM remediation_tickets WHERE id=?', (int(ticket_id),)).fetchone()
    if record is None:
        raise ValueError('Remediation ticket not found')
    return dict(record)


def create_ticket(assessment_id, finding_id, actor, role, owner='', due_date='', notes=''):
    require_permission(role, 'create_remediation')
    if not actor or not finding_id or not assessment_id:
        raise ValueError('Assessment, finding and actor are required')
    if due_date:
        datetime.strptime(due_date, '%Y-%m-%d')
    initialize()
    with _db() as db:
        found = db.execute('SELECT 1 FROM assessment_findings WHERE assessment_id=? AND finding_id=?', (assessment_id, finding_id)).fetchone()
        if not found:
            raise ValueError('Finding is not part of this assessment')
        now = _now()
        cursor = db.execute('''INSERT OR IGNORE INTO remediation_tickets
            (assessment_id,finding_id,owner,due_date,notes,requested_by,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?)''', (assessment_id, finding_id, owner.strip(), due_date, notes[:2000], actor, now, now))
        row = db.execute('SELECT id FROM remediation_tickets WHERE assessment_id=? AND finding_id=?', (assessment_id, finding_id)).fetchone()
        if cursor.rowcount:
            db.execute('INSERT INTO remediation_ticket_events (ticket_id,actor,actor_role,old_status,new_status,detail,at) VALUES (?,?,?,?,?,?,?)', (row[0], actor, role, '', 'Open', 'Ticket created', now))
        return row[0]


def change_ticket(ticket_id, new_status, actor, role, *, owner=None, due_date=None, notes=None, verification_assessment='', evidence=''):
    require_permission(role, 'update_remediation_work')
    initialize()
    with _db() as db:
        old = _row(db, ticket_id)
        before = old['status']
        if new_status not in STATES or (new_status != before and new_status not in TRANSITIONS[before]):
            raise ValueError(f'Invalid remediation transition: {before} -> {new_status}')
        if new_status != before:
            approval = new_status in {'Approved', 'Rejected', 'Resolved'}
            if approval and role not in {'Approver', 'Admin'}:
                raise PermissionError('Only an approver or admin may approve, reject or resolve')
            if not approval and role not in {'Analyst', 'Security Analyst', 'Admin'}:
                raise PermissionError('Only an analyst or admin may advance remediation work')
            if approval and actor.strip().lower() == old['requested_by'].strip().lower():
                raise PermissionError('Maker-Checker: the requester cannot approve or verify their own recommendation')
        if role == 'Approver' and any(v is not None for v in (owner, due_date, notes)):
            raise PermissionError('Approvers cannot edit remediation work details')
        if role in {'Analyst', 'Security Analyst'} and (verification_assessment or evidence):
            raise PermissionError('Analysts cannot record independent verification')
        new_owner = old['owner'] if owner is None else owner.strip()
        new_due = old['due_date'] if due_date is None else due_date
        new_notes = old['notes'] if notes is None else notes[:2000]
        if new_due:
            datetime.strptime(new_due, '%Y-%m-%d')
        verifier = old['verified_by']
        verified_scan = old['verification_assessment']
        verified_evidence = old['verification_evidence']
        if new_status in {'Approved', 'Rejected'} and evidence.strip():
            verified_evidence = evidence.strip()[:2000]
        if new_status == 'Resolved' and before != 'Resolved':
            if actor.strip().lower() == old['requested_by'].strip().lower():
                raise PermissionError('Maker-Checker: independent verification is required')
            if not verification_assessment or not evidence.strip():
                raise ValueError('Resolution requires a later comparable rescan and independent verification evidence')
            from assessment_manager import get_assessment
            from scan_flow import coverage_comparable
            original = get_assessment(old['assessment_id'])
            followup = get_assessment(verification_assessment)
            if not original or not followup or followup['assessment_id'] == original['assessment_id']:
                raise ValueError('Verification must use a different assessment')
            if followup.get('created_at', '') <= original.get('created_at', ''):
                raise ValueError('Verification scan must be later than original assessment')
            if followup.get('status') != 'Completed' or not coverage_comparable(original, followup):
                raise ValueError('Verification requires completed comparable scanner coverage')
            source = next((f for f in original.get('findings', []) if f['finding_id'] == old['finding_id']), None)
            if source is None:
                raise ValueError('Original finding no longer exists')
            if any(finding_match_key(f) == finding_match_key(source) for f in followup.get('findings', [])):
                raise ValueError('Finding remains detected in verification scan')
            verifier, verified_scan, verified_evidence = actor, verification_assessment, evidence.strip()[:2000]
        now = _now()
        db.execute('''UPDATE remediation_tickets SET status=?,owner=?,due_date=?,notes=?,
            approved_by=?,verified_by=?,verification_assessment=?,verification_evidence=?,updated_at=? WHERE id=?''',
            (new_status, new_owner, new_due, new_notes,
             actor if new_status in {'Approved', 'Rejected'} and new_status != before else old['approved_by'],
             verifier, verified_scan, verified_evidence, now, ticket_id))
        if new_status != before or (new_owner, new_due, new_notes) != (old['owner'], old['due_date'], old['notes']):
            db.execute('INSERT INTO remediation_ticket_events (ticket_id,actor,actor_role,old_status,new_status,detail,at) VALUES (?,?,?,?,?,?,?)',
                       (ticket_id, actor, role, before, new_status, ('Evidence: '+evidence[:300]) if evidence else 'Ticket updated', now))
        return True


def list_tickets(assessment_id=None):
    initialize()
    with _db() as db:
        db.row_factory = __import__('sqlite3').Row
        if assessment_id:
            rows = db.execute('SELECT * FROM remediation_tickets WHERE assessment_id=? ORDER BY id DESC', (assessment_id,)).fetchall()
        else:
            rows = db.execute('SELECT * FROM remediation_tickets ORDER BY id DESC').fetchall()
        return [dict(row) for row in rows]


def ticket_history(ticket_id):
    initialize()
    with _db() as db:
        db.row_factory = __import__('sqlite3').Row
        return [dict(r) for r in db.execute('SELECT * FROM remediation_ticket_events WHERE ticket_id=? ORDER BY id', (int(ticket_id),)).fetchall()]


def export_tickets(assessment_id, fmt='csv'):
    rows = list_tickets(assessment_id)
    if fmt == 'json':
        return json.dumps(rows, indent=2)
    if fmt != 'csv':
        raise ValueError('Unsupported export format')
    output = io.StringIO()
    columns = ['id','assessment_id','finding_id','status','owner','due_date','requested_by','approved_by','verified_by','verification_assessment','created_at','updated_at']
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore')
    writer.writeheader()
    writer.writerows([{key: csv_cell(value) for key, value in row.items()} for row in rows])
    return output.getvalue()
