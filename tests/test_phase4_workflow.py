"""Phase 4 regression tests: creation, transitions, approval, verification and export."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import assessment_manager as am
import remediation_workflow as rw


class Phase4WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / 'phase4.db'
        self.patch = patch.object(am, 'DB_PATH', self.db)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.temp.cleanup)
        am.initialize()
        self.aid = am.create_assessment('analyst', 'docker_image', {'name':'test-image', 'scanner_plan': [('Trivy','Pending','')]})
        self.finding = {'finding_id':'f-1','source':'Trivy','finding_type':'vulnerability','severity':'HIGH',
                        'title':'Package vulnerability','asset':'test-image','cve':'CVE-2024-1234','package':'openssl'}
        am.save_findings(self.aid, [self.finding])

    def _create(self):
        return rw.create_ticket(self.aid, 'f-1', 'analyst', 'Analyst', owner='dev', due_date='2026-12-01')

    def test_create_is_idempotent_and_audited(self):
        tid = self._create()
        self.assertEqual(tid, self._create())
        self.assertEqual(len(rw.list_tickets(self.aid)), 1)
        self.assertEqual(len(rw.ticket_history(tid)), 1)

    def test_reject_unknown_finding(self):
        with self.assertRaises(ValueError):
            rw.create_ticket(self.aid, 'missing', 'analyst', 'Analyst')

    def test_reject_unauthorized_creation(self):
        with self.assertRaises(PermissionError):
            rw.create_ticket(self.aid, 'f-1', 'approver', 'Approver')

    def test_workflow_and_role_separation(self):
        tid = self._create()
        rw.change_ticket(tid, 'Pending Approval', 'analyst', 'Analyst')
        with self.assertRaises(PermissionError):
            rw.change_ticket(tid, 'Approved', 'analyst', 'Analyst')
        rw.change_ticket(tid, 'Approved', 'approver', 'Approver')
        with self.assertRaises(PermissionError):
            rw.change_ticket(tid, 'In Progress', 'approver', 'Approver')
        rw.change_ticket(tid, 'In Progress', 'analyst', 'Analyst', notes='patched')
        rw.change_ticket(tid, 'Ready for Rescan', 'analyst', 'Analyst')
        self.assertEqual(rw.list_tickets(self.aid)[0]['status'], 'Ready for Rescan')
        self.assertEqual(len(rw.ticket_history(tid)), 5)

    def test_no_resolution_without_independent_evidence(self):
        tid = self._create()
        rw.change_ticket(tid, 'Pending Approval', 'analyst', 'Analyst')
        rw.change_ticket(tid, 'Approved', 'approver', 'Approver')
        rw.change_ticket(tid, 'In Progress', 'analyst', 'Analyst')
        rw.change_ticket(tid, 'Ready for Rescan', 'analyst', 'Analyst')
        with self.assertRaises(ValueError):
            rw.change_ticket(tid, 'Resolved', 'approver', 'Approver')
        self.assertEqual(rw.list_tickets(self.aid)[0]['status'], 'Ready for Rescan')

    def test_invalid_transition_and_export(self):
        tid = self._create()
        with self.assertRaises(ValueError):
            rw.change_ticket(tid, 'Resolved', 'admin', 'Admin')
        self.assertIn('finding_id', rw.export_tickets(self.aid))
        self.assertIn('f-1', rw.export_tickets(self.aid, 'json'))

    def test_approver_cannot_reassign_owner(self):
        tid = self._create()
        with self.assertRaises(PermissionError):
            rw.change_ticket(tid, 'Open', 'approver', 'Approver', owner='other')


if __name__ == '__main__':
    unittest.main()
