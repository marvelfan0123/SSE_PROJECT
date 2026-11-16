import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from owasp_classifier import classify
from vulngraph_core import parse_docker_inspect, correlate_ports, make_attack_graph
import assessment_manager
import audit_log

class IntegrationTests(unittest.TestCase):
    def test_classification_requires_evidence(self):
        self.assertEqual(classify({'finding_id':'f1','cve':'CVE-2025-1234'},'a')['category'],'UNCLASSIFIED')
        self.assertEqual(classify({'finding_id':'f1','cwe':['CWE-79']},'a')['category'],'A05')
        self.assertEqual(classify({'finding_id':'f1','cwe':['CWE-79','CWE-287']},'a')['category'],'UNCLASSIFIED')

    def test_persist_graph_assessment_isolation(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(assessment_manager,'DB_PATH',Path(td)/'db.sqlite'):
                assessment_manager.initialize()
                a=assessment_manager.create_assessment('analyst','lab',{'name':'test'},'Normal')
                b=assessment_manager.create_assessment('analyst','lab',{'name':'test2'},'Normal')
                containers=parse_docker_inspect([{'Id':'abc','Config':{'Image':'test'},'State':{'Running':True},'NetworkSettings':{'Ports':{'3000/tcp':[{'HostIp':'127.0.0.1','HostPort':'8080'}]}}}])
                links=correlate_ports([{'asset':'127.0.0.1','port':'8080','state':'open'}],containers,a)
                assessment_manager.save_vg_evidence(a,containers,links,[classify({'finding_id':'f1','cwe':'CWE-79'},a)])
                stored=assessment_manager.load_vg_evidence(a)
                self.assertEqual(len(stored['relationships']),1)
                self.assertEqual(len(stored['classifications']),1)
                self.assertFalse(assessment_manager.load_vg_evidence(b)['relationships'])
                graph=make_attack_graph(stored['containers'],stored['relationships'],[],a)
                self.assertTrue(graph.has_edge('127.0.0.1:8080','abc'))
                cvg=make_attack_graph(stored['containers'],stored['relationships'],[{'assessment_id':a,'asset':'test','cve':'CVE-2025-12345'}],a)
                self.assertTrue(any(v=='cve:CVE-2025-12345' for u,v in cvg.edges()))

    def test_audit_chain_detects_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(audit_log,'DB_PATH',Path(td)/'audit.sqlite'):
                audit_log.log_event('analyst','Analyst','scan','assessment','a')
                audit_log.log_event('approver','Approver','review','assessment','a')
                self.assertTrue(audit_log.verify_audit_chain('Admin')['valid'])
                with audit_log._connection() as db:
                    db.execute("UPDATE audit_events SET action='forged' WHERE id=1")
                self.assertFalse(audit_log.verify_audit_chain('Admin')['valid'])
                with self.assertRaises(PermissionError):
                    audit_log.verify_audit_chain('Analyst')

if __name__ == '__main__': unittest.main()
