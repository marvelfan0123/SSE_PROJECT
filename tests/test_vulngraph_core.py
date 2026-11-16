import unittest
from vulngraph_core import parse_docker_inspect,correlate_ports,contextual_risk,make_attack_graph

class VulnGraphCoreTests(unittest.TestCase):
    def setUp(self):
        self.containers=parse_docker_inspect([{'Id':'c1','Name':'/juice','Image':'sha256:img','Config':{'Image':'juice:latest'},'State':{'Running':True},'NetworkSettings':{'Ports':{'3000/tcp':[{'HostIp':'127.0.0.1','HostPort':'8080'}]},'Networks':{'lab':{}}}}])
    def test_inspect(self):
        self.assertEqual(self.containers[0]['mappings'][0]['host_port'],'8080')
    def test_local_mapping(self):
        links=correlate_ports([{'asset':'127.0.0.1','port':8080,'state':'open'}],self.containers,'a1')
        self.assertEqual(links[0]['status'],'Confirmed Mapping')
        self.assertIn('not confirmed external',links[0]['reachability'])
    def test_no_remote_mapping(self):
        self.assertEqual(correlate_ports([{'asset':'192.0.2.1','port':8080,'state':'open'}],self.containers,'a1'),[])
    def test_risk(self):
        self.assertEqual(contextual_risk(10,1,1,5)['risk'],10)
        self.assertEqual(contextual_risk(10,None,1,5)['risk'],10)
        self.assertIsNone(contextual_risk(None,.9,1,5)['risk'])
        self.assertIsNone(contextual_risk(8,.9,None,5)['risk'])
    def test_invalid(self):
        with self.assertRaises(ValueError): contextual_risk(8,float('nan'),1,5)
    def test_graph_assessment_isolation(self):
        links=correlate_ports([{'asset':'127.0.0.1','port':8080,'state':'open'}],self.containers,'a1')
        g=make_attack_graph(self.containers,links,[{'assessment_id':'a1','cve':'CVE-2024-1234','image_id':'sha256:img'}],'a1')
        self.assertTrue(g.has_edge('127.0.0.1:8080','c1'))
        self.assertTrue(g.has_edge('image:sha256:img','cve:CVE-2024-1234'))
        self.assertNotIn('Internet',g)
        g2=make_attack_graph(self.containers,links,[],'a2')
        self.assertFalse(g2.has_edge('127.0.0.1:8080','c1'))
if __name__=='__main__': unittest.main()
