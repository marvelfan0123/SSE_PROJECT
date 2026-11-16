"""Unit tests for NetworkX attack graph generation and interactive visualization."""
import unittest
import networkx as nx
from vulngraph_core import (
    make_attack_graph,
    filter_attack_graph,
    generate_attack_graph_html,
    parse_docker_inspect,
    correlate_ports,
)


class NetworkXAttackGraphTests(unittest.TestCase):
    def setUp(self):
        self.containers = [
            {"container_id": "c_shop", "name": "juice-shop", "image": "bkimminich/juice-shop:v15.0",
             "image_id": "sha256:juice123", "running": True, "mappings": [{"container_port": "3000/tcp", "host_ip": "127.0.0.1", "host_port": "3000"}]}
        ]
        self.relationships = [
            {"relationship_id": "rel_1", "assessment_id": "as_1", "source": "127.0.0.1:3000", "destination": "c_shop",
             "status": "Confirmed Mapping", "evidence": {"probe": "nmap"}}
        ]
        self.findings = [
            {"assessment_id": "as_1", "cve": "CVE-2023-12345", "asset": "bkimminich/juice-shop:v15.0",
             "image_id": "sha256:juice123", "package": "jsonwebtoken", "installed_version": "8.5.1",
             "fixed_version": "9.0.0", "cvss": 9.8, "risk_score": 7.84, "severity": "CRITICAL"}
        ]
        self.hosts = [{"host_ip": "127.0.0.1", "hostname": "localhost", "state": "up"}]
        self.services = [{"host_ip": "127.0.0.1", "port": 3000, "service_name": "http", "product": "Node.js", "version": "18"}]

    def test_all_eight_node_types_generated(self):
        graph = make_attack_graph(
            self.containers, self.relationships, self.findings, "as_1",
            hosts=self.hosts, services=self.services, reachability=1.0, include_attacker=True
        )

        kinds = {d.get("kind") for _, d in graph.nodes(data=True)}
        expected_kinds = {"Attacker", "Host", "Open Port", "Service", "Container", "Image", "Dependency", "CVE"}
        self.assertEqual(kinds, expected_kinds)

        # Check nodes count and edges count
        self.assertGreaterEqual(graph.number_of_nodes(), 8)
        self.assertGreaterEqual(graph.number_of_edges(), 7)

    def test_evidence_only_node_creation_trivy_only(self):
        """When only Trivy image findings exist and no Docker/Nmap evidence exists, do not fabricate Host/Port/Container nodes."""
        graph = make_attack_graph(
            [], [], self.findings, "as_1",
            hosts=[], services=[], reachability=0.0, include_attacker=True
        )
        kinds = {d.get("kind") for _, d in graph.nodes(data=True)}
        self.assertIn("Image", kinds)
        self.assertIn("Dependency", kinds)
        self.assertIn("CVE", kinds)
        self.assertNotIn("Host", kinds)
        self.assertNotIn("Open Port", kinds)
        self.assertNotIn("Container", kinds)

    def test_evidence_only_node_creation_nmap_only(self):
        """When only Nmap Host/Service evidence exists, do not fabricate Container/Image/CVE nodes."""
        graph = make_attack_graph(
            [], [], [], "as_1",
            hosts=self.hosts, services=self.services, reachability=1.0, include_attacker=True
        )
        kinds = {d.get("kind") for _, d in graph.nodes(data=True)}
        self.assertIn("Attacker", kinds)
        self.assertIn("Host", kinds)
        self.assertIn("Open Port", kinds)
        self.assertIn("Service", kinds)
        self.assertNotIn("Container", kinds)
        self.assertNotIn("Image", kinds)
        self.assertNotIn("CVE", kinds)

    def test_traceable_edges_with_status_and_evidence(self):
        graph = make_attack_graph(
            self.containers, self.relationships, self.findings, "as_1",
            hosts=self.hosts, services=self.services, reachability=1.0, include_attacker=True
        )
        for u, v, data in graph.edges(data=True):
            self.assertIn("status", data)
            self.assertIn("source", data)
            self.assertIn("evidence", data)
            self.assertIn("confirmed", data)
            self.assertIn("style", data)
            self.assertIn(data["status"], ("Confirmed Mapping", "Confirmed External Reachability", "Internal Modelled Exposure",
                                          "Service Detection", "Container Image Association", "Package Dependency", "Confirmed Association"))

    def test_confirmed_vs_potential_distinction(self):
        unconfirmed_rel = [
            {"relationship_id": "rel_u", "assessment_id": "as_1", "source": "127.0.0.1:8080", "destination": "c_shop",
             "status": "Unverified Mapping", "evidence": {"probe": "docker_only"}}
        ]
        graph = make_attack_graph(
            self.containers, unconfirmed_rel, self.findings, "as_1",
            hosts=self.hosts, services=self.services, reachability=0.5, include_attacker=True
        )
        styles = {d.get("style") for _, _, d in graph.edges(data=True)}
        self.assertIn("solid", styles)
        self.assertIn("dashed", styles)

    def test_graph_filtering(self):
        unconfirmed_rel = [
            {"relationship_id": "rel_u", "assessment_id": "as_1", "source": "127.0.0.1:8080", "destination": "c_shop",
             "status": "Unverified Mapping", "evidence": {"probe": "docker_only"}}
        ]
        graph = make_attack_graph(
            self.containers, self.relationships + unconfirmed_rel, self.findings, "as_1",
            hosts=self.hosts, services=self.services, reachability=1.0, include_attacker=True
        )
        # Filter by node types
        cve_only = filter_attack_graph(graph, allowed_kinds=["Dependency", "CVE"])
        self.assertEqual({d.get("kind") for _, d in cve_only.nodes(data=True)}, {"Dependency", "CVE"})

        # Filter by Confirmed Only
        confirmed_g = filter_attack_graph(graph, confirmation_filter="Confirmed Only")
        for _, _, ed in confirmed_g.edges(data=True):
            self.assertTrue(ed.get("confirmed", True))

        # Filter by Search query
        search_g = filter_attack_graph(graph, search_query="CVE-2023-12345")
        self.assertIn("cve:CVE-2023-12345", search_g.nodes)

    def test_assessment_isolation(self):
        graph1 = make_attack_graph(self.containers, self.relationships, self.findings, "as_1")
        graph2 = make_attack_graph(self.containers, self.relationships, self.findings, "as_2")
        self.assertGreater(graph1.number_of_nodes(), 0)
        # as_2 should not contain findings or relationships from as_1
        self.assertEqual(len([n for n, d in graph2.nodes(data=True) if d.get("kind") == "CVE"]), 0)

    def test_pyvis_html_generation(self):
        graph = make_attack_graph(
            self.containers, self.relationships, self.findings, "as_1",
            hosts=self.hosts, services=self.services, reachability=1.0, include_attacker=True
        )
        html_out = generate_attack_graph_html(graph, height="500px")
        self.assertIn("<html", html_out.lower())
        self.assertIn("#0B1220", html_out)  # Midnight security background
        self.assertIn("vis-network", html_out)


if __name__ == "__main__":
    unittest.main()

