"""Attack Path Discovery and Confidence Engine."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import networkx as nx
import vulngraph_core


@dataclass
class AttackPath:
    path_id: str
    nodes: List[str]
    length: int
    critical_cves: List[str]
    confidence: float
    description: str


class AttackPathEngine:
    """Discovers and ranks multi-hop attack paths through network and container topology."""

    @staticmethod
    def find_attack_paths(graph: nx.DiGraph, source: str = "internet", max_depth: int = 6) -> List[AttackPath]:
        """Discover valid traversal paths from attacker node to high-severity CVEs."""
        paths: List[AttackPath] = []
        if source not in graph:
            # Look for Attacker or Internet nodes
            candidates = [n for n, d in graph.nodes(data=True) if d.get("kind") in ("Attacker", "External Network") or "internet" in str(n).lower()]
            if not candidates:
                return []
            source = candidates[0]

        # Target nodes: CVE nodes
        cve_targets = [n for n, d in graph.nodes(data=True) if d.get("kind") == "CVE" or str(n).upper().startswith("CVE-")]

        for target in cve_targets[:25]:  # Bounded search for performance
            try:
                for raw_path in nx.all_simple_paths(graph, source=source, target=target, cutoff=max_depth):
                    # Compute path confidence based on edge statuses
                    confidence = 1.0
                    for u, v in zip(raw_path[:-1], raw_path[1:]):
                        edge_data = graph.get_edge_data(u, v, default={})
                        status = edge_data.get("status", "confirmed")
                        if status == "potential":
                            confidence *= 0.6
                        elif status == "inferred":
                            confidence *= 0.8

                    cve_node = raw_path[-1]
                    paths.append(AttackPath(
                        path_id=f"path_{len(paths)+1}",
                        nodes=raw_path,
                        length=len(raw_path),
                        critical_cves=[cve_node],
                        confidence=round(confidence, 2),
                        description=" -> ".join(str(n) for n in raw_path)
                    ))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        # Sort paths by length (shortest first) and confidence (highest first)
        paths.sort(key=lambda p: (-p.confidence, p.length))
        return paths

