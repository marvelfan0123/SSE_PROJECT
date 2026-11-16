"""Graph Visualizer and PyVis HTML Generation."""
from __future__ import annotations
from typing import Any, Dict, Optional
import networkx as nx
import vulngraph_core


class GraphVisualizer:
    """Generates interactive PyVis visual representations with anti-shaking physics."""

    @staticmethod
    def generate_html(
        graph: nx.DiGraph,
        height: str = "680px",
        selected_asset: str = "All",
        selected_node_type: str = "All",
        severity_filter: str = "All",
        status_filter: str = "All",
        search_query: str = ""
    ) -> str:
        """Render the complete interactive attack graph HTML."""
        return vulngraph_core.generate_global_attack_graph_html(
            graph,
            height=height,
            selected_asset=selected_asset,
            selected_node_type=selected_node_type,
            severity_filter=severity_filter,
            status_filter=status_filter,
            search_query=search_query
        )

