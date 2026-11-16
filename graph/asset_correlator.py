"""Asset Correlation Engine for Attack Graph Construction."""
from __future__ import annotations
from typing import Any, Dict, List, Set, Tuple
import vulngraph_core


class AssetCorrelator:
    """Correlates container inspect metadata, open ports, and services into structured graph entities."""

    @staticmethod
    def correlate_ports(open_ports: List[Dict[str, Any]], bindings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map external port bindings to internal container services."""
        return vulngraph_core.correlate_ports(open_ports, bindings)

    @staticmethod
    def parse_docker_metadata(inspect_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract graph node properties from Docker inspection."""
        return vulngraph_core.parse_docker_inspect(inspect_data)

