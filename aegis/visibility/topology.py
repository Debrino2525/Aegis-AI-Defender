"""Network topology visualization."""

from typing import Any, Dict, List, Optional


class NetworkTopology:
    """2D network topology visualization."""

    def __init__(self):
        self.nodes = []
        self.edges = []

    def add_node(self, ip: str, name: str, node_type: str = "unknown") -> None:
        """Add a node to the topology."""
        if not any(n["ip"] == ip for n in self.nodes):
            self.nodes.append({"ip": ip, "name": name, "type": node_type})

    def add_edge(self, source: str, dest: str, protocol: str = "unknown") -> None:
        """Add an edge to the topology."""
        if not any(e["source"] == source and e["dest"] == dest for e in self.edges):
            self.edges.append({"source": source, "dest": dest, "protocol": protocol})

    def get_topology(self) -> Dict[str, Any]:
        """Get the topology data for visualization."""
        return {"nodes": self.nodes, "edges": self.edges}
