"""Network topology engine for 2D visualization.

Analyzes connections, assets, and monitor data to build a network topology
graph suitable for 2D visualization. Implements force-directed layout
algorithms for clear visualization.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum


class NodeType(Enum):
    """Types of nodes in the topology."""
    ASSET = "asset"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    """Types of edges in the topology."""
    CONNECTION = "connection"
    TRAFFIC = "traffic"
    SCAN = "scan"
    UNKNOWN = "unknown"


@dataclass
class TopologyNode:
    """A node in the topology graph."""
    id: str
    label: str
    node_type: NodeType
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    role: Optional[str] = None
    os_type: Optional[str] = None
    risk_level: Optional[str] = None
    x: float = 0.0
    y: float = 0.0
    radius: float = 20.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "node_type": self.node_type.value,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "role": self.role,
            "os_type": self.os_type,
            "risk_level": self.risk_level,
            "x": self.x,
            "y": self.y,
            "radius": self.radius,
            "metadata": self.metadata,
        }


@dataclass
class TopologyEdge:
    """An edge in the topology graph."""
    id: str
    source: str
    target: str
    edge_type: EdgeType
    weight: float = 1.0
    protocol: Optional[str] = None
    port: Optional[int] = None
    traffic_volume: int = 0
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "protocol": self.protocol,
            "port": self.port,
            "traffic_volume": self.traffic_volume,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
        }


@dataclass
class TopologyGraph:
    """The complete topology graph."""
    nodes: Dict[str, TopologyNode] = field(default_factory=dict)
    edges: Dict[str, TopologyEdge] = field(default_factory=dict)
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "last_updated": self.last_updated,
        }


class TopologyEngine:
    """Builds and maintains the network topology graph."""

    def __init__(self):
        self.graph = TopologyGraph()
        self._node_counter = 0
        self._edge_counter = 0

    def update_from_connections(self, connections: List[Dict[str, Any]]) -> None:
        """Update topology from network connection data."""
        for conn in connections:
            self._process_connection(conn)

        self._apply_layout()
        self.graph.last_updated = datetime.now(timezone.utc).isoformat()

    def update_from_assets(self, assets: List[Dict[str, Any]]) -> None:
        """Update topology from asset inventory data."""
        for asset in assets:
            self._process_asset(asset)

        self._apply_layout()
        self.graph.last_updated = datetime.now(timezone.utc).isoformat()

    def update_from_monitor_graph(self, monitor_nodes: List[Dict], monitor_edges: List[Dict]) -> None:
        """Update topology from existing monitor graph data."""
        for node in monitor_nodes:
            self._process_monitor_node(node)

        for edge in monitor_edges:
            self._process_monitor_edge(edge)

        self._apply_layout()
        self.graph.last_updated = datetime.now(timezone.utc).isoformat()

    def get_graph(self) -> TopologyGraph:
        """Get the current topology graph."""
        return self.graph

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        """Get a specific node."""
        return self.graph.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[TopologyNode]:
        """Get all neighbors of a node."""
        neighbors = []
        for edge in self.graph.edges.values():
            if edge.source == node_id:
                neighbors.append(self.graph.nodes.get(edge.target))
            elif edge.target == node_id:
                neighbors.append(self.graph.nodes.get(edge.source))
        return [n for n in neighbors if n]

    def _process_connection(self, conn: Dict[str, Any]) -> None:
        """Process a single connection into the topology."""
        local_ip = conn.get("local_ip")
        remote_ip = conn.get("remote_ip")
        remote_port = conn.get("remote_port")
        protocol = conn.get("protocol", "tcp")

        if not local_ip or not remote_ip:
            return

        # Create or update nodes
        local_node = self._get_or_create_node(local_ip, "connection")
        remote_node = self._get_or_create_node(remote_ip, "connection")

        # Create or update edge
        edge_id = f"{local_ip}-{remote_ip}-{remote_port}"
        if edge_id not in self.graph.edges:
            self.graph.edges[edge_id] = TopologyEdge(
                id=edge_id,
                source=local_ip,
                target=remote_ip,
                edge_type=EdgeType.CONNECTION,
                protocol=protocol,
                port=remote_port,
            )
        else:
            self.graph.edges[edge_id].weight += 1
            self.graph.edges[edge_id].last_seen = datetime.now(timezone.utc).isoformat()

    def _process_asset(self, asset: Dict[str, Any]) -> None:
        """Process an asset into the topology."""
        asset_id = asset.get("asset_id") or asset.get("agent_id")
        hostname = asset.get("hostname")
        ips = asset.get("ipv4", [])

        if not asset_id:
            return

        # Determine if this is an asset or external
        node_type = NodeType.ASSET if hostname else NodeType.EXTERNAL

        # Create node
        if asset_id not in self.graph.nodes:
            self.graph.nodes[asset_id] = TopologyNode(
                id=asset_id,
                label=hostname or asset_id,
                node_type=node_type,
                ip_address=ips[0] if ips else None,
                hostname=hostname,
                role=asset.get("role"),
                os_type=asset.get("os_type"),
                risk_level=asset.get("risk_level"),
            )
        else:
            # Update existing node
            node = self.graph.nodes[asset_id]
            if hostname:
                node.label = hostname
            if ips:
                node.ip_address = ips[0]
            if asset.get("role"):
                node.role = asset.get("role")
            if asset.get("os_type"):
                node.os_type = asset.get("os_type")
            if asset.get("risk_level"):
                node.risk_level = asset.get("risk_level")

    def _process_monitor_node(self, node: Dict) -> None:
        """Process a monitor graph node."""
        node_id = node.get("id")
        if not node_id:
            return

        if node_id not in self.graph.nodes:
            self.graph.nodes[node_id] = TopologyNode(
                id=node_id,
                label=node.get("label", node_id),
                node_type=NodeType.ASSET,
                ip_address=node.get("ip"),
                hostname=node.get("hostname"),
                x=node.get("x", 0.0),
                y=node.get("y", 0.0),
                metadata=node,
            )

    def _process_monitor_edge(self, edge: Dict) -> None:
        """Process a monitor graph edge."""
        edge_id = edge.get("id")
        source = edge.get("source")
        target = edge.get("target")

        if not edge_id or not source or not target:
            return

        if edge_id not in self.graph.edges:
            self.graph.edges[edge_id] = TopologyEdge(
                id=edge_id,
                source=source,
                target=target,
                edge_type=EdgeType.TRAFFIC,
                weight=edge.get("weight", 1.0),
                metadata=edge,
            )

    def _get_or_create_node(self, ip: str, source: str) -> TopologyNode:
        """Get or create a node for an IP address."""
        if ip not in self.graph.nodes:
            self.graph.nodes[ip] = TopologyNode(
                id=ip,
                label=ip,
                node_type=NodeType.EXTERNAL,
                ip_address=ip,
            )
        return self.graph.nodes[ip]

    def _apply_layout(self) -> None:
        """Apply force-directed layout to the graph."""
        if not self.graph.nodes:
            return

        # Initialize positions if not set
        for node in self.graph.nodes.values():
            if node.x == 0.0 and node.y == 0.0:
                node.x = math.random() * 800
                node.y = math.random() * 600

        # Simple force-directed layout (50 iterations)
        iterations = 50
        k = 100.0  # Optimal distance
        repulsion = 5000.0
        attraction = 0.01

        for _ in range(iterations):
            # Repulsion (nodes push apart)
            for n1 in self.graph.nodes.values():
                for n2 in self.graph.nodes.values():
                    if n1.id == n2.id:
                        continue

                    dx = n1.x - n2.x
                    dy = n1.y - n2.y
                    dist = math.sqrt(dx * dx + dy * dy) or 1.0

                    force = repulsion / (dist * dist)
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force

                    n1.x += fx
                    n1.y += fy

            # Attraction (connected nodes pull together)
            for edge in self.graph.edges.values():
                source = self.graph.nodes.get(edge.source)
                target = self.graph.nodes.get(edge.target)

                if not source or not target:
                    continue

                dx = target.x - source.x
                dy = target.y - source.y
                dist = math.sqrt(dx * dx + dy * dy) or 1.0

                force = (dist - k) * attraction
                fx = (dx / dist) * force
                fy = (dy / dist) * force

                source.x += fx
                source.y += fy
                target.x -= fx
                target.y -= fy

            # Center the graph
            avg_x = sum(n.x for n in self.graph.nodes.values()) / len(self.graph.nodes)
            avg_y = sum(n.y for n in self.graph.nodes.values()) / len(self.graph.nodes)

            for node in self.graph.nodes.values():
                node.x += (400 - avg_x) * 0.1
                node.y += (300 - avg_y) * 0.1

    def reset(self) -> None:
        """Reset the topology graph."""
        self.graph = TopologyGraph()
        self._node_counter = 0
        self._edge_counter = 0


# Global instance
_topology_engine: Optional[TopologyEngine] = None


def get_topology_engine() -> TopologyEngine:
    """Get the global topology engine instance."""
    global _topology_engine
    if _topology_engine is None:
        _topology_engine = TopologyEngine()
    return _topology_engine
