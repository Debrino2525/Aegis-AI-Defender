"""Network topology visualization engine.

Builds and maintains a 2D network topology graph from connection data,
asset information, and monitor telemetry for visualization.
"""

from aegis.topology.engine import TopologyEngine, get_topology_engine

__all__ = ["TopologyEngine", "get_topology_engine"]
