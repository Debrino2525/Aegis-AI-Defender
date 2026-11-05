"""HTTP routes for network topology visualization."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from aegis.topology.engine import get_topology_engine

router = APIRouter()


@router.get("/api/topology")
async def get_topology():
    """Get the current network topology graph."""
    engine = get_topology_engine()
    graph = engine.get_graph()
    return graph.to_dict()


@router.get("/api/topology/nodes/{node_id}")
async def get_topology_node(node_id: str):
    """Get a specific topology node."""
    engine = get_topology_engine()
    node = engine.get_node(node_id)
    if not node:
        return {"error": "Node not found"}
    return node.to_dict()


@router.get("/api/topology/nodes/{node_id}/neighbors")
async def get_topology_neighbors(node_id: str):
    """Get neighbors of a topology node."""
    engine = get_topology_engine()
    neighbors = engine.get_neighbors(node_id)
    return {
        "node_id": node_id,
        "neighbors": [n.to_dict() for n in neighbors],
    }


@router.post("/api/topology/reset")
async def reset_topology():
    """Reset the topology graph."""
    engine = get_topology_engine()
    engine.reset()
    return {"ok": True}
