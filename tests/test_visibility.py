"""Tests for visibility module."""

from aegis.visibility.fingerprinting import DeviceFingerprinter
from aegis.visibility.topology import NetworkTopology

def test_fingerprint_mac():
    fp = DeviceFingerprinter()
    result = fp.fingerprint_from_mac("00:50:56:00:00:01")
    assert result is not None
    assert result["vendor"] == "VMware"

def test_topology():
    topo = NetworkTopology()
    topo.add_node("10.0.0.1", "Server", "server")
    topo.add_edge("10.0.0.1", "10.0.0.2", "TCP")
    data = topo.get_topology()
    assert len(data["nodes"]) == 1
    assert len(data["edges"]) == 1
