"""Tests for threat hunting module."""

from aegis.hunting.pcap import PCAPManager
from aegis.hunting.search import AdvancedSearch
from aegis.hunting.export import DataExporter

def test_pcap_manager():
    pcap = PCAPManager()
    assert pcap.start_capture("eth0") == True
    result = pcap.stop_capture()
    assert result is not None

def test_advanced_search():
    search = AdvancedSearch()
    alerts = search.search_alerts("test")
    assert isinstance(alerts, list)

def test_data_exporter():
    exporter = DataExporter()
    dns_csv = exporter.export_dns("24h")
    assert "timestamp" in dns_csv
