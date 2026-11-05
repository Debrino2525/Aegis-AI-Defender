"""Tests for executive reporting module."""

from aegis.reporting.executive import ExecutiveReporter
from aegis.reporting.trends import TrendTracker

def test_executive_reporter():
    reporter = ExecutiveReporter()
    weekly = reporter.generate_weekly_report()
    assert weekly["type"] == "weekly"
    monthly = reporter.generate_monthly_report()
    assert monthly["type"] == "monthly"

def test_trend_tracker():
    tracker = TrendTracker()
    assert tracker.record_metric("test", 5.0) == True
    trend = tracker.get_trend("test", 30)
    assert isinstance(trend, list)
