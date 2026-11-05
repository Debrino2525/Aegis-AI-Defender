"""Executive reporting API routes."""

from fastapi import APIRouter
from aegis.reporting.executive import ExecutiveReporter
from aegis.reporting.trends import TrendTracker

router = APIRouter()
reporter = ExecutiveReporter()
tracker = TrendTracker()

@router.get("/api/reporting/weekly")
async def get_weekly_report():
    return reporter.generate_weekly_report()

@router.get("/api/reporting/monthly")
async def get_monthly_report():
    return reporter.generate_monthly_report()

@router.post("/api/reporting/schedule")
async def schedule_report(report_type: str, frequency: str):
    return {"success": reporter.schedule_report(report_type, frequency)}

@router.get("/api/reporting/trends/{metric_name}")
async def get_trend(metric_name: str, days: int = 30):
    return tracker.get_trend(metric_name, days)

@router.get("/api/reporting/metrics")
async def get_current_metrics():
    return {
        "attack_surface": tracker.calculate_attack_surface(),
        "detection_rate": tracker.calculate_detection_rate(),
        "response_time": tracker.calculate_response_time()
    }
