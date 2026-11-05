"""Advanced AI API routes."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field
from aegis.ai.unsupervised import UnsupervisedLearning
from aegis.ai.predictive import PredictiveAnalytics
from aegis.ai.nlp import NaturalLanguageProcessing

router = APIRouter()
unsupervised = UnsupervisedLearning()
predictive = PredictiveAnalytics()
nlp = NaturalLanguageProcessing()


class TrainRequest(BaseModel):
    data: List[Dict[str, Any]]
    threshold_z: float = 2.5
    window: int = 200


class DetectRequest(BaseModel):
    model_id: str
    sample: Dict[str, Any]


class RLStateRequest(BaseModel):
    state: Dict[str, Any]


class RLFeedbackRequest(BaseModel):
    state: Dict[str, Any]
    action: str
    reward: float
    next_state: Optional[Dict[str, Any]] = None


class FederatedRequest(BaseModel):
    client_data: List[Dict[str, Any]]


class IncidentRequest(BaseModel):
    incident: Dict[str, Any]


class LoadRequest(BaseModel):
    current_load: Dict[str, Any]


class IngestScanRequest(BaseModel):
    result: Dict[str, Any]


class QueryRequest(BaseModel):
    query: str


class ReportRequest(BaseModel):
    data: Dict[str, Any]
    report_type: str = "weekly"


class EntityExtractRequest(BaseModel):
    text: str


@router.post("/api/ai/unsupervised/train")
async def train_anomaly_detector(req: TrainRequest):
    model_id = unsupervised.train_anomaly_detector(
        req.data, threshold_z=req.threshold_z, window=req.window
    )
    return {"model_id": model_id}


@router.post("/api/ai/unsupervised/detect")
async def detect_anomaly(req: DetectRequest):
    return {"anomalous": unsupervised.detect_anomaly(req.model_id, req.sample)}


@router.post("/api/ai/unsupervised/detail")
async def anomaly_detail(req: DetectRequest):
    return unsupervised.anomaly_detail(req.model_id, req.sample)


@router.post("/api/ai/rl/select-action")
async def select_action(req: RLStateRequest):
    return unsupervised.reinforcement_learning(req.state)


@router.post("/api/ai/rl/feedback")
async def rl_feedback(req: RLFeedbackRequest):
    unsupervised.record_outcome(
        state=req.state,
        action=req.action,
        reward=req.reward,
        next_state=req.next_state,
    )
    return {"status": "recorded"}


@router.post("/api/ai/federated/aggregate")
async def aggregate_federated(req: FederatedRequest):
    return unsupervised.federated_learning(req.client_data)


@router.post("/api/ai/predict/next-attack")
async def predict_next_attack(req: IncidentRequest):
    return predictive.predict_next_attack(req.incident)


@router.post("/api/ai/predict/ingest-scan")
async def ingest_scan(req: IngestScanRequest):
    predictive.ingest_scan_result(req.result)
    return {"status": "ingested"}


@router.get("/api/ai/predict/vulnerabilities")
async def forecast_vulnerabilities(time_horizon: int = 30):
    return predictive.forecast_vulnerabilities(time_horizon)


@router.post("/api/ai/predict/optimize-resources")
async def optimize_resources(req: LoadRequest):
    return predictive.optimize_resources(req.current_load)


@router.post("/api/ai/nlp/summarize")
async def summarize_incident(req: IncidentRequest):
    return {"summary": nlp.summarize_incident(req.incident)}


@router.post("/api/ai/nlp/query")
async def query_natural_language(req: QueryRequest):
    return nlp.query_natural_language(req.query)


@router.post("/api/ai/nlp/generate-report")
async def generate_report(req: ReportRequest):
    report = nlp.generate_report(req.data, report_type=req.report_type)
    return {"report": report}


@router.post("/api/ai/nlp/extract-entities")
async def extract_entities(req: EntityExtractRequest):
    return nlp.extract_entities(req.text)
