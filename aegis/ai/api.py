"""Advanced AI API routes with Real Machine Learning and LLM Capabilities."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from aegis.ai.unsupervised import UnsupervisedLearning
from aegis.ai.predictive import PredictiveAnalytics
from aegis.ai.nlp import NaturalLanguageProcessing
from aegis.ai.llm.provider import LLMConfig, configure_llm, get_llm_provider
from aegis.ai.llm.investigator import AIInvestigator
from aegis.ai.llm.remediation_synthesizer import RemediationSynthesizer
from aegis.ai.ml.semantic_search import SemanticThreatSearch

router = APIRouter()
unsupervised = UnsupervisedLearning()
predictive = PredictiveAnalytics()
nlp = NaturalLanguageProcessing()
investigator = AIInvestigator()
remediation_synthesizer = RemediationSynthesizer()
semantic_search = SemanticThreatSearch()


# ---------------------------------------------------------------------------
# Pydantic Request Models
# ---------------------------------------------------------------------------

class TrainRequest(BaseModel):
    data: List[Dict[str, Any]]
    threshold_z: float = 2.5
    window: int = 200


class IForestFitRequest(BaseModel):
    data: List[Dict[str, Any]]
    contamination: float = 0.05
    n_estimators: int = 100


class IForestScoreRequest(BaseModel):
    model_id: Optional[str] = None
    sample: Dict[str, Any]


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


class SemanticSearchRequest(BaseModel):
    query: str
    top_k: int = 5


class ReportRequest(BaseModel):
    data: Dict[str, Any]
    report_type: str = "weekly"


class EntityExtractRequest(BaseModel):
    text: str


class RemediationRequest(BaseModel):
    finding: Dict[str, Any]


# ---------------------------------------------------------------------------
# LLM Provider Management Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/ai/llm/config")
async def configure_llm_provider(req: LLMConfig):
    """Configure the LLM backend (Gemini API, Ollama, OpenAI)."""
    provider = configure_llm(req)
    return {
        "status": "configured",
        "provider": provider.provider_name,
        "model": provider.model_name,
        "available": provider.is_available(),
    }


@router.get("/api/ai/llm/status")
async def get_llm_status():
    """Get active LLM provider connectivity status."""
    provider = get_llm_provider()
    return {
        "provider": provider.provider_name,
        "model": provider.model_name,
        "available": provider.is_available(),
    }


@router.post("/api/ai/llm/investigate")
async def investigate_incident_llm(req: IncidentRequest):
    """Perform a deep forensic incident investigation using the active LLM."""
    return await investigator.ainvestigate(req.incident)


@router.post("/api/ai/llm/synthesize-remediation")
async def synthesize_remediation_llm(req: RemediationRequest):
    """Generate OS-specific PowerShell & Bash remediation scripts using the LLM."""
    return await remediation_synthesizer.asynthesize(req.finding)


# ---------------------------------------------------------------------------
# Real Machine Learning Endpoints (Isolation Forest & Semantic Search)
# ---------------------------------------------------------------------------

@router.post("/api/ai/ml/isolation-forest/fit")
async def fit_isolation_forest(req: IForestFitRequest):
    """Fit a real scikit-learn Isolation Forest on network observations."""
    model_id = unsupervised.train_isolation_forest(
        req.data, contamination=req.contamination, n_estimators=req.n_estimators
    )
    return {"model_id": model_id, "algorithm": "IsolationForest", "samples": len(req.data)}


@router.post("/api/ai/ml/isolation-forest/score")
async def score_isolation_forest(req: IForestScoreRequest):
    """Score a network observation using the trained Isolation Forest."""
    return unsupervised.score_isolation_forest(req.model_id or "default", req.sample)


@router.post("/api/ai/ml/semantic-search")
async def semantic_threat_search(req: SemanticSearchRequest):
    """Semantic vector search across CVEs, KEVs, and ATT&CK techniques."""
    results = semantic_search.search(req.query, top_k=req.top_k)
    return {"query": req.query, "count": len(results), "results": results}


# ---------------------------------------------------------------------------
# Statistical & Unsupervised Learning Endpoints
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Predictive Analytics Endpoints
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Natural Language Processing & Reporting Endpoints
# ---------------------------------------------------------------------------

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
