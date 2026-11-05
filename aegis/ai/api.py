"""Advanced AI API routes."""

from fastapi import APIRouter
from aegis.ai.unsupervised import UnsupervisedLearning
from aegis.ai.predictive import PredictiveAnalytics
from aegis.ai.nlp import NaturalLanguageProcessing

router = APIRouter()
unsupervised = UnsupervisedLearning()
predictive = PredictiveAnalytics()
nlp = NaturalLanguageProcessing()

@router.post("/api/ai/unsupervised/train")
async def train_anomaly_detector(data: list):
    model_id = unsupervised.train_anomaly_detector(data)
    return {"model_id": model_id}

@router.post("/api/ai/unsupervised/detect")
async def detect_anomaly(model_id: str, sample: dict):
    return {"anomalous": unsupervised.detect_anomaly(model_id, sample)}

@router.post("/api/ai/predict/next-attack")
async def predict_next_attack(incident: dict):
    return predictive.predict_next_attack(incident)

@router.get("/api/ai/predict/vulnerabilities")
async def forecast_vulnerabilities(time_horizon: int = 30):
    return predictive.forecast_vulnerabilities(time_horizon)

@router.post("/api/ai/nlp/summarize")
async def summarize_incident(incident: dict):
    return {"summary": nlp.summarize_incident(incident)}

@router.post("/api/ai/nlp/query")
async def query_natural_language(query: str):
    return nlp.query_natural_language(query)
