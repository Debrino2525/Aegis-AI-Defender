"""Semantic Vector Search Engine for Threat Intel and CVEs.

Uses scikit-learn TF-IDF Vectorizer and Cosine Similarity to allow semantic
queries across vulnerabilities, CISA KEVs, and MITRE ATT&CK techniques.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# Default knowledge base seed of prominent CVEs and ATT&CK tactics
DEFAULT_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "id": "CVE-2021-44228",
        "title": "Log4Shell Apache Log4j JNDI Remote Code Execution",
        "description": "Apache Log4j2 logging framework JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints allowing unauthenticated remote code execution.",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "tactic": "Initial Access",
        "cisa_kev": True,
    },
    {
        "id": "CVE-2023-38606",
        "title": "Apple Kernel GMode Hardware MMIO Bypass Zero-Day",
        "description": "An attacker with kernel privileges may bypass hardware page protection mechanisms via memory-mapped I/O registers during Triangulation campaign.",
        "severity": "HIGH",
        "cvss": 8.8,
        "tactic": "Defense Evasion",
        "cisa_kev": True,
    },
    {
        "id": "CVE-2024-21413",
        "title": "Microsoft Outlook Moniker Link Remote Code Execution (#MonikerLink)",
        "description": "Microsoft Outlook remote code execution vulnerability bypassing Protected View when processing special file:// moniker link paths.",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "tactic": "Execution",
        "cisa_kev": True,
    },
    {
        "id": "CVE-2023-34362",
        "title": "MOVEit Transfer SQL Injection to Remote Code Execution",
        "description": "Progress MOVEit Transfer web application SQL injection vulnerability allowing unauthenticated attacker to gain access to database and execute arbitrary code.",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "tactic": "Initial Access",
        "cisa_kev": True,
    },
    {
        "id": "CVE-2024-3094",
        "title": "XZ Utils liblzma SSH Backdoor Supply Chain Compromise",
        "description": "Malicious code injected into upstream tarballs of XZ Utils compromising OpenSSH sshd authentication through systemd notify mechanism.",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "tactic": "Persistence",
        "cisa_kev": True,
    },
    {
        "id": "T1021.002",
        "title": "SMB/Windows Admin Shares Lateral Movement",
        "description": "Adversaries may use valid accounts to interact with remote SMB shares over TCP port 445 to execute code and move laterally across Windows domain.",
        "severity": "HIGH",
        "cvss": 8.0,
        "tactic": "Lateral Movement",
        "cisa_kev": False,
    },
    {
        "id": "T1071.001",
        "title": "Web Protocols C2 Beaconing (HTTP/HTTPS)",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to evade network detection systems and establish command and control.",
        "severity": "HIGH",
        "cvss": 7.5,
        "tactic": "Command and Control",
        "cisa_kev": False,
    },
    {
        "id": "T1041",
        "title": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel rather than initiating a separate connection.",
        "severity": "HIGH",
        "cvss": 7.5,
        "tactic": "Exfiltration",
        "cisa_kev": False,
    },
]


class SemanticThreatSearch:
    """Vector-space semantic search engine for CVEs and ATT&CK intelligence."""

    def __init__(self, corpus: Optional[List[Dict[str, Any]]] = None):
        self._corpus: List[Dict[str, Any]] = list(corpus or DEFAULT_KNOWLEDGE_BASE)
        self._vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            max_features=5000,
        )
        self._tfidf_matrix: Optional[np.ndarray] = None
        self._build_index()

    def _build_index(self) -> None:
        """Vectorize the documents in the knowledge base."""
        if not self._corpus:
            return
        texts = [
            f"{doc.get('id', '')} {doc.get('title', '')} {doc.get('description', '')} {doc.get('tactic', '')}"
            for doc in self._corpus
        ]
        self._tfidf_matrix = self._vectorizer.fit_transform(texts)

    def add_documents(self, documents: List[Dict[str, Any]]) -> None:
        """Add new CVE or finding records to the semantic search index."""
        self._corpus.extend(documents)
        self._build_index()

    def search(self, query: str, top_k: int = 5, min_score: float = 0.05) -> List[Dict[str, Any]]:
        """Perform semantic cosine-similarity search against the vectorized knowledge base."""
        if not query.strip() or self._tfidf_matrix is None:
            return []

        query_vec = self._vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self._tfidf_matrix)[0]

        # Rank indices by highest similarity
        top_indices = np.argsort(similarities)[::-1]
        results = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score < min_score:
                break
            doc = dict(self._corpus[idx])
            doc["similarity_score"] = round(score, 4)
            results.append(doc)
            if len(results) >= top_k:
                break

        return results
