"""Lightweight embedding support for adversarial input deduplication.

Uses sentence-transformers (all-MiniLM-L6-v2, 80 MB) for local inference
— no Postgres or cloud service required.  The same interface will work
unchanged when the project migrates to pgvector: swap the storage backend,
keep embed() and semantic_similarity() as-is.
"""

from __future__ import annotations

import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

_model = None


def _get_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Loaded sentence-transformers model all-MiniLM-L6-v2")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed; embedding disabled. "
                "Run: pip install sentence-transformers"
            )
    return _model


def embed(text: str) -> Optional[List[float]]:
    """Return a 384-dimensional embedding for text, or None if unavailable."""
    model = _get_model()
    if model is None:
        return None
    try:
        return model.encode(text, show_progress_bar=False).tolist()
    except Exception as exc:
        logger.warning(f"Embedding failed: {exc}")
        return None


def semantic_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two embedding vectors."""
    try:
        import numpy as np
        va, vb = np.array(a), np.array(b)
        denom = np.linalg.norm(va) * np.linalg.norm(vb)
        if denom == 0:
            return 0.0
        return float(np.dot(va, vb) / denom)
    except Exception:
        return 0.0
