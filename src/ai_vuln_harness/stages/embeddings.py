"""Embedding-based similarity index for semantic dedup of findings.

Uses sentence-transformers + FAISS for fast cosine similarity search.
Lazy-loads the model on first use to avoid startup penalty.

Usage:
    index = EmbeddingIndex()
    index.encode_findings(findings)
    pairs = index.find_similar_pairs(threshold=0.85)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np

try:
    import faiss
    from sentence_transformers import SentenceTransformer

    _HAS_EMBEDDINGS = True
except ImportError:
    _HAS_EMBEDDINGS = False


_DEFAULT_MODEL = "all-MiniLM-L6-v2"
_DEFAULT_THRESHOLD = 0.85


def _finding_text(f: dict) -> str:
    """Produce a textual representation of a finding for embedding."""
    parts = [
        str(f.get("class") or ""),
        str(f.get("desc") or ""),
        str(f.get("file") or ""),
    ]
    return " ".join(p for p in parts if p)


class EmbeddingIndex:
    """Sentence-transformer embedding index for finding similarity.

    Lazy-loads the model on first ``encode_findings`` call.  When
    sentence-transformers or faiss is not installed, all methods become
    no-ops that return empty results.

    Parameters
    ----------
    model_name:
        Name of the sentence-transformers model to use.
    device:
        Torch device string (``"cpu"`` or ``"cuda"``).
    """

    def __init__(
        self,
        model_name: str = _DEFAULT_MODEL,
        device: str = "cpu",
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._model: SentenceTransformer | None = None
        self._embeddings: np.ndarray | None = None
        self._findings: list[dict] = []

    def _ensure_model(self) -> bool:
        """Lazily load the sentence-transformers model.

        Returns True if the model is available, False otherwise.
        """
        if not _HAS_EMBEDDINGS:
            return False
        if self._model is not None:
            return True
        try:
            self._model = SentenceTransformer(self._model_name, device=self._device)
            return True
        except Exception:
            return False

    def encode_findings(self, findings: list[dict]) -> int:
        """Encode findings into embeddings.

        Parameters
        ----------
        findings:
            List of finding dicts.

        Returns
        -------
        int
            Number of findings encoded.
        """
        if not findings:
            self._embeddings = None
            self._findings = []
            return 0

        if not self._ensure_model():
            self._findings = list(findings)
            return len(findings)

        texts = [_finding_text(f) for f in findings]
        self._embeddings = self._model.encode(
            texts,
            show_progress_bar=False,
            normalize_embeddings=True,
        ).astype("float32")
        self._findings = list(findings)
        return len(findings)

    def find_similar_pairs(
        self,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> list[tuple[int, int, float]]:
        """Find pairs of findings with cosine similarity above threshold.

        Parameters
        ----------
        threshold:
            Minimum cosine similarity (0.0–1.0).

        Returns
        -------
        List of (idx_a, idx_b, similarity) tuples. Each pair appears once
        with idx_a < idx_b.  Empty list when embeddings are unavailable.
        """
        if self._embeddings is None or len(self._findings) < 2:
            return []

        if not self._ensure_model():
            return []

        n = len(self._findings)
        dim = self._embeddings.shape[1]

        # Use FAISS inner-product index (embeddings are already L2-normalized,
        # so inner product = cosine similarity).
        index = faiss.IndexFlatIP(dim)
        index.add(self._embeddings)

        # Query each embedding against itself; skip self-match (distance=1.0)
        # and collect pairs above threshold.
        k = min(n, 50)  # neighbours to retrieve per query
        distances, indices = index.search(self._embeddings, k)

        pairs: list[tuple[int, int, float]] = []
        seen: set[tuple[int, int]] = set()

        for i in range(n):
            for j_idx in range(1, k):  # skip [0] = self
                j = int(indices[i, j_idx])
                if j < 0 or j >= n:
                    continue
                sim = float(distances[i, j_idx])
                if sim < threshold:
                    break  # results are sorted by descending distance
                a, b = (i, j) if i < j else (j, i)
                if (a, b) not in seen:
                    seen.add((a, b))
                    pairs.append((a, b, sim))

        pairs.sort(key=lambda x: x[2], reverse=True)
        return pairs

    @property
    def available(self) -> bool:
        """True when sentence-transformers + faiss are importable."""
        return _HAS_EMBEDDINGS

    @property
    def size(self) -> int:
        """Number of findings currently encoded."""
        return len(self._findings)
