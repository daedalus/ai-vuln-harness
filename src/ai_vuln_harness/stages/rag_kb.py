"""RAG Knowledge Base for CWE/CVE vulnerability patterns.

Provides semantic matching of code snippets against known vulnerability patterns
using multiple backends:
- SQLite + TF-IDF (default, no external dependencies)
- SQLite + FAISS (optional, requires faiss-cpu + sentence-transformers)

Reference: DeepAudit's RAG knowledge base (CWE/CVE via ChromaDB).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

try:
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer

    _HAS_FAISS = True
except ImportError:
    _HAS_FAISS = False


# Built-in CWE/CVE pattern catalog
_DEFAULT_CWE_PATTERNS: list[dict] = [
    {
        "cwe": "CWE-78",
        "title": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
        "patterns": ["os.system", "subprocess.call", "subprocess.Popen", "exec(", "eval(", "shell=True"],
        "language": "python",
    },
    {
        "cwe": "CWE-89",
        "title": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input, but it does not neutralize or incorrectly neutralizes special elements.",
        "patterns": ["execute(", "cursor.execute", "query(", "sql", "SELECT", "INSERT", "UPDATE", "DELETE"],
        "language": "generic",
    },
    {
        "cwe": "CWE-79",
        "title": "Cross-site Scripting (XSS)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.",
        "patterns": ["innerHTML", "document.write", "render_template_string", "Markup(", "safe(", "mark_safe"],
        "language": "generic",
    },
    {
        "cwe": "CWE-22",
        "title": "Path Traversal",
        "description": "The software uses external input to construct a pathname, but it does not properly neutralize special elements that could resolve to a location outside the restricted directory.",
        "patterns": ["open(", "os.path.join", "../", "..\\\\", "pathlib", "Path("],
        "language": "generic",
    },
    {
        "cwe": "CWE-918",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "patterns": ["requests.get", "requests.post", "urlopen", "urllib", "httpx", "aiohttp", "fetch("],
        "language": "python",
    },
    {
        "cwe": "CWE-502",
        "title": "Deserialization of Untrusted Data",
        "description": "The software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "patterns": ["pickle.load", "pickle.loads", "yaml.load", "yaml.unsafe_load", "marshal.loads", "jsonpickle"],
        "language": "python",
    },
    {
        "cwe": "CWE-798",
        "title": "Use of Hard-coded Credentials",
        "description": "The software contains hard-coded credentials such as a password or cryptographic key.",
        "patterns": ["password", "secret", "api_key", "token", "credential", "auth_token"],
        "language": "generic",
    },
    {
        "cwe": "CWE-327",
        "title": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "The software uses a broken or risky cryptographic algorithm or protocol.",
        "patterns": ["md5(", "sha1(", "DES", "RC4", "ECB", "weak", "insecure"],
        "language": "generic",
    },
    {
        "cwe": "CWE-287",
        "title": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        "patterns": ["authenticate", "login", "session", "cookie", "jwt", "token"],
        "language": "generic",
    },
    {
        "cwe": "CWE-862",
        "title": "Missing Authorization",
        "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        "patterns": ["@app.route", "def ", "permission", "role", "admin", "access"],
        "language": "generic",
    },
    {
        "cwe": "CWE-611",
        "title": "XML External Entity (XXE) Injection",
        "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
        "patterns": ["xml.etree", "lxml", "defusedxml", "ENTITY", "SYSTEM", "DTD"],
        "language": "python",
    },
    {
        "cwe": "CWE-434",
        "title": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        "patterns": ["upload", "file", "multipart", "filename", "content_type"],
        "language": "generic",
    },
    {
        "cwe": "CWE-306",
        "title": "Missing Authentication for Critical Function",
        "description": "The software does not perform any authentication for functionality that requires a provable user identity.",
        "patterns": ["debug", "admin", "console", "management", "internal"],
        "language": "generic",
    },
    {
        "cwe": "CWE-190",
        "title": "Integer Overflow or Wraparound",
        "description": "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.",
        "patterns": ["int(", "overflow", "wraparound", "MAX_INT", "limit"],
        "language": "generic",
    },
    {
        "cwe": "CWE-125",
        "title": "Out-of-bounds Read",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
        "patterns": ["buffer", "overflow", "bounds", "length", "size", "index"],
        "language": "generic",
    },
]


class VulnerabilityKB:
    """Knowledge base for CWE/CVE vulnerability patterns.

    Supports multiple backends:
    - SQLite + TF-IDF (default, no external dependencies)
    - SQLite + FAISS (optional, requires faiss-cpu + sentence-transformers)

    Usage:
        # Default: SQLite + TF-IDF
        kb = VulnerabilityKB()

        # With SQLite persistence
        kb = VulnerabilityKB(db_path="output/kb.db")

        # With FAISS backend (if installed)
        kb = VulnerabilityKB(db_path="output/kb.db", use_faiss=True)
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        use_faiss: bool = False,
        embedding_model: str = "all-MiniLM-L6-v2",
        reset: bool = False,
    ) -> None:
        self._patterns: list[dict] = list(_DEFAULT_CWE_PATTERNS)
        self._vectorizer: TfidfVectorizer | None = None
        self._tfidf_matrix = None
        self._built_tfidf = False

        # FAISS state
        self._use_faiss = use_faiss and _HAS_FAISS
        self._faiss_index = None
        self._faiss_embeddings = None
        self._faiss_model = None
        self._built_faiss = False

        if self._use_faiss:
            try:
                self._faiss_model = SentenceTransformer(embedding_model)
            except Exception:
                self._use_faiss = False

        # SQLite state
        self._conn: sqlite3.Connection | None = None
        self._db_path = db_path

        if db_path:
            self._init_db(db_path, reset=reset)
            self._load_from_db()

    def _init_db(self, db_path: Path | str, reset: bool = False) -> None:
        """Initialize SQLite database for pattern storage.

        If reset=True, drops and recreates the table.
        """
        self._conn = sqlite3.connect(str(db_path))

        if reset:
            self._conn.execute("DROP TABLE IF EXISTS cwe_patterns")

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cwe_patterns (
                cwe TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                patterns TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT 'generic'
            )
        """)
        self._conn.commit()

        # Seed database with defaults only when empty
        count = self._conn.execute("SELECT COUNT(*) FROM cwe_patterns").fetchone()[0]
        if count == 0:
            for p in _DEFAULT_CWE_PATTERNS:
                self._conn.execute(
                    """INSERT OR REPLACE INTO cwe_patterns(cwe, title, description, patterns, language)
                       VALUES(?, ?, ?, ?, ?)""",
                    (p["cwe"], p["title"], p["description"], json.dumps(p.get("patterns", [])), p.get("language", "generic")),
                )
            self._conn.commit()

    def _load_from_db(self) -> None:
        """Load patterns from database into memory."""
        if not self._conn:
            return
        rows = self._conn.execute("SELECT cwe, title, description, patterns, language FROM cwe_patterns").fetchall()
        # Replace defaults with DB content
        self._patterns = []
        for cwe, title, desc, patterns_json, lang in rows:
            self._patterns.append({
                "cwe": cwe,
                "title": title,
                "description": desc,
                "patterns": json.loads(patterns_json),
                "language": lang,
            })
        self._built = False

    def _save_to_db(self) -> None:
        """Save all patterns to database."""
        if not self._conn:
            return
        for p in self._patterns:
            self._conn.execute(
                """INSERT OR REPLACE INTO cwe_patterns(cwe, title, description, patterns, language)
                   VALUES(?, ?, ?, ?, ?)""",
                (p["cwe"], p["title"], p["description"], json.dumps(p.get("patterns", [])), p.get("language", "generic")),
            )
        self._conn.commit()

    def add_pattern(
        self,
        cwe: str,
        title: str,
        description: str,
        patterns: list[str],
        language: str = "generic",
        persist: bool = False,
    ) -> None:
        """Add a CWE/CVE pattern to the knowledge base."""
        entry = {
            "cwe": cwe,
            "title": title,
            "description": description,
            "patterns": patterns,
            "language": language,
        }
        self._patterns.append(entry)
        self._built_tfidf = False
        self._built_faiss = False
        if persist and self._conn:
            self._conn.execute(
                """INSERT OR REPLACE INTO cwe_patterns(cwe, title, description, patterns, language)
                   VALUES(?, ?, ?, ?, ?)""",
                (cwe, title, description, json.dumps(patterns), language),
            )
            self._conn.commit()

    def load_from_file(self, path: Path, persist: bool = False) -> int:
        """Load patterns from a JSON file.

        Returns the number of patterns loaded.
        """
        with open(path) as f:
            data = json.load(f)
        count = 0
        if isinstance(data, list):
            for entry in data:
                self._patterns.append(entry)
                count += 1
        self._built_tfidf = False
        self._built_faiss = False
        if persist and self._conn:
            self._save_to_db()
        return count

    def add_patterns_from_corpus(self, entries: list[dict], persist: bool = False) -> int:
        """Bulk load patterns from a CVE corpus or CWE catalog.

        Each entry should have at minimum ``cwe`` and ``title``.  Optional
        keys: ``description``, ``patterns``, ``language``, ``severity_common``.

        Returns the number of patterns added.
        """
        count = 0
        for entry in entries:
            cwe = entry.get("cwe", "")
            if not cwe:
                continue
            pattern = {
                "cwe": cwe,
                "title": entry.get("title", ""),
                "description": entry.get("description", ""),
                "patterns": entry.get("patterns", []),
                "language": entry.get("language", "generic"),
            }
            self._patterns.append(pattern)
            count += 1
        self._built_tfidf = False
        self._built_faiss = False
        if persist and self._conn:
            self._save_to_db()
        return count

    def _build_index(self) -> None:
        """Build search index (TF-IDF or FAISS)."""
        if self._use_faiss:
            self._build_faiss_index()
        else:
            self._build_tfidf_index()

    def _build_tfidf_index(self) -> None:
        """Build TF-IDF index from patterns."""
        if not _HAS_SKLEARN:
            return
        if self._built_tfidf:
            return

        print(f"Building TF-IDF index for {len(self._patterns)} patterns...")
        docs = []
        for p in self._patterns:
            doc = f"{p['title']} {p['description']} {' '.join(p.get('patterns', []))}"
            docs.append(doc)

        self._vectorizer = TfidfVectorizer(
            stop_words="english",
            max_features=1000,
            ngram_range=(1, 2),
        )
        self._tfidf_matrix = self._vectorizer.fit_transform(docs)
        self._built_tfidf = True
        print(f"  TF-IDF index built: {self._tfidf_matrix.shape[1]} features, {len(self._patterns)} documents")

    def _build_faiss_index(self) -> None:
        """Build FAISS index from patterns."""
        if not _HAS_FAISS or self._faiss_model is None:
            self._build_tfidf_index()
            return
        if self._built_faiss:
            return

        # Try loading from disk first
        if self._db_path:
            index_path = Path(str(self._db_path)).with_suffix(".faiss")
            if index_path.exists():
                try:
                    self._faiss_index = faiss.read_index(str(index_path))
                    self._built_faiss = True
                    print(f"  Loaded FAISS index from {index_path}")
                    return
                except Exception:
                    pass

        # Build fresh index
        print(f"Building FAISS index for {len(self._patterns)} patterns...")
        texts = []
        for p in self._patterns:
            text = f"{p['title']} {p['description']} {' '.join(p.get('patterns', []))}"
            texts.append(text)

        # Encode in batches for progress reporting
        batch_size = 1000
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            embeddings = self._faiss_model.encode(batch, show_progress_bar=False)
            all_embeddings.append(embeddings)
            if (i // batch_size) % 10 == 0:
                print(f"  Encoded {min(i + batch_size, len(texts))}/{len(texts)} patterns...")

        self._faiss_embeddings = np.vstack(all_embeddings)
        embeddings_np = self._faiss_embeddings.astype("float32")

        dimension = embeddings_np.shape[1]
        faiss.normalize_L2(embeddings_np)
        self._faiss_index = faiss.IndexFlatIP(dimension)
        self._faiss_index.add(embeddings_np)
        self._built_faiss = True
        print(f"  FAISS index built: {dimension}d, {len(self._patterns)} vectors")

        # Save to disk
        if self._db_path:
            index_path = Path(str(self._db_path)).with_suffix(".faiss")
            try:
                faiss.write_index(self._faiss_index, str(index_path))
                print(f"  Saved FAISS index to {index_path}")
            except Exception:
                pass

    def search(self, query: str, top_k: int = 5, threshold: float = 0.1) -> list[dict]:
        """Search for matching CWE/CVE patterns.

        Uses FAISS when available, falls back to TF-IDF, then keyword matching.

        Parameters
        ----------
        query:
            Code snippet or description to search for.
        top_k:
            Maximum number of results to return.
        threshold:
            Minimum similarity score (0.0–1.0).

        Returns
        -------
        List of dicts with 'cwe', 'title', 'score', 'patterns' keys.
        """
        self._build_index()

        # Try FAISS first
        if self._use_faiss and self._faiss_index is not None and self._faiss_model is not None:
            return self._faiss_search(query, top_k, threshold)

        # Fall back to TF-IDF
        if _HAS_SKLEARN and self._vectorizer is not None and self._tfidf_matrix is not None:
            return self._tfidf_search(query, top_k, threshold)

        # Final fallback: keyword matching
        return self._keyword_search(query, top_k)

    def _faiss_search(self, query: str, top_k: int, threshold: float) -> list[dict]:
        """Search using FAISS index."""
        query_embedding = self._faiss_model.encode([query])
        query_np = np.array(query_embedding).astype("float32")
        faiss.normalize_L2(query_np)

        distances, indices = self._faiss_index.search(query_np, min(top_k, len(self._patterns)))

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < 0 or idx >= len(self._patterns):
                continue
            score = float(dist)  # Inner product = cosine after normalization
            if score >= threshold:
                results.append({
                    "cwe": self._patterns[idx]["cwe"],
                    "title": self._patterns[idx]["title"],
                    "score": round(score, 4),
                    "patterns": self._patterns[idx].get("patterns", []),
                    "language": self._patterns[idx].get("language", "generic"),
                    "backend": "faiss",
                })

        return results

    def _tfidf_search(self, query: str, top_k: int, threshold: float) -> list[dict]:
        """Search using TF-IDF index."""
        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._tfidf_matrix).flatten()

        results = []
        for idx in scores.argsort()[::-1][:top_k]:
            if scores[idx] >= threshold:
                results.append({
                    "cwe": self._patterns[idx]["cwe"],
                    "title": self._patterns[idx]["title"],
                    "score": round(float(scores[idx]), 4),
                    "patterns": self._patterns[idx].get("patterns", []),
                    "language": self._patterns[idx].get("language", "generic"),
                    "backend": "tfidf",
                })

        return results

    def _keyword_search(self, query: str, top_k: int) -> list[dict]:
        """Fallback keyword-based search when sklearn is not available."""
        query_lower = query.lower()
        results = []

        for p in self._patterns:
            score = 0.0
            text = f"{p['title']} {p['description']} {' '.join(p.get('patterns', []))}".lower()
            for keyword in query_lower.split():
                if keyword in text:
                    score += 0.2
            for pat in p.get("patterns", []):
                if pat.lower() in query_lower:
                    score += 0.3
            if score > 0:
                results.append({
                    "cwe": p["cwe"],
                    "title": p["title"],
                    "score": min(score, 1.0),
                    "patterns": p.get("patterns", []),
                    "language": p.get("language", "generic"),
                    "backend": "keyword",
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def get_pattern(self, cwe: str) -> dict | None:
        """Get a specific CWE pattern by ID."""
        for p in self._patterns:
            if p["cwe"] == cwe:
                return p
        return None

    def list_patterns(self) -> list[dict]:
        """List all patterns."""
        return list(self._patterns)

    @property
    def size(self) -> int:
        return len(self._patterns)

    def close(self) -> None:
        """Close database connection if open."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
