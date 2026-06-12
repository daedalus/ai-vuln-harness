"""RAG Knowledge Base for CWE/CVE vulnerability patterns.

Provides semantic matching of code snippets against known vulnerability patterns
using TF-IDF similarity. No external vector database required — uses sklearn's
TfidfVectorizer for lightweight, dependency-minimal similarity search.

Reference: DeepAudit's RAG knowledge base (CWE/CVE via ChromaDB).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False


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

    Uses TF-IDF for lightweight semantic similarity search without
    requiring external vector databases.
    """

    def __init__(self) -> None:
        self._patterns: list[dict] = list(_DEFAULT_CWE_PATTERNS)
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._built = False

    def add_pattern(
        self,
        cwe: str,
        title: str,
        description: str,
        patterns: list[str],
        language: str = "generic",
    ) -> None:
        """Add a CWE/CVE pattern to the knowledge base."""
        self._patterns.append({
            "cwe": cwe,
            "title": title,
            "description": description,
            "patterns": patterns,
            "language": language,
        })
        self._built = False

    def load_from_file(self, path: Path) -> int:
        """Load patterns from a JSON file.

        Returns the number of patterns loaded.
        """
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            for entry in data:
                self._patterns.append(entry)
        self._built = False
        return len(data) if isinstance(data, list) else 0

    def _build_index(self) -> None:
        """Build TF-IDF index from patterns."""
        if not _HAS_SKLEARN:
            return
        if self._built:
            return

        # Combine description + patterns into a single document per CWE
        docs = []
        for p in self._patterns:
            doc = f"{p['title']} {p['description']} {' '.join(p.get('patterns', []))}"
            docs.append(doc)

        self._vectorizer = TfidfVectorizer(
            stop_words="english",
            max_features=1000,
            ngram_range=(1, 2),
        )
        self._matrix = self._vectorizer.fit_transform(docs)
        self._built = True

    def search(self, query: str, top_k: int = 5, threshold: float = 0.1) -> list[dict]:
        """Search for matching CWE/CVE patterns.

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
        if not _HAS_SKLEARN:
            # Fallback: keyword matching
            return self._keyword_search(query, top_k)

        self._build_index()
        if self._vectorizer is None or self._matrix is None:
            return self._keyword_search(query, top_k)

        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix).flatten()

        results = []
        for idx in scores.argsort()[::-1][:top_k]:
            if scores[idx] >= threshold:
                results.append({
                    "cwe": self._patterns[idx]["cwe"],
                    "title": self._patterns[idx]["title"],
                    "score": round(float(scores[idx]), 4),
                    "patterns": self._patterns[idx].get("patterns", []),
                    "language": self._patterns[idx].get("language", "generic"),
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
