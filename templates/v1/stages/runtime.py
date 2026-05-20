from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
from collections import Counter
from pathlib import Path


def split_model_pools(models: list[str]) -> tuple[list[str], list[str]]:
    hunt_preferred = [m for m in models if any(k in m for k in ('deepseek', 'qwen', 'gemma'))]
    validate_preferred = [m for m in models if any(k in m for k in ('nemotron', 'trinity', 'z-ai'))]

    hunt = hunt_preferred[:]
    validate = [m for m in validate_preferred if m not in hunt]

    for m in models:
        if m not in hunt and m not in validate:
            (hunt if len(hunt) <= len(validate) else validate).append(m)

    validate = [m for m in validate if m not in hunt]
    if not validate:
        validate = [m for m in models if m not in hunt]
    return hunt, validate


# ---------------------------------------------------------------------------
# Auth configuration
# ---------------------------------------------------------------------------

_AUTH_DEFAULT_PATHS = [
    lambda script_dir: script_dir / 'auth.json',
    lambda _script_dir: Path.home() / '.local/share/opencode/auth.json',
]

_PROVIDER_ENV_MAP = {
    'openrouter': 'OPENROUTER_API_KEY',
    'groq': 'GROQ_API_KEY',
    'cerebras': 'CEREBRAS_API_KEY',
    'google': 'GOOGLE_API_KEY',
    'zen': 'ZEN_API_KEY',
}


def load_auth_config(
    *,
    explicit_path: Path | None = None,
    script_dir: Path | None = None,
    skip_global_fallback: bool = False,
) -> dict[str, str]:
    """Load provider API keys into a flat ``{provider_name: key}`` dict.

    Resolution order (first non-empty value wins per provider):
    1. Environment variable (``OPENROUTER_API_KEY``, ``GROQ_API_KEY``, …)
    2. ``--auth-json`` CLI override (*explicit_path*)
    3. ``{script_dir}/auth.json`` (script-relative, default primary)
    4. ``~/.local/share/opencode/auth.json`` (global fallback)

    This matches **operating-default № 9**: auth files resolve relative to
    the script directory, not ``cwd``.
    """
    keys: dict[str, str] = {}

    # --- 1. File-based sources ---
    candidates: list[Path] = []
    if explicit_path is not None:
        candidates.append(explicit_path)
    if script_dir is not None:
        paths = _AUTH_DEFAULT_PATHS[:]
        if skip_global_fallback:
            paths = paths[:1]
        candidates.extend(fn(script_dir) for fn in paths)

    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        try:
            data = json.loads(resolved.read_text())
            if isinstance(data, dict):
                for provider in _PROVIDER_ENV_MAP:
                    val = data.get(provider) or data.get(f'{provider}_api_key')
                    if val and provider not in keys:
                        keys[provider] = str(val)
        except (json.JSONDecodeError, OSError):
            continue

    # --- 2. Environment variable override ---
    for provider, env_var in _PROVIDER_ENV_MAP.items():
        env_val = os.environ.get(env_var)
        if env_val:
            keys[provider] = env_val

    return keys


def cache_key(stage: str, model: str, text: str) -> str:
    h = hashlib.sha256(text.encode()).hexdigest()[:12]
    return f'{stage}:{model}:{h}'


class JsonCache:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.data = json.loads(self.path.read_text() or '{}')
        else:
            self.data = {}

    def get(self, key: str):
        return self.data.get(key)

    def put(self, key: str, value):
        self.data[key] = value
        self.path.write_text(json.dumps(self.data, indent=2))


class StateDB:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)')
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS tasks (
              task_id TEXT PRIMARY KEY,
              stage TEXT NOT NULL,
              status TEXT NOT NULL,
              payload TEXT NOT NULL
            )
            '''
        )
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS findings (
              finding_id TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              payload TEXT NOT NULL
            )
            '''
        )
        self.conn.commit()

    def put_meta(self, key: str, value: str):
        cur = self.conn.cursor()
        cur.execute('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', (key, value))
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        cur = self.conn.cursor()
        row = cur.execute('SELECT v FROM meta WHERE k=?', (key,)).fetchone()
        return row[0] if row else None


# ---------------------------------------------------------------------------
# Cross-run regression analysis (KL-divergence over class distributions)
# ---------------------------------------------------------------------------

def _smooth_counter(counter: Counter, vocab: set[str], alpha: float = 1.0) -> dict[str, float]:
    total = sum(counter.values()) + alpha * len(vocab)
    return {t: (counter.get(t, 0) + alpha) / total for t in vocab}


def _kl_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    d = 0.0
    for t, p_t in p.items():
        q_t = q.get(t, 0.0)
        if q_t == 0.0 and p_t > 0.0:
            return math.inf
        if p_t > 0.0:
            d += p_t * math.log(p_t / q_t)
    return d


def js_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Jensen-Shannon divergence — symmetric, bounded [0, log2]."""
    vocab = set(p.keys()) | set(q.keys())
    m = {t: (p.get(t, 0.0) + q.get(t, 0.0)) / 2.0 for t in vocab}
    return (_kl_divergence(p, m) + _kl_divergence(q, m)) / 2.0


def class_distribution(findings: list[dict]) -> Counter:
    """Count findings by vulnerability class.

    Falls back to ``class`` key, then ``attack_class``, then ``cwe_id``.
    """
    counts: Counter = Counter()
    for f in findings:
        cls = str(f.get('class') or f.get('attack_class') or f.get('cwe_id') or 'unknown').lower()
        counts[cls] += 1
    return counts


class CrossRunRegression:
    """Tracks historical run summaries and flags distributional drift
    via Jensen-Shannon divergence.

    Usage::

        history = CrossRunRegression(Path('output/run_history.jsonl'))
        history.record_run('2026-05-20T10:00:00Z', findings)
        drift = history.detect_drift(window=5, threshold=0.15)
        if drift:
            print(f'Drift detected: {drift}')
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load_history(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().strip().splitlines() if line.strip()]

    def _append_record(self, record: dict) -> None:
        with open(self.path, 'a') as f:
            f.write(json.dumps(record) + '\n')

    def record_run(self, timestamp: str, findings: list[dict], metadata: dict | None = None) -> dict:
        """Record a run's class distribution and return the saved record."""
        dist = class_distribution(findings)
        record = {
            'timestamp': timestamp,
            'total_findings': len(findings),
            'class_counts': dict(dist),
            'metadata': metadata or {},
        }
        self._append_record(record)
        return record

    def detect_drift(self, window: int = 5, threshold: float = 0.15) -> list[dict]:
        """Compare the most recent run against the previous *window* runs.

        Returns a list of drift signals, one per historical run compared.
        Each signal contains ``js_divergence``, ``vs_timestamp``, and
        ``changed_classes`` — the classes whose relative frequency shifted by
        more than 5 percentage points.

        A JS divergence > *threshold* indicates meaningful distributional
        drift — the model is behaving differently than before.
        """
        history = self._load_history()
        if len(history) < 2:
            return []

        current = history[-1]
        current_dist = _smooth_counter(
            Counter(current.get('class_counts', {})),
            set(current.get('class_counts', {}).keys()),
            alpha=1.0,
        )

        signals: list[dict] = []
        comparators = history[-min(window, len(history) - 1) - 1:-1]

        for prev in comparators:
            prev_dist = _smooth_counter(
                Counter(prev.get('class_counts', {})),
                set(current.get('class_counts', {}).keys())
                | set(prev.get('class_counts', {}).keys()),
                alpha=1.0,
            )

            js = js_divergence(current_dist, prev_dist)

            # Find classes whose share shifted by more than 5pp
            changed = []
            all_classes = set(current_dist.keys()) | set(prev_dist.keys())
            for cls in sorted(all_classes):
                cur_share = current_dist.get(cls, 0.0)
                prev_share = prev_dist.get(cls, 0.0)
                diff = cur_share - prev_share
                if abs(diff) > 0.05:
                    changed.append({
                        'class': cls,
                        'shift_pp': round(diff * 100, 1),
                        'current_share_pct': round(cur_share * 100, 1),
                        'prev_share_pct': round(prev_share * 100, 1),
                    })

            if js > threshold:
                signals.append({
                    'js_divergence': round(js, 4),
                    'vs_timestamp': prev.get('timestamp', 'unknown'),
                    'vs_total_findings': prev.get('total_findings', 0),
                    'current_total': current.get('total_findings', 0),
                    'changed_classes': changed,
                    'drifted': True,
                })

        return signals
