from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import ssl
import time
import urllib.request
from collections import Counter
from pathlib import Path


def split_model_pools(models: list[str]) -> tuple[list[str], list[str]]:
    models = list(dict.fromkeys(models))
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


# ---------------------------------------------------------------------------
# Model limits from /v1/models or models.dev cache
# ---------------------------------------------------------------------------

_MODELS_DEV_PATH = 'config/models.dev'

_BASE_URLS = {
    'openrouter': 'https://openrouter.ai/api/v1',
    'groq': 'https://api.groq.com/openai/v1',
    'cerebras': 'https://api.cerebras.ai/v1',
    'google': 'https://generativelanguage.googleapis.com/v1beta/openai',
    'zen': 'https://opencode.ai/zen/v1',
}


_KNOWN_PROVIDERS = frozenset({'openrouter', 'groq', 'cerebras', 'google', 'zen'})


def _resolve_provider(model_id: str) -> str:
    prov, _, _ = model_id.partition(':')
    return prov if prov in _KNOWN_PROVIDERS else 'openrouter'


def _strip_provider(model_id: str) -> str:
    prov, sep, rest = model_id.partition(':')
    return rest if prov in _KNOWN_PROVIDERS and sep else model_id


def fetch_model_limits(models: list[str], script_dir: Path) -> dict[str, int]:
    models_dev = script_dir / _MODELS_DEV_PATH

    if models_dev.exists():
        cache = json.loads(models_dev.read_text())
        now = time.time()
        good = {k: v for k, v in cache.items()
                if now - v.get('last_updated', 0) < 86400 * 7}
        if all(m in good for m in models if m):
            return {m: good[m]['context_window'] for m in models if m}
    else:
        cache = {}
        models_dev.parent.mkdir(parents=True, exist_ok=True)

    limits: dict[str, int] = {}
    updated: dict[str, float] = {}
    ctx = ssl.create_default_context()
    per_provider: dict[str, list[str]] = {}
    for m in models:
        if m:
            per_provider.setdefault(_resolve_provider(m), []).append(m)

    for provider, provider_models in per_provider.items():
        base = _BASE_URLS.get(provider)
        if not base:
            continue
        try:
            req = urllib.request.Request(f'{base}/models')
            resp = urllib.request.urlopen(req, context=ctx, timeout=15)
            data = json.loads(resp.read().decode())
            for entry in data.get('data', []):
                eid = entry.get('id', '')
                ctx_win = entry.get('context_length') or entry.get('context_window') or 0
                bare = _strip_provider(eid)
                if bare in provider_models and ctx_win:
                    limits[bare] = int(ctx_win)
                    updated[bare] = time.time()
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass

    if limits:
        cache.update({
            mid: {
                'context_window': cw,
                'max_output_tokens': cw,
                'last_updated': updated.get(mid, time.time()),
            }
            for mid, cw in limits.items()
        })
        models_dev.write_text(json.dumps(cache, indent=2))

    fallback = {m: limits[m] for m in models if m and m in limits}
    missing = [m for m in models if m and m not in fallback]
    if missing and models_dev.exists():
        cache_data = json.loads(models_dev.read_text())
        for m in missing:
            if m in cache_data:
                fallback[m] = cache_data[m]['context_window']

    if not fallback:
        fallback = {m: 128_000 for m in models if m}
    return fallback


def cache_key(stage: str, model: str, text: str) -> str:
    h = hashlib.sha256(text.encode()).hexdigest()[:12]
    return f'{stage}:{model}:{h}'


class JsonCache:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raw = json.loads(self.path.read_text() or '{}')
            self.data = raw if isinstance(raw, dict) else {}
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
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS runs (
              run_id TEXT PRIMARY KEY,
              status TEXT NOT NULL DEFAULT 'running',
              started_at REAL NOT NULL,
              finished_at REAL,
              repo_path TEXT
            )
            '''
        )
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS costs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              run_id TEXT NOT NULL,
              stage TEXT NOT NULL,
              amount_usd REAL NOT NULL,
              recorded_at REAL NOT NULL
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

    def create_run(self, repo_path: str, run_id: str) -> None:
        """Register a new pipeline run.  Idempotent (INSERT OR IGNORE)."""
        cur = self.conn.cursor()
        cur.execute(
            'INSERT OR IGNORE INTO runs(run_id, status, started_at, repo_path) VALUES(?,?,?,?)',
            (run_id, 'running', time.time(), repo_path),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, status: str = 'completed') -> None:
        """Mark a run as finished with the given *status* (e.g. 'completed', 'aborted', 'failed')."""
        cur = self.conn.cursor()
        cur.execute(
            'UPDATE runs SET status=?, finished_at=? WHERE run_id=?',
            (status, time.time(), run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> dict | None:
        """Return run metadata or ``None`` if the run_id is unknown."""
        cur = self.conn.cursor()
        row = cur.execute(
            'SELECT run_id, status, started_at, finished_at, repo_path FROM runs WHERE run_id=?',
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            'run_id': row[0],
            'status': row[1],
            'started_at': row[2],
            'finished_at': row[3],
            'repo_path': row[4],
        }

    def record_cost(self, run_id: str, stage: str, amount_usd: float) -> None:
        """Append a cost entry for *run_id* / *stage*.

        Multiple calls per stage are allowed (e.g. one per Hunt task) — they
        accumulate so that ``total_cost`` reflects the full spend.
        """
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO costs(run_id, stage, amount_usd, recorded_at) VALUES(?,?,?,?)',
            (run_id, stage, float(amount_usd), time.time()),
        )
        self.conn.commit()

    def total_cost(self, run_id: str) -> float:
        """Return the sum of all recorded cost entries for *run_id* in USD."""
        cur = self.conn.cursor()
        row = cur.execute(
            'SELECT COALESCE(SUM(amount_usd), 0.0) FROM costs WHERE run_id=?',
            (run_id,),
        ).fetchone()
        return float(row[0]) if row else 0.0

    def close(self) -> None:
        self.conn.close()


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
        records = []
        for line in self.path.read_text().strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

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


# ---------------------------------------------------------------------------
# Schema repair utility
# ---------------------------------------------------------------------------

import re as _re


def repair_json_output(raw: str) -> tuple[dict | list | None, bool]:
    """Attempt to parse JSON from a raw model output string.

    Returns ``(parsed, was_repaired)`` where *was_repaired* is ``True`` when
    the raw string needed extraction (e.g., the model wrapped its JSON in a
    markdown code fence or prefixed it with explanatory prose).

    Repair strategy (first successful pass wins):

    1. Direct ``json.loads`` — fast path for well-formed output.
    2. Strip ````json … ```` or ```` ``` … ```` markdown fences.
    3. Extract the first balanced ``{ … }`` or ``[ … ]`` block.

    Returns ``(None, False)`` when all three passes fail.
    """
    raw = raw.strip()

    # Pass 1: direct parse
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass

    # Pass 2: strip code fences
    fence_match = _re.search(r'```(?:json)?\s*\n?(.*?)```', raw, _re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip()), True
        except json.JSONDecodeError:
            pass

    # Pass 3: extract first balanced JSON object or array
    for opener, closer in [('{', '}'), ('[', ']')]:
        idx = raw.find(opener)
        if idx == -1:
            continue
        depth = 0
        for i in range(idx, len(raw)):
            if raw[i] == opener:
                depth += 1
            elif raw[i] == closer:
                depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[idx:i + 1]), True
                except json.JSONDecodeError:
                    break

    return None, False
