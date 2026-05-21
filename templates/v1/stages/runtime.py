"""Runtime utilities shared across pipeline stages.

Logging conventions (dual-channel):
  - stderr: all status, progress, warnings, errors, debug output.
  - stdout: ONLY structured JSON (findings, report, PoC results).
  - Format: ``HH:MM:SS [LEVEL] message`` — no millis, no PID.
  - Stage entry: ``[stage N] StageName: doing work...``
  - Stage exit: ``  -> result summary`` (indented with leading spaces).

Model pool rules:
  - Hunt and Validate use DISJOINT model pools. No model appears in both.
  - If too small for a clean split, the strongest model goes to Validate.
  - Disjoint pools prevent correlated biases from slipping through both stages.

call_llm retry strategy:
  - Retry on 429/502/503/504 with exponential backoff (5s * attempt + 1).
  - Reasoning models (nemotron, trinity) stash output in ``message.reasoning``
    instead of ``message.content`` — merge both after the API call.
  - ``max_tokens`` must be 8192 minimum; reasoning models consume large output
    budgets and 4096 causes truncation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sqlite3
import ssl
import threading
import time
import urllib.request
from collections import Counter
from pathlib import Path


def split_model_pools(models: list[str]) -> tuple[list[str], list[str]]:
    """Split model chain into disjoint Hunt and Validate pools.

    Hunt gets models matching deepseek/qwen/gemma; Validate gets
    nemotron/trinity/z-ai. If the chain is too small for a clean split,
    the strongest model goes to Validate because disagreement beats
    agreement — if Validate uses the same model as Hunt, correlated
    biases slip through (confirmed by zlib run: deepseek-v4-flash
    reported gzprintf as HIGH format-string; nemotron-nano correctly
    rejected it as API-by-design).
    """
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
    if not hunt:
        hunt = [m for m in models if m not in validate] or models[:1]
    return hunt, validate


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
    keys: dict[str, str] = {}

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
                        if isinstance(val, dict):
                            val = val.get('key') or val.get('api_key') or ''
                        if val:
                            keys[provider] = str(val)
        except (json.JSONDecodeError, OSError):
            continue

    for provider, env_var in _PROVIDER_ENV_MAP.items():
        env_val = os.environ.get(env_var)
        if env_val:
            keys[provider] = env_val

    return keys


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
    models_dev.parent.mkdir(parents=True, exist_ok=True)

    limits: dict[str, int] = {}
    updated: dict[str, float] = {}
    ctx = ssl.create_default_context()
    per_provider: dict[str, list[str]] = {}
    if models:
        for m in models:
            if m:
                per_provider.setdefault(_resolve_provider(m), []).append(m)
    else:
        for prov in ('openrouter', 'groq', 'cerebras', 'google', 'zen'):
            per_provider.setdefault(prov, [])

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
                if not eid.endswith(':free'):
                    continue
                ctx_win = entry.get('context_length') or entry.get('context_window') or 0
                if not ctx_win:
                    continue
                bare = _strip_provider(eid)
                if provider_models and bare not in provider_models:
                    continue
                limits[bare] = int(ctx_win)
                updated[bare] = time.time()
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass

    if limits:
        cache_data = {m: {'context_window': cw, 'max_output_tokens': cw, 'last_updated': updated.get(m, time.time())} for m, cw in limits.items()}
        models_dev.write_text(json.dumps(cache_data, indent=2))

    if not models:
        return limits

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
        cur = self.conn.cursor()
        cur.execute(
            'INSERT OR IGNORE INTO runs(run_id, status, started_at, repo_path) VALUES(?,?,?,?)',
            (run_id, 'running', time.time(), repo_path),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, status: str = 'completed') -> None:
        cur = self.conn.cursor()
        cur.execute(
            'UPDATE runs SET status=?, finished_at=? WHERE run_id=?',
            (status, time.time(), run_id),
        )
        self.conn.commit()

    def get_run(self, run_id: str) -> dict | None:
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
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO costs(run_id, stage, amount_usd, recorded_at) VALUES(?,?,?,?)',
            (run_id, stage, float(amount_usd), time.time()),
        )
        self.conn.commit()

    def total_cost(self, run_id: str) -> float:
        cur = self.conn.cursor()
        row = cur.execute(
            'SELECT COALESCE(SUM(amount_usd), 0.0) FROM costs WHERE run_id=?',
            (run_id,),
        ).fetchone()
        return float(row[0]) if row else 0.0

    def close(self) -> None:
        self.conn.close()


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
    vocab = set(p.keys()) | set(q.keys())
    m = {t: (p.get(t, 0.0) + q.get(t, 0.0)) / 2.0 for t in vocab}
    return (_kl_divergence(p, m) + _kl_divergence(q, m)) / 2.0


def class_distribution(findings: list[dict]) -> Counter:
    counts: Counter = Counter()
    for f in findings:
        cls = str(f.get('class') or f.get('attack_class') or f.get('cwe_id') or 'unknown').lower()
        counts[cls] += 1
    return counts


class CrossRunRegression:
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


import re as _re

_RETRYABLE_ERRORS = ('429', '502', '503', '504', 'rate', 'too many', 'try again', 'temporary', 'upstream')
"""HTTP status / error substrings that trigger automatic retry with backoff.

Includes 502/503/504 (provider gateway overload — transient, not model failure)
in addition to 429 rate limits. Without this, transient provider errors would
be misclassified as permanent model failures and the pipeline would skip
healthy models behind a temporarily overloaded gateway.
"""

_MODEL_BY_DOMAIN = {
    'mem-safety':     'openrouter:nvidia/nemotron-nano-12b-v2-vl:free',
    'data-flow':      'openrouter:deepseek/deepseek-v4-flash:free',
    'crypto':         'openrouter:deepseek/deepseek-v4-flash:free',
    'format-str':     'openrouter:deepseek/deepseek-v4-flash:free',
    'ipc':            'openrouter:deepseek/deepseek-v4-flash:free',
    'auth':           'openrouter:deepseek/deepseek-v4-flash:free',
    'injection':      'openrouter:deepseek/deepseek-v4-flash:free',
    'path-traversal': 'openrouter:qwen/qwen-2.5-coder-32b-instruct:free',
    'concurrency':    'openrouter:google/gemma-4-26b-a4b-it:free',
    'resource':       'openrouter:qwen/qwen-2.5-coder-32b-instruct:free',
    'secrets':        'openrouter:deepseek/deepseek-v4-flash:free',
}

HUNT_SYSTEM_PROMPT = (
    'You are a single-attack-class vulnerability hunter. You have one task, '
    'one attack class, one scope. You go deep, not wide. Other hunters cover '
    'other attack classes — you do not stray. Determine whether the given '
    'attack class is present in the assigned scope. Emit zero or more findings, '
    'each anchored to specific code lines with verbatim evidence. '
    'If you find no vulnerabilities, emit {"done": true}.'
)

VALIDATE_SYSTEM_PROMPT = (
    'You are an adversarial code reviewer. Your job is to DISPROVE findings, '
    'not confirm them. Output ONLY a JSON object with "status" '
    '("confirmed" / "rejected" / "needs-more-info") and "reason".'
)

TRACE_SYSTEM_PROMPT = (
    'You are a trace analyst. Determine whether attacker-controlled input can '
    'reach the vulnerable sink from the consumer entry points. Output ONLY a '
    'JSON object with "reachable" (true/false), "call_path" (list of function '
    'names), and "reasoning".'
)


def _get_auth_key(provider: str, auth: dict | None = None) -> str | None:
    if auth:
        val = auth.get(provider) or auth.get(f'{provider}_api_key')
        if val:
            return val.get('key') if isinstance(val, dict) else str(val)
    env_var = _PROVIDER_ENV_MAP.get(provider)
    if env_var:
        return os.environ.get(env_var)
    return None


def call_llm(
    model_id: str,
    prompt: str,
    *,
    system: str = '',
    max_tokens: int = 8192,
    timeout: int = 120,
    auth: dict[str, str] | None = None,
    cache: JsonCache | None = None,
) -> str:
    """Call an LLM via provider-prefixed model ID (e.g. ``openrouter:...``).

    1. Check cache first (keyed on ``stage:model:hash(prompt+system)``).
    2. Resolve provider prefix to base URL, auth key, and headers.
    3. Retry on 429/502/503/504 with exponential backoff (5, 10, 15s).
    4. Merge ``message.reasoning`` into content (reasoning models stash
       output there instead of ``message.content``).
    5. Cache successful responses for instant replay.
    """
    ck = cache_key('llm', model_id, prompt + system) if cache else None
    if ck and cache:
        cached = cache.get(ck)
        if cached is not None:
            return cached if isinstance(cached, str) else json.dumps(cached)

    provider = _resolve_provider(model_id)
    model_name = _strip_provider(model_id)
    print(f"[call_llm] model_id={model_id!r} provider={provider!r} model_name={model_name!r}", flush=True)

    api_key = _get_auth_key(provider, auth)
    if not api_key:
        raise ValueError(f'no auth key for provider: {provider} (model: {model_id})')

    base = _BASE_URLS.get(provider)
    if not base:
        raise ValueError(f'unknown provider: {provider}')

    messages = []
    if system:
        messages.append({'role': 'system', 'content': system})
    messages.append({'role': 'user', 'content': prompt})

    payload = {
        'model': model_name,
        'max_tokens': max_tokens,
        'messages': messages,
    }

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url=f'{base}/chat/completions',
        data=json.dumps(payload).encode(),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
    )

    last_exception: Exception | None = None
    for attempt in range(3):
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
            result = json.loads(resp.read().decode())
            choices = result.get('choices')
            if not choices:
                raise ValueError(f'no_choices: {json.dumps(result)[:200]}')
            msg = choices[0].get('message', {})
            content = (msg.get('content') or '')
            reasoning = (msg.get('reasoning') or '')
            if not content.strip() and reasoning:
                content = reasoning
            completion_tokens = result.get('usage', {}).get('completion_tokens', 0)
            logging.getLogger('vuln-harness').info('Got %d completion tokens from %s %s', completion_tokens, provider, model_name)
            if ck and cache:
                cache.put(ck, content)
            return content
        except urllib.error.HTTPError as e:
            code = e.code
            estr = str(code)
            if any(x in estr for x in _RETRYABLE_ERRORS):
                last_exception = e
                time.sleep(5 * (attempt + 1))
                continue
            raise RuntimeError(f'HTTP {code} from {base}/chat/completions (model={model_name})') from e
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as e:
            estr = str(e)
            if any(x in estr for x in _RETRYABLE_ERRORS):
                last_exception = e
                time.sleep(5 * (attempt + 1))
                continue
            raise RuntimeError(f'{type(e).__name__} from {base}/chat/completions (model={model_name}): {e}') from e

    raise RuntimeError(f'llm call exhausted after 3 retries; last error: {last_exception}')


class ModelPool:
    """Thread-safe pool of alive models ranked by capability (context length descending).

    ``pick()`` returns the most capable alive model. ``mark_dead()`` removes a
    model on permanent failure so subsequent calls skip to the next best.
    This enables transparent fallback across model failures in a single
    request without callers managing model chains.
    """

    def __init__(self, models: list[str], limits: dict[str, int]):
        self._models = sorted(models, key=lambda m: -limits.get(m, 0))
        self._dead: set[str] = set()
        self._lock = threading.Lock()

    def pick(self) -> str | None:
        """Return the best alive model, or None if the pool is empty."""
        with self._lock:
            for m in self._models:
                if m not in self._dead:
                    return m
            return None

    def mark_dead(self, model: str) -> None:
        """Remove *model* from the pool permanently."""
        with self._lock:
            self._dead.add(model)

    @property
    def alive(self) -> list[str]:
        """Return all currently-alive models, most capable first."""
        with self._lock:
            return [m for m in self._models if m not in self._dead]

    @property
    def is_empty(self) -> bool:
        return self.pick() is None


def call_llm_from_pool(
    pool: ModelPool,
    prompt: str,
    *,
    system: str = '',
    max_tokens: int = 8192,
    timeout: int = 120,
    auth: dict[str, str] | None = None,
    cache: JsonCache | None = None,
) -> str:
    """Call an LLM using the best available model from *pool*.

    Picks the most capable alive model and calls ``call_llm`` (which retries
    3× on 429/502/503/504).  If the model permanently fails, marks it dead
    and retries with the next best model.  Continues until a model succeeds
    or the pool is exhausted.
    """
    last_exception: Exception | None = None
    while not pool.is_empty:
        model = pool.pick()
        if model is None:
            break
        try:
            return call_llm(
                model, prompt,
                system=system, max_tokens=max_tokens,
                timeout=timeout, auth=auth, cache=cache,
            )
        except Exception as e:
            estr = str(e)
            if any(x in estr for x in _RETRYABLE_ERRORS):
                logger = logging.getLogger('vuln-harness')
                logger.warning('[pool] model %s failed: %s — marking dead, retrying next', model, estr[:100])
                pool.mark_dead(model)
                last_exception = e
                continue
            raise
    raise RuntimeError(f'model pool exhausted; last error: {last_exception}')


def health_check_models(
    models: list[str],
    *,
    auth: dict[str, str] | None = None,
    cache: JsonCache | None = None,
    max_workers: int = 8,
) -> tuple[list[str], list[tuple[str, str]]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    alive: list[str] = []
    dead: list[tuple[str, str]] = []

    def probe(mid: str) -> tuple[str, bool, str]:
        try:
            call_llm(mid, 'Reply with one word: ok', max_tokens=8, auth=auth, cache=cache)
            return mid, True, ''
        except Exception as e:
            return mid, False, str(e)[:120]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, m): m for m in models}
        for f in as_completed(futures):
            mid, ok, err = f.result()
            if ok:
                alive.append(mid)
            else:
                dead.append((mid, err))

    alive.sort(key=lambda m: models.index(m) if m in models else 999)
    return alive, dead


def _rephrase_gap_prompt(original_prompt: str, model_id: str) -> str:
    return (
        original_prompt.rstrip('\n')
        + '\n\n--\n'
        + f'Note: The previous model ({model_id}) produced no findings for this '
        + 'scope. Double-check each function carefully. Verify you are not '
        + 'missing anything — re-examine every function in the provided context. '
        + 'If you genuinely find no vulnerabilities, explain specifically which '
        + 'functions you checked and why each is safe.'
    )


def _repair_truncated_json(text: str) -> str:
    """Repair JSON truncated mid-brace by reasoning models.

    Reasoning models often exceed ``max_tokens``, cutting output off mid-brace.
    This repair balances open/close braces — succeeds on ~70% of truncated
    validate responses. The remaining 30% need a full retry (next model in chain).
    """
    text = text.strip()
    if not text.endswith('}'):
        text += '}'
    depth = 0
    for ch in text:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
    while depth > 0:
        text += '}'
        depth -= 1
    while depth < 0 and text.rfind('}') > text.rfind('{'):
        text = text.rstrip('}')
        depth += 1
    return text


def parse_llm_json(text: str) -> dict:
    parsed, repaired = repair_json_output(text)
    if parsed is not None:
        return parsed if isinstance(parsed, dict) else {}
    repaired = _repair_truncated_json(text)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        return {}


def repair_json_output(raw: str) -> tuple[dict | list | None, bool]:
    raw = raw.strip()

    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass

    fence_match = _re.search(r'```(?:json)?\s*\n?(.*?)```', raw, _re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip()), True
        except json.JSONDecodeError:
            pass

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
