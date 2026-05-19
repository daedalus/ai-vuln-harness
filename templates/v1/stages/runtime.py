from __future__ import annotations

import hashlib
import json
import sqlite3
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
