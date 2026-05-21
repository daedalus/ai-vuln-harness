from __future__ import annotations

import json
import subprocess
import textwrap
from pathlib import Path

_C_FLAGS = ['-fsanitize=address', '-g', '-O0']

_LANGUAGE_EXT = {
    'c': '.c', 'cpp': '.cpp', 'go': '.go',
    'python': '.py', 'javascript': '.js', 'typescript': '.ts', 'rust': '.rs',
}

_LANGUAGE_RUNTIME = {
    'c':      {'compile': ['gcc', *_C_FLAGS, '{src}', '-o', '{bin}'], 'run': ['{bin}'], 'ext': '.bin'},
    'cpp':    {'compile': ['g++', *_C_FLAGS, '{src}', '-o', '{bin}'], 'run': ['{bin}'], 'ext': '.bin'},
    'rust':   {'compile': ['rustc', '{src}', '-o', '{bin}'], 'run': ['{bin}'], 'ext': '.bin'},
    'go':     {'compile': ['go', 'build', '-o', '{bin}', '{src}'], 'run': ['{bin}'], 'ext': '.bin'},
    'python': {'compile': None, 'run': ['python3', '{src}'], 'ext': '.py'},
    'javascript': {'compile': None, 'run': ['node', '{src}'], 'ext': '.js'},
    'typescript': {'compile': ['npx', 'tsc', '--outDir', '{outdir}', '{src}'], 'run': ['node', '{bin}'], 'ext': '.js'},
}


def _lang_from_snippet(snippet: dict) -> str:
    return snippet.get('language', 'c')


def _ext_for_lang(lang: str) -> str:
    return _LANGUAGE_EXT.get(lang, '.c')


def build_poc_json(finding: dict, snippet: dict) -> dict:
    lang = _lang_from_snippet(snippet)
    compiler_info = _LANGUAGE_RUNTIME.get(lang, _LANGUAGE_RUNTIME['c'])
    return {
        'schema_version': 'v1',
        'poc_id': f"poc-{finding.get('snippet_id', 'unknown')}-{finding.get('class', 'unknown')}",
        'finding': {
            'snippet_id': finding.get('snippet_id', ''),
            'class': finding.get('class', ''),
            'severity': finding.get('severity', 'LOW'),
            'desc': finding.get('desc', ''),
            'call_path': finding.get('call_path', []),
        },
        'harness': {
            'language': lang,
            'compiler': compiler_info.get('compile'),
            'runtime': compiler_info.get('run'),
            'source_file': '',
            'dependencies': [],
            'libraries': [],
        },
        'test_cases': [
            {
                'id': 'tc-1',
                'description': f"Reproduce {finding.get('class', 'vuln')} in {snippet.get('name', '?')}",
                'input': {},
                'expected': {'crash': True, 'error': True},
            }
        ],
        'result': {'status': 'incomplete', 'verdict': 'needs-more-info', 'reasoning': ''},
    }


def _autogen_source(finding: dict, snippet: dict) -> str:
    lang = _lang_from_snippet(snippet)
    content = (snippet.get('content') or '')
    func_name = snippet.get('name', 'target_func')
    header = f'/* PoC: {finding.get("desc", "finding")} in {func_name} */'

    if lang in ('c', 'cpp'):
        return textwrap.dedent(f"""\
        #include <stdlib.h>
        #include <string.h>
        #include <stdio.h>

        {header}
        {content}

        int main(void) {{
            fprintf(stderr, "Test completed\\n");
            return 0;
        }}
        """)

    if lang == 'python':
        return textwrap.dedent(f"""\
        import sys
        import os

        # {header}
        {textwrap.indent(content, '')}

        if __name__ == '__main__':
            sys.stderr.write("Test completed\\n")
        """)

    if lang == 'go':
        return textwrap.dedent(f"""\
        package main

        import "os"

        // {header}
        {content}

        func main() {{
            os.Stderr.WriteString("Test completed\\n")
        }}
        """)

    if lang == 'rust':
        return textwrap.dedent(f"""\
        use std::io::{{self, Write}};

        // {header}
        {content}

        fn main() {{
            let _ = writeln!(io::stderr(), "Test completed");
        }}
        """)

    if lang in ('javascript', 'typescript'):
        return textwrap.dedent(f"""\
        // {header}
        {content}

        console.error("Test completed");
        """)

    return content


def _source_ext(lang: str) -> str:
    return _LANGUAGE_EXT.get(lang, '.txt')


def _write_files(poc: dict, src: str, output_dir: Path) -> None:
    lang = poc['harness']['language']
    ext = _source_ext(lang)
    output_dir.mkdir(parents=True, exist_ok=True)
    src_file = output_dir / f"{poc['poc_id']}{ext}"
    json_file = output_dir / f"{poc['poc_id']}.json"
    src_file.write_text(src, encoding='utf-8')
    poc['harness']['source_file'] = str(src_file)
    json_file.write_text(json.dumps(poc, indent=2))


def _build(poc: dict, workdir: Path) -> tuple[bool, Path | None]:
    lang = poc['harness']['language']
    rt = _LANGUAGE_RUNTIME.get(lang)
    if rt is None or rt['compile'] is None:
        src_path = workdir / 'pocs' / f"{poc['poc_id']}{rt['ext']}" if rt else (workdir / 'pocs' / f"{poc['poc_id']}.txt")
        return True, src_path

    ext = rt['ext']
    src_path = workdir / 'pocs' / f"{poc['poc_id']}{_source_ext(lang)}"
    bin_path = workdir / 'pocs' / f"{poc['poc_id']}{ext}"
    if not src_path.exists():
        return False, None

    cmd = [part.replace('{src}', str(src_path)).replace('{bin}', str(bin_path)).replace('{outdir}', str(workdir / 'pocs')) for part in rt['compile']]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return False, None
    return True, bin_path


def _execute(target: Path, lang: str) -> dict:
    rt = _LANGUAGE_RUNTIME.get(lang, _LANGUAGE_RUNTIME['c'])
    cmd = [part.replace('{src}', str(target)).replace('{bin}', str(target)) for part in rt['run']]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {'status': 'execution_failed', 'exit_code': -1, 'stdout': '', 'stderr': 'timeout'}
    return {'status': 'completed', 'exit_code': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}


def process_findings(findings: list[dict], snippet_db: dict[str, dict], output_dir: Path, run: bool = True) -> list[dict]:
    results = []
    for f in findings:
        snippet = snippet_db.get(f.get('snippet_id', ''), {})
        poc = build_poc_json(f, snippet)
        src = _autogen_source(f, snippet)
        _write_files(poc, src, output_dir / 'pocs')

        if run:
            ok, target = _build(poc, output_dir)
            if not ok:
                poc['result'] = {'status': 'build_failed', 'verdict': 'needs-more-info', 'reasoning': 'build failed'}
            else:
                lang = poc['harness']['language']
                exec_result = _execute(target, lang)
                poc['result'] = {
                    'status': exec_result['status'],
                    'verdict': 'confirmed' if (exec_result.get('exit_code', 0) != 0 or 'ERROR' in exec_result.get('stderr', '')) else 'rejected',
                    'reasoning': f"exit={exec_result.get('exit_code')}, stderr={exec_result.get('stderr', '')[:200]}",
                }
                if poc['result']['verdict'] == 'confirmed':
                    f['poc_confirmed'] = True
            json_file = output_dir / 'pocs' / f"{poc['poc_id']}.json"
            json_file.write_text(json.dumps(poc, indent=2))
        results.append(poc)
    return results
