from __future__ import annotations

PIPELINE_STAGES = [
    'ingestor', 'recon', 'coordinator', 'hunt', 'validate',
    'voting', 'shield', 'chainer', 'poc', 'trace', 'report',
]

REQUIRED_FINDING_FIELDS = {
    'snippet_id',
    'severity',
    'class',
    'desc',
    'status',
    'poc_confirmed',
    'bucket_rationale',
}


def standardize_finding(finding: dict) -> dict:
    out = dict(finding)
    out.setdefault('status', 'raw')
    out.setdefault('poc_confirmed', False)
    out.setdefault('bucket_rationale', '')
    out.setdefault('call_path', [])
    return out


def validate_subset_schema(data, schema: dict, path: str = '$') -> list[str]:
    errors: list[str] = []
    expected_type = schema.get('type')
    if expected_type == 'object' and not isinstance(data, dict):
        errors.append(f'{path}: expected object')
        return errors
    if expected_type == 'array' and not isinstance(data, list):
        errors.append(f'{path}: expected array')
        return errors
    if expected_type == 'string' and not isinstance(data, str):
        errors.append(f'{path}: expected string')
        return errors
    if expected_type == 'boolean' and not isinstance(data, bool):
        errors.append(f'{path}: expected boolean')
        return errors

    enum = schema.get('enum')
    if enum is not None and data not in enum:
        errors.append(f'{path}: value not in enum {enum}')

    if isinstance(data, dict):
        for req in schema.get('required', []):
            if req not in data:
                errors.append(f'{path}: missing required field {req}')
        props = schema.get('properties', {})
        for k, v in data.items():
            if k in props:
                errors.extend(validate_subset_schema(v, props[k], f'{path}.{k}'))

    if isinstance(data, list):
        item_schema = schema.get('items')
        if item_schema:
            for i, item in enumerate(data):
                errors.extend(validate_subset_schema(item, item_schema, f'{path}[{i}]'))

    return errors


def apply_repair_turns(data, schema: dict, repair_fn=None, max_attempts: int = 2):
    current = data
    for _ in range(max_attempts + 1):
        errors = validate_subset_schema(current, schema)
        if not errors:
            return current, []
        if repair_fn is None:
            return current, errors
        current = repair_fn(current, errors)
    return current, validate_subset_schema(current, schema)
