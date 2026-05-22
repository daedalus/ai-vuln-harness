# Evaluation & Regression (v1)

## Required KPIs

- `precision_at_top_n`
- `reject_rate`
- `duplicate_rate`
- `gap_closure_rate`
- `time_cost_per_stage`

## Benchmark corpus

Create and version a benchmark corpus with:
- known-true vulnerabilities
- known-false positive patterns (including API-by-design cases)
- representative library and application targets

## Regression gate

Any prompt/model/stage change must run benchmark evaluation and show no KPI regression against baseline.
