"""Prometheus metrics for the SOC2 Dashboard."""
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, REGISTRY

# HTTP request counters
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests by method, path, and status",
    ["method", "endpoint", "status"],
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Agent / scanner run counters
agent_runs_total = Counter(
    "agent_runs_total",
    "Total agent executions by agent name and result",
    ["agent", "result"],
)

# Compliance business metrics
controls_pass = Gauge("compliance_controls_pass_total", "Controls currently PASS")
controls_fail = Gauge("compliance_controls_fail_total", "Controls currently FAIL")
evidence_records_total = Gauge("compliance_evidence_records_total", "Total evidence records in local DB")

# SSE client gauge
sse_clients_connected = Gauge("sse_clients_connected", "Currently connected SSE clients")

# Celery task metrics
celery_tasks_enqueued_total = Counter(
    "celery_tasks_enqueued_total",
    "Total Celery tasks enqueued by task name",
    ["task"],
)
celery_tasks_failed_total = Counter(
    "celery_tasks_failed_total",
    "Total Celery task failures by task name",
    ["task"],
)
