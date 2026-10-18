from prometheus_client import Counter, Gauge, Histogram

RUN_JOBS_CLAIMED = Counter("secmind_run_jobs_claimed_total", "Durable run jobs claimed by workers")
RUN_JOB_FAILURES = Counter("secmind_run_job_failures_total", "Recoverable worker execution failures")
RUN_JOB_DURATION = Histogram("secmind_run_job_duration_seconds", "Worker wall time per claimed run")
ACTIVE_RUNS = Gauge("secmind_active_runs", "Runs currently owned by this worker process")
TOOL_CALLS = Counter("secmind_tool_calls_total", "Tool calls by status", ["tool", "status"])
MODEL_REQUESTS = Counter("secmind_model_provider_requests_total", "Actual provider requests", ["model", "status"])
MODEL_TOKENS = Counter("secmind_model_tokens_total", "Provider token usage", ["model", "direction"])
OUTBOX_PENDING = Gauge("secmind_outbox_pending", "Unprojected transactional outbox events")
