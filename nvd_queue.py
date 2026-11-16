"""Root-level wrapper for core.nvd_queue."""
from core.nvd_queue import (
    enqueue_cve_ids,
    get_queue_stats,
    get_cve_status,
    recover_stale_processing,
    process_next_queue_item,
    start_background_enricher,
    stop_background_enricher,
    ensure_background_enricher_running,
)

__all__ = [
    "enqueue_cve_ids",
    "get_queue_stats",
    "get_cve_status",
    "recover_stale_processing",
    "process_next_queue_item",
    "start_background_enricher",
    "stop_background_enricher",
    "ensure_background_enricher_running",
]

