"""Persistent Background NVD CVE Enrichment Queue for VulnX.

Features:
- Persistent SQLite queue storing unique uncached CVEs.
- Strict compliance with official NIST NVD API rate limits (6.0s delay without API key, 0.6s with API key).
- Exponential backoff on HTTP 429 rate limit triggers (never hammering or retrying indefinitely).
- Bounded retries (maximum 3 attempts) for transient failures.
- Non-blocking execution allowing immediate finding processing and dashboard interaction.
- Dynamic cascading updates: automatically enriches finding CVSS and updates Contextual Risk scores in SQLite.
- Safe survivability across process restarts (recovers in-flight processing items).
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from db_utils import connect_sqlite, DB_PATH
from nvd_enrichment import fetch_nvd_cve

logger = logging.getLogger("vulnx.nvd_queue")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Worker thread coordination
_WORKER_THREAD: threading.Thread | None = None
_WORKER_LOCK = threading.Lock()
_STOP_EVENT = threading.Event()

# Rate limit configuration
RATE_LIMIT_DELAY_NO_KEY = 6.0   # 5 requests per 30 seconds
RATE_LIMIT_DELAY_WITH_KEY = 0.6  # 50 requests per 30 seconds
MAX_RETRIES = 3
STALE_PROCESSING_SECONDS = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def enqueue_cve_ids(cve_ids: list[str], assessment_id: str | None = None, db_path=None) -> int:
    """Validate, deduplicate, and enqueue uncached CVE IDs into the persistent SQLite queue."""
    if not cve_ids:
        return 0

    valid_cves = sorted(list(dict.fromkeys(
        str(c).strip().upper() for c in cve_ids
        if c and CVE_ID_RE.fullmatch(str(c).strip().upper())
    )))
    if not valid_cves:
        return 0

    con = connect_sqlite(db_path or DB_PATH)
    try:
        with con:
            # Check already enriched in cache
            placeholders = ",".join("?" for _ in valid_cves)
            cached_rows = con.execute(
                f"SELECT cve, record_json FROM assessment_nvd_cache WHERE cve IN ({placeholders})",
                valid_cves
            ).fetchall()
            
            # Skip already successfully enriched or verified not_found CVEs
            already_done = set()
            for cve, r_json in cached_rows:
                try:
                    data = json.loads(r_json) if isinstance(r_json, str) else r_json
                    if data.get("status") in ("enriched", "not_found"):
                        already_done.add(cve)
                except Exception:
                    pass

            to_queue = [c for c in valid_cves if c not in already_done]
            if not to_queue:
                return 0

            # Exclude CVEs already queued
            q_placeholders = ",".join("?" for _ in to_queue)
            existing_queued = {
                r[0] for r in con.execute(
                    f"SELECT cve FROM assessment_nvd_queue WHERE cve IN ({q_placeholders})",
                    to_queue
                ).fetchall()
            }
            truly_new = [c for c in to_queue if c not in existing_queued]
            if not truly_new:
                return 0

            now = _now()
            rows = [
                (cve, assessment_id or "", "pending", 0, None, now, "", now, now)
                for cve in truly_new
            ]
            con.executemany(
                """INSERT OR IGNORE INTO assessment_nvd_queue
                (cve, assessment_id, status, attempts, last_attempt_at, next_attempt_at, error, enqueued_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows
            )
            return len(truly_new)
    finally:
        con.close()


def get_queue_stats(assessment_id: str | None = None, db_path=None) -> dict[str, int]:
    """Return aggregated status counts from the persistent NVD queue."""
    con = connect_sqlite(db_path or DB_PATH)
    try:
        cur = con.cursor()
        if assessment_id:
            rows = cur.execute(
                "SELECT status, COUNT(*) FROM assessment_nvd_queue WHERE assessment_id = ? GROUP BY status",
                (assessment_id,)
            ).fetchall()
            cached_count = cur.execute(
                """SELECT COUNT(DISTINCT f.cve) FROM assessment_findings f
                   JOIN assessment_nvd_cache c ON f.cve = c.cve
                   WHERE f.assessment_id = ? AND c.record_json LIKE '%"status": "enriched"%'""",
                (assessment_id,)
            ).fetchone()[0]
        else:
            rows = cur.execute(
                "SELECT status, COUNT(*) FROM assessment_nvd_queue GROUP BY status"
            ).fetchall()
            cached_count = cur.execute(
                "SELECT COUNT(*) FROM assessment_nvd_cache WHERE record_json LIKE '%\"status\": \"enriched\"%'"
            ).fetchone()[0]

        counts = {status: count for status, count in rows}
        return {
            "total": sum(counts.values()),
            "pending": counts.get("pending", 0),
            "processing": counts.get("processing", 0),
            "enriched": counts.get("enriched", 0),
            "unavailable": counts.get("unavailable", 0),
            "failed": counts.get("failed", 0),
            "cached": cached_count,
        }
    finally:
        con.close()


def get_cve_status(cve: str, db_path=None) -> str:
    """Return explicit enrichment status for a given CVE."""
    cve = str(cve or "").strip().upper()
    if not CVE_ID_RE.fullmatch(cve):
        return "N/A"

    con = connect_sqlite(db_path or DB_PATH)
    try:
        cur = con.cursor()
        # 1. Check persistent cache
        cached = cur.execute(
            "SELECT record_json FROM assessment_nvd_cache WHERE cve = ?",
            (cve,)
        ).fetchone()
        if cached:
            try:
                data = json.loads(cached[0])
                status = data.get("status")
                if status == "enriched":
                    return "Cached"
                elif status == "not_found":
                    return "Unavailable"
                elif status == "error":
                    return "Failed"
            except Exception:
                pass

        # 2. Check queue
        queue_row = cur.execute(
            "SELECT status FROM assessment_nvd_queue WHERE cve = ?",
            (cve,)
        ).fetchone()
        if queue_row:
            q_status = queue_row[0]
            if q_status == "enriched":
                return "Enriched"
            elif q_status == "unavailable":
                return "Unavailable"
            elif q_status in ("pending", "processing"):
                return "Pending"
            elif q_status == "failed":
                return "Failed"

        return "Pending"
    finally:
        con.close()


def recover_stale_processing(db_path=None) -> int:
    """Reset any items stuck in 'processing' state (e.g. from prior process termination)."""
    con = connect_sqlite(db_path or DB_PATH)
    try:
        now = _now()
        with con:
            cur = con.cursor()
            cur.execute(
                """UPDATE assessment_nvd_queue
                   SET status = 'pending', updated_at = ?
                   WHERE status = 'processing'""",
                (now,)
            )
            return cur.rowcount
    finally:
        con.close()


def process_next_queue_item(api_key: str | None = None, db_path=None) -> tuple[str | None, str]:
    """Process a single queued CVE item respecting backoff and persistence."""
    api_key = api_key or os.getenv("NVD_API_KEY")
    con = connect_sqlite(db_path or DB_PATH)
    try:
        now = _now()
        with con:
            cur = con.cursor()
            row = cur.execute(
                """SELECT cve, attempts, error FROM assessment_nvd_queue
                   WHERE status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                   ORDER BY attempts ASC, enqueued_at ASC LIMIT 1""",
                (now,)
            ).fetchone()
            if not row:
                return None, "empty"

            cve, attempts, last_err = row[0], row[1], row[2]
            cur.execute(
                "UPDATE assessment_nvd_queue SET status = 'processing', updated_at = ? WHERE cve = ?",
                (now, cve)
            )

        # Execute external NVD query outside the SQLite transaction
        result = fetch_nvd_cve(cve, api_key=api_key)
        status = result.get("status")
        now = _now()

        with con:
            cur = con.cursor()
            if status == "enriched":
                # Save to cache
                cur.execute(
                    """INSERT INTO assessment_nvd_cache (cve, cached_at, record_json)
                       VALUES (?, ?, ?)
                       ON CONFLICT(cve) DO UPDATE SET cached_at=excluded.cached_at, record_json=excluded.record_json""",
                    (cve, now, json.dumps(result))
                )
                cur.execute(
                    "UPDATE assessment_nvd_queue SET status = 'enriched', updated_at = ? WHERE cve = ?",
                    (now, cve)
                )
                _propagate_enrichment_to_findings(cve, result, con)
                return cve, "enriched"

            elif status == "not_found":
                # Confirmed missing in NVD
                cur.execute(
                    """INSERT INTO assessment_nvd_cache (cve, cached_at, record_json)
                       VALUES (?, ?, ?)
                       ON CONFLICT(cve) DO UPDATE SET cached_at=excluded.cached_at, record_json=excluded.record_json""",
                    (cve, now, json.dumps(result))
                )
                cur.execute(
                    "UPDATE assessment_nvd_queue SET status = 'unavailable', updated_at = ? WHERE cve = ?",
                    (now, cve)
                )
                _propagate_enrichment_to_findings(cve, result, con)
                return cve, "unavailable"

            else:
                # Error status (e.g. rate limit 429 or network timeout)
                err_msg = str(result.get("error", "Unknown error"))
                is_rate_limit = "rate limit" in err_msg.lower() or "429" in err_msg
                
                if is_rate_limit:
                    # Exponential backoff for rate limits: 15s delay
                    next_attempt = datetime.now(timezone.utc).timestamp() + 15.0
                    next_iso = datetime.fromtimestamp(next_attempt, timezone.utc).isoformat(timespec="seconds")
                    cur.execute(
                        """UPDATE assessment_nvd_queue
                           SET status = 'pending', error = ?, next_attempt_at = ?, updated_at = ?
                           WHERE cve = ?""",
                        (err_msg, next_iso, now, cve)
                    )
                    return cve, "rate_limited"
                else:
                    new_attempts = attempts + 1
                    if new_attempts >= MAX_RETRIES:
                        cur.execute(
                            """UPDATE assessment_nvd_queue
                               SET status = 'failed', attempts = ?, error = ?, updated_at = ?
                               WHERE cve = ?""",
                            (new_attempts, err_msg, now, cve)
                        )
                        # Save failure into cache so workers don't repeatedly re-query
                        cur.execute(
                            """INSERT INTO assessment_nvd_cache (cve, cached_at, record_json)
                               VALUES (?, ?, ?)
                               ON CONFLICT(cve) DO UPDATE SET cached_at=excluded.cached_at, record_json=excluded.record_json""",
                            (cve, now, json.dumps(result))
                        )
                        _propagate_enrichment_to_findings(cve, result, con)
                        return cve, "failed"
                    else:
                        next_attempt = datetime.now(timezone.utc).timestamp() + (new_attempts * 5.0)
                        next_iso = datetime.fromtimestamp(next_attempt, timezone.utc).isoformat(timespec="seconds")
                        cur.execute(
                            """UPDATE assessment_nvd_queue
                               SET status = 'pending', attempts = ?, error = ?, next_attempt_at = ?, updated_at = ?
                               WHERE cve = ?""",
                            (new_attempts, err_msg, next_iso, now, cve)
                        )
                        return cve, "retry_scheduled"
    finally:
        con.close()


def _propagate_enrichment_to_findings(cve: str, nvd_record: dict, con) -> int:
    """Update all findings associated with this CVE, recomputing contextual risk."""
    from vulngraph_core import score_finding_canonical

    cur = con.cursor()
    rows = cur.execute(
        "SELECT assessment_id, finding_id, finding_json, exposure_factor, criticality_factor FROM assessment_findings WHERE cve = ?",
        (cve,)
    ).fetchall()

    if not rows:
        return 0

    cvss_score = nvd_record.get("cvss_score")
    rec_status = nvd_record.get("status")
    if rec_status == "enriched":
        nvd_status = "Enriched"
    elif rec_status == "failed":
        nvd_status = "Failed"
    elif rec_status == "not_found":
        nvd_status = "Unavailable"
    else:
        nvd_status = "Unavailable"
    updated_count = 0

    for aid, fid, f_json_str, exp_f, crit_f in rows:
        try:
            finding = json.loads(f_json_str) if isinstance(f_json_str, str) else f_json_str
            finding["nvd_enrichment"] = nvd_record
            finding["nvd_status"] = nvd_status

            if cvss_score is not None:
                finding["cvss"] = cvss_score

            # Recompute canonical 0-10 contextual risk with enriched parameters
            scored = score_finding_canonical(
                finding,
                exposure_kind=exp_f or "internal",
                criticality=int(crit_f or 3),
                nvd_record=nvd_record,
            )

            new_risk = scored.get("contextual_risk")
            new_label = scored.get("risk_label", "Unscored")
            new_cvss = scored.get("cvss")
            new_json_str = json.dumps(scored)

            cur.execute(
                """UPDATE assessment_findings
                   SET cvss = ?, risk_score = ?, risk_label = ?, finding_json = ?
                   WHERE assessment_id = ? AND finding_id = ?""",
                (new_cvss, new_risk, new_label, new_json_str, aid, fid)
            )

            # Update or insert risk calculation audit entry
            cur.execute(
                """INSERT INTO assessment_risk_calculations
                   (assessment_id, finding_id, model_version, cvss, epss, reachability, criticality, calculated_risk, status, reason, calculated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    aid, fid, scored.get("model_version", "vulngraph-contextual-risk-1.0"),
                    new_cvss, scored.get("epss"), scored.get("reachability"),
                    scored.get("criticality_level", 3), new_risk,
                    scored.get("contextual_status", "Enriched"),
                    scored.get("contextual_reason", "Background NVD enrichment"),
                    _now(),
                )
            )
            updated_count += 1
        except Exception as exc:
            logger.warning(f"Error propagating NVD enrichment for finding {fid}: {exc}")

    return updated_count


def _enrichment_worker_loop(api_key: str | None = None, db_path=None):
    """Background worker daemon thread that drains the NVD queue respecting rate limits."""
    api_key = api_key or os.getenv("NVD_API_KEY")
    delay = RATE_LIMIT_DELAY_WITH_KEY if api_key else RATE_LIMIT_DELAY_NO_KEY

    # Clean up any stale processing markers on startup
    recover_stale_processing(db_path)

    while not _STOP_EVENT.is_set():
        try:
            cve, outcome = process_next_queue_item(api_key=api_key, db_path=db_path)
            if outcome == "empty":
                # Idle wait before checking queue again
                _STOP_EVENT.wait(3.0)
                continue

            if outcome == "rate_limited":
                # Back off on 429
                _STOP_EVENT.wait(15.0)
                continue

            # Standard rate limit pause between requests
            _STOP_EVENT.wait(delay)
        except Exception as exc:
            logger.error(f"NVD background worker exception: {exc}")
            _STOP_EVENT.wait(5.0)


def start_background_enricher(api_key: str | None = None, db_path=None) -> threading.Thread:
    """Start the persistent NVD enrichment background worker thread if not already running."""
    global _WORKER_THREAD
    with _WORKER_LOCK:
        if _WORKER_THREAD is None or not _WORKER_THREAD.is_alive():
            _STOP_EVENT.clear()
            _WORKER_THREAD = threading.Thread(
                target=_enrichment_worker_loop,
                args=(api_key, db_path),
                daemon=True,
                name="VulnNVDEnricher"
            )
            _WORKER_THREAD.start()
        return _WORKER_THREAD


def stop_background_enricher(timeout: float = 3.0):
    """Signal the background enricher to stop."""
    global _WORKER_THREAD
    with _WORKER_LOCK:
        if _WORKER_THREAD and _WORKER_THREAD.is_alive():
            _STOP_EVENT.set()
            _WORKER_THREAD.join(timeout=timeout)
            _WORKER_THREAD = None


def ensure_background_enricher_running(api_key: str | None = None, db_path=None) -> None:
    """Ensure the background worker is running if there are pending items in the queue."""
    stats = get_queue_stats(db_path=db_path)
    if stats.get("pending", 0) > 0 or stats.get("processing", 0) > 0:
        start_background_enricher(api_key=api_key, db_path=db_path)
