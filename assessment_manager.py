"""Assessment-scoped orchestration and persistence for VulnX: Scanning and Vulnerability Management Platform.

The Streamlit process launches assessment_worker as a detached worker process. Each
assessment owns its scanner statuses, normalized findings, asset entities, and
evidence graphs, ensuring complete assessment isolation and survivability across restarts.
"""
from __future__ import annotations
import json, os, sqlite3, subprocess, sys, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from db_utils import connect_sqlite, initialize_all_tables, DB_PATH
from system_reset import reset_all_assessment_data, get_assessment_data_summary

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "assessment_reports"


def _json_value(value, default):
    if value is None or value == "":
        return default
    return json.loads(value)


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@contextmanager
def _db():
    con = connect_sqlite(DB_PATH)
    try:
        with con:
            yield con
    finally:
        con.close()


def initialize():
    initialize_all_tables(DB_PATH)


def find_recent_active_assessment(created_by: str, target_name: str, within_seconds: int = 8) -> str | None:
    """Return an existing assessment_id if the same user queued/started the same target within `within_seconds`."""
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT assessment_id, created_at, status FROM assessments WHERE created_by=? AND target_name=? AND status IN ('Queued','Running','Discovering assets','Processing findings') ORDER BY created_at DESC LIMIT 1",
            (created_by, target_name),
        ).fetchall()
    for r in rows:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(r["created_at"])).total_seconds()
            if 0 <= age <= within_seconds:
                return r["assessment_id"]
        except (ValueError, TypeError):
            continue
    return None


def create_assessment(created_by: str, target_type: str, target: dict, criticality: str = "Normal") -> str:
    initialize()
    assessment_id = "VX-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6].upper()
    now = _now()
    with _db() as con:
        con.execute(
            """INSERT INTO assessments 
            (assessment_id, created_at, updated_at, created_by, target_type, target_name, target_json, criticality, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (assessment_id, now, now, created_by, target_type, target.get("name", "Target"), json.dumps(target), criticality, "Queued")
        )
        for scanner, state, message in target.get("scanner_plan", []):
            con.execute(
                "INSERT INTO assessment_scanners (assessment_id, scanner, status, message) VALUES (?, ?, ?, ?)",
                (assessment_id, scanner, state, message)
            )
    return assessment_id


def update_assessment(assessment_id, status=None, error=None, stage=None, worker_pid=None, heartbeat=False):
    initialize()
    with _db() as con:
        fields = []
        values = []
        if status is not None:
            fields.append("status=?")
            values.append(status)
        if error is not None:
            fields.append("error=?")
            values.append(error)
        if stage is not None:
            fields.append("stage=?")
            values.append(stage)
        if worker_pid is not None:
            fields.append("worker_pid=?")
            values.append(int(worker_pid))
        if heartbeat:
            fields.append("heartbeat_at=?")
            values.append(_now())
        if fields:
            fields.append("updated_at=?")
            values.append(_now())
            values.append(assessment_id)
            con.execute(f"UPDATE assessments SET {','.join(fields)} WHERE assessment_id=?", values)


def record_worker_heartbeat(assessment_id: str, pid: int | None = None, stage: str | None = None) -> None:
    """Update worker heartbeat timestamp and optional PID/stage."""
    update_assessment(assessment_id, stage=stage, worker_pid=pid, heartbeat=True)


def is_worker_alive(pid: int | None) -> bool:
    """Return True if a worker OS process with the given PID is currently running."""
    if not pid or int(pid) <= 0:
        return False
    pid = int(pid)
    if os.name == "nt":
        try:
            res = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
                capture_output=True, text=True, timeout=5, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return f'"{pid}"' in (res.stdout or "")
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def update_scanner(assessment_id, scanner, status, message="", result=None):
    initialize()
    now = _now()
    with _db() as con:
        row = con.execute("SELECT started_at FROM assessment_scanners WHERE assessment_id=? AND scanner=?", (assessment_id, scanner)).fetchone()
        started = row[0] if row else None
        if status == "Running":
            started = now
            count = con.execute("SELECT COALESCE(MAX(attempt),0)+1 FROM assessment_attempts WHERE assessment_id=? AND scanner=?", (assessment_id, scanner)).fetchone()[0]
            con.execute("INSERT INTO assessment_attempts(assessment_id, scanner, attempt, started_at, status) VALUES(?,?,?,?,?)", (assessment_id, scanner, count, now, "Running"))
        completed = now if status in {"Completed", "Failed", "Skipped"} else None
        con.execute(
            "UPDATE assessment_scanners SET status=?, started_at=COALESCE(started_at, ?), completed_at=COALESCE(?, completed_at), message=?, result_json=? WHERE assessment_id=? AND scanner=?",
            (status, started, completed, message, json.dumps(result or {}), assessment_id, scanner)
        )
        if status in {"Completed", "Failed", "Skipped"}:
            con.execute(
                "UPDATE assessment_attempts SET finished_at=?, status=?, message=? WHERE assessment_id=? AND scanner=? AND attempt=(SELECT MAX(attempt) FROM assessment_attempts WHERE assessment_id=? AND scanner=?) AND status='Running'",
                (now, status, message, assessment_id, scanner, assessment_id, scanner)
            )
        con.execute("UPDATE assessments SET updated_at=? WHERE assessment_id=?", (now, assessment_id))


def get_assessment(assessment_id):
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["target"] = _json_value(item.pop("target_json"), {})
        scanners = con.execute("SELECT * FROM assessment_scanners WHERE assessment_id=? ORDER BY rowid", (assessment_id,)).fetchall()
        item["scanners"] = [dict(x) | {"result": _json_value(x["result_json"], {})} for x in scanners]
        findings = con.execute("SELECT finding_json FROM assessment_findings WHERE assessment_id=? ORDER BY risk_score DESC", (assessment_id,)).fetchall()
        raw_findings = [_json_value(x[0], {}) for x in findings]
        from vulngraph_core import MODEL_VERSION, score_finding_canonical
        exp_kind = item["target"].get("exposure_kind", "internal")
        crit_kind = item.get("criticality", "Normal")
        migrated_findings = []
        for f in raw_findings:
            r_score = f.get("risk_score")
            m_ver = str(f.get("model_version") or "")
            if (isinstance(r_score, (int, float)) and not isinstance(r_score, bool) and r_score > 10.0) or m_ver.startswith("vulnx-"):
                migrated_findings.append(score_finding_canonical(f, exposure_kind=exp_kind, criticality=crit_kind))
            else:
                migrated_findings.append(f)
        item["findings"] = migrated_findings
        attempts = con.execute("SELECT * FROM assessment_attempts WHERE assessment_id=? ORDER BY scanner,attempt", (assessment_id,)).fetchall()
        item["attempts"] = [dict(x) for x in attempts]
        
        # Load asset entities
        hosts = con.execute("SELECT host_ip, hostname, state, details_json FROM assessment_hosts WHERE assessment_id=?", (assessment_id,)).fetchall()
        ports = con.execute("SELECT host_ip, port, protocol, state FROM assessment_ports WHERE assessment_id=?", (assessment_id,)).fetchall()
        services = con.execute("SELECT host_ip, port, service_name, product, version FROM assessment_services WHERE assessment_id=?", (assessment_id,)).fetchall()
        images = con.execute("SELECT image_name, image_id, digest, container_id FROM assessment_images WHERE assessment_id=?", (assessment_id,)).fetchall()
        deps = con.execute("SELECT image_name, package, version, fixed_version, ecosystem FROM assessment_dependencies WHERE assessment_id=?", (assessment_id,)).fetchall()
        
        item["hosts"] = [dict(h) for h in hosts]
        item["ports"] = [dict(p) for p in ports]
        item["services"] = [dict(s) for s in services]
        item["images"] = [dict(img) for img in images]
        item["dependencies"] = [dict(d) for d in deps]
        vg_containers = con.execute("SELECT container_json FROM vg_containers WHERE assessment_id=?", (assessment_id,)).fetchall()
        item["containers"] = [_json_value(c[0], {}) for c in vg_containers]
        
        return item


def list_assessments(limit=50):
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT assessment_id, created_at, updated_at, created_by, target_type, target_name, criticality, status, stage, error FROM assessments ORDER BY created_at DESC LIMIT ?",
            (int(limit),)
        ).fetchall()
    return [dict(x) for x in rows]


def get_nvd_cache_sqlite():
    initialize()
    with _db() as con:
        rows = con.execute("SELECT cve, record_json FROM assessment_nvd_cache").fetchall()
    return {cve: _json_value(payload, {}) for cve, payload in rows}


def put_nvd_cache_sqlite(records):
    initialize()
    if not records:
        return
    now = _now()
    rows = [
        (cve, now, json.dumps(record) if not isinstance(record, str) else record)
        for cve, record in records.items()
    ]
    with _db() as con:
        con.executemany(
            "INSERT INTO assessment_nvd_cache(cve, cached_at, record_json) VALUES(?, ?, ?) ON CONFLICT(cve) DO UPDATE SET cached_at=excluded.cached_at, record_json=excluded.record_json",
            rows
        )


def save_findings(assessment_id, findings):
    initialize()
    if not findings:
        return
    rows = [
        (
            assessment_id,
            f.get("finding_id"),
            f.get("source", ""),
            f.get("finding_type", ""),
            f.get("severity", "UNKNOWN"),
            f.get("title", ""),
            f.get("asset", ""),
            f.get("cve", ""),
            f.get("package", ""),
            f.get("cvss"),
            f.get("exposure_factor"),
            f.get("criticality_factor"),
            f.get("risk_score"),
            f.get("risk_label", "Unscored"),
            json.dumps(f) if not isinstance(f.get("finding_json"), str) else f["finding_json"]
        )
        for f in findings
    ]
    with _db() as con:
        con.executemany(
            """INSERT OR REPLACE INTO assessment_findings
            (assessment_id, finding_id, source, finding_type, severity, title, asset, cve, package, cvss, exposure_factor, criticality_factor, risk_score, risk_label, finding_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )


def replace_source_findings(assessment_id, source, findings):
    """Atomically replace findings for one successfully retried scanner."""
    initialize()
    rows = [
        (
            assessment_id,
            f.get("finding_id"),
            f.get("source", ""),
            f.get("finding_type", ""),
            f.get("severity", "UNKNOWN"),
            f.get("title", ""),
            f.get("asset", ""),
            f.get("cve", ""),
            f.get("package", ""),
            f.get("cvss"),
            f.get("exposure_factor"),
            f.get("criticality_factor"),
            f.get("risk_score"),
            f.get("risk_label", "Unscored"),
            json.dumps(f) if not isinstance(f.get("finding_json"), str) else f["finding_json"]
        )
        for f in findings
    ]
    with _db() as con:
        con.execute("DELETE FROM assessment_findings WHERE assessment_id=? AND source=?", (assessment_id, source))
        if rows:
            con.executemany(
                """INSERT OR REPLACE INTO assessment_findings
                (assessment_id, finding_id, source, finding_type, severity, title, asset, cve, package, cvss, exposure_factor, criticality_factor, risk_score, risk_label, finding_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows
            )


def save_discovered_assets(assessment_id, hosts=None, ports=None, services=None, images=None, dependencies=None, containers=None):
    """Persist normalized asset entities for this assessment."""
    initialize()
    now = _now()
    with _db() as con:
        if hosts is not None:
            con.execute("DELETE FROM assessment_hosts WHERE assessment_id=?", (assessment_id,))
            if hosts:
                con.executemany(
                    "INSERT INTO assessment_hosts (assessment_id, host_ip, hostname, state, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    [(assessment_id, h.get("host_ip", "127.0.0.1"), h.get("hostname", ""), h.get("state", "up"), json.dumps(h.get("details", {})), now) for h in hosts]
                )
        if ports is not None:
            con.execute("DELETE FROM assessment_ports WHERE assessment_id=?", (assessment_id,))
            if ports:
                con.executemany(
                    "INSERT INTO assessment_ports (assessment_id, host_ip, port, protocol, state) VALUES (?, ?, ?, ?, ?)",
                    [(assessment_id, p.get("host_ip", "127.0.0.1"), int(p.get("port", 0)), p.get("protocol", "tcp"), p.get("state", "open")) for p in ports]
                )
        if services is not None:
            con.execute("DELETE FROM assessment_services WHERE assessment_id=?", (assessment_id,))
            if services:
                con.executemany(
                    "INSERT INTO assessment_services (assessment_id, host_ip, port, service_name, product, version) VALUES (?, ?, ?, ?, ?, ?)",
                    [(assessment_id, s.get("host_ip", "127.0.0.1"), int(s.get("port", 0)), s.get("service_name", "unknown"), s.get("product", ""), s.get("version", "")) for s in services]
                )
        if images is not None:
            con.execute("DELETE FROM assessment_images WHERE assessment_id=?", (assessment_id,))
            if images:
                con.executemany(
                    "INSERT INTO assessment_images (assessment_id, image_name, image_id, digest, container_id) VALUES (?, ?, ?, ?, ?)",
                    [(assessment_id, img.get("image_name", ""), img.get("image_id", ""), img.get("digest", ""), img.get("container_id", "")) for img in images]
                )
        if dependencies is not None:
            con.execute("DELETE FROM assessment_dependencies WHERE assessment_id=?", (assessment_id,))
            if dependencies:
                con.executemany(
                    "INSERT INTO assessment_dependencies (assessment_id, image_name, package, version, fixed_version, ecosystem) VALUES (?, ?, ?, ?, ?, ?)",
                    [(assessment_id, d.get("image_name", ""), d.get("package", ""), d.get("version", ""), d.get("fixed_version", ""), d.get("ecosystem", "")) for d in dependencies]
                )


def save_risk_calculations(assessment_id, calculations):
    """Persist audit records for contextual risk calculations."""
    initialize()
    if not calculations:
        return
    now = _now()
    rows = [
        (
            assessment_id, c.get("finding_id", ""), c.get("model_version", "vulngraph-contextual-risk-1.0"),
            c.get("cvss"), c.get("epss"), c.get("reachability"), c.get("criticality"),
            c.get("calculated_risk"), c.get("status", ""), c.get("reason", ""), now
        )
        for c in calculations
    ]
    with _db() as con:
        con.executemany(
            """INSERT INTO assessment_risk_calculations
            (assessment_id, finding_id, model_version, cvss, epss, reachability, criticality, calculated_risk, status, reason, calculated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )


def retry_failed_scanners(assessment_id, actor):
    """Queue only failed scanners; completed results remain intact."""
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        record = con.execute("SELECT status, created_by FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
        if not record or record["status"] not in {"Failed", "Partial"}:
            raise ValueError("Only finished failed/partial assessments can be retried")
        if actor != record["created_by"] and actor != "admin":
            raise PermissionError("Assessment owner or administrator required")
        failed = [r[0] for r in con.execute("SELECT scanner FROM assessment_scanners WHERE assessment_id=? AND status='Failed'", (assessment_id,)).fetchall()]
        if not failed:
            raise ValueError("No failed scanners to retry")
        for scanner in failed:
            con.execute("UPDATE assessment_scanners SET status='Pending', started_at=NULL, completed_at=NULL, message='Queued for retry', result_json='{}' WHERE assessment_id=? AND scanner=?", (assessment_id, scanner))
        con.execute("UPDATE assessments SET status='Queued', stage='Retry queued', error='', updated_at=? WHERE assessment_id=?", (_now(), assessment_id))
    return failed


def recover_interrupted_assessment(assessment_id, actor, min_age_seconds=600):
    """Manual stale-job recovery; never interrupt a recently active worker."""
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT status, created_by, updated_at FROM assessments WHERE assessment_id=?", (assessment_id,)).fetchone()
        if not row or row['status'] not in {'Queued', 'Running', 'Discovering assets', 'Processing findings'}:
            raise ValueError('Assessment is not in an interruptible state')
        if actor != row['created_by'] and actor != 'admin':
            raise PermissionError('Assessment owner or administrator required')
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(row['updated_at'])).total_seconds()
        if age < min_age_seconds:
            raise ValueError('Assessment was updated recently; recovery is not yet safe')
        active = con.execute("SELECT scanner FROM assessment_scanners WHERE assessment_id=? AND status IN ('Running','Pending')", (assessment_id,)).fetchall()
        if not active:
            raise ValueError('No interrupted scanner tasks found')
        for r in active:
            con.execute("UPDATE assessment_scanners SET status='Failed', completed_at=?, message='Interrupted: eligible for retry' WHERE assessment_id=? AND scanner=?", (_now(), assessment_id, r[0]))
            con.execute("UPDATE assessment_attempts SET status='Failed', finished_at=?, message='Worker interrupted' WHERE assessment_id=? AND scanner=? AND status='Running'", (_now(), assessment_id, r[0]))
        successes = con.execute("SELECT COUNT(*) FROM assessment_scanners WHERE assessment_id=? AND status='Completed'", (assessment_id,)).fetchone()[0]
        con.execute("UPDATE assessments SET status=?, stage='Interrupted — retry available', error='Worker interruption detected', updated_at=? WHERE assessment_id=?", ('Partial' if successes else 'Failed', _now(), assessment_id))
    return [r[0] for r in active]


def cancel_assessment(assessment_id: str, actor: str) -> dict:
    """Cancel an active or queued assessment, terminate its worker if running, and preserve partial results."""
    initialize()
    with _db() as con:
        con.row_factory = sqlite3.Row
        row = con.execute(
            "SELECT status, created_by, worker_pid FROM assessments WHERE assessment_id=?",
            (assessment_id,),
        ).fetchone()
        if not row or row["status"] not in {"Queued", "Running", "Discovering assets", "Processing findings"}:
            raise ValueError("Assessment is not in an active or cancellable state")
        if actor != row["created_by"] and actor != "admin":
            raise PermissionError("Assessment owner or administrator required")

        pid = row["worker_pid"]
        if pid and is_worker_alive(pid):
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(int(pid))],
                        capture_output=True, timeout=5, check=False,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                else:
                    os.kill(int(pid), 15)
            except Exception:
                pass

        now = _now()
        active_scanners = [
            r[0] for r in con.execute(
                "SELECT scanner FROM assessment_scanners WHERE assessment_id=? AND status IN ('Pending','Running')",
                (assessment_id,),
            ).fetchall()
        ]
        for scanner in active_scanners:
            con.execute(
                "UPDATE assessment_scanners SET status='Failed', completed_at=?, message='Cancelled by operator' WHERE assessment_id=? AND scanner=?",
                (now, assessment_id, scanner),
            )
            con.execute(
                "UPDATE assessment_attempts SET status='Failed', finished_at=?, message='Cancelled by operator' WHERE assessment_id=? AND scanner=? AND status='Running'",
                (now, assessment_id, scanner),
            )
        completed_count = con.execute(
            "SELECT COUNT(*) FROM assessment_scanners WHERE assessment_id=? AND status='Completed'",
            (assessment_id,),
        ).fetchone()[0]
        findings_count = con.execute(
            "SELECT COUNT(*) FROM assessment_findings WHERE assessment_id=?",
            (assessment_id,),
        ).fetchone()[0]
        final_status = "Partial" if (completed_count > 0 or findings_count > 0) else "Failed"
        con.execute(
            "UPDATE assessments SET status=?, stage='Cancelled by operator', error='Cancelled by operator', updated_at=? WHERE assessment_id=?",
            (final_status, now, assessment_id),
        )
    return {"assessment_id": assessment_id, "status": final_status, "cancelled_scanners": active_scanners}


def launch_worker(assessment_id):
    initialize()
    existing = get_assessment(assessment_id)
    if existing and existing.get("status") in {"Running", "Discovering assets", "Processing findings"}:
        pid = existing.get("worker_pid")
        if pid and is_worker_alive(pid):
            return int(pid)
    log_path = REPORT_DIR / f"{assessment_id}-worker.log"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    kwargs = {"cwd": str(BASE_DIR), "stdin": subprocess.DEVNULL, "stderr": subprocess.STDOUT, "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    else:
        kwargs["start_new_session"] = True
    with open(log_path, "a", encoding="utf-8") as log_handle:
        process = subprocess.Popen([sys.executable, str(BASE_DIR / "assessment_worker.py"), assessment_id],
                                   stdout=log_handle, **kwargs)
    update_assessment(assessment_id, worker_pid=process.pid, heartbeat=True)
    return process.pid


def discover_container(container_id):
    """Read Docker inspect metadata for a selected running local container."""
    import shutil
    if not shutil.which("docker"):
        raise RuntimeError("Docker CLI was not found on PATH.")
    result = subprocess.run([shutil.which("docker"), "inspect", str(container_id)], capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=15, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Docker inspect failed")[:400])
    raw_output = result.stdout or ""
    if not raw_output.strip():
        detail = (result.stderr or "Docker inspect returned empty output.").strip()
        raise RuntimeError(f"Could not read Docker container metadata: {detail[:300]}")
    parsed = json.loads(raw_output)
    if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
        raise RuntimeError("Docker inspect returned an unexpected JSON structure.")
    data = parsed[0]
    published = []
    for container_port, bindings in ((data.get("NetworkSettings") or {}).get("Ports") or {}).items():
        for binding in bindings or []:
            host_ip = binding.get("HostIp") or ""
            try:
                host_port = int(binding.get("HostPort"))
            except (TypeError, ValueError):
                continue
            if host_ip in {"127.0.0.1", "0.0.0.0", "::", "::1", ""}:
                published.append({"container_port": container_port, "host_ip": host_ip, "host_port": host_port})
    return {
        "container_id": str(container_id),
        "name": (data.get("Name") or "").lstrip("/"),
        "image": (data.get("Config") or {}).get("Image") or data.get("Image") or "",
        "state": (data.get("State") or {}).get("Status", "unknown"),
        "published": published,
        "networks": sorted(((data.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
    }


def save_vg_evidence(assessment_id, containers, relationships, classifications):
    """Atomic assessment-specific evidence update."""
    initialize()
    with _db() as db:
        for table in ('vg_containers', 'vg_asset_relationships', 'vg_owasp_classifications'):
            db.execute(f'DELETE FROM {table} WHERE assessment_id=?', (assessment_id,))
        if containers:
            db.executemany('INSERT INTO vg_containers VALUES (?,?,?)', [(assessment_id, c['container_id'], json.dumps(c)) for c in containers])
        if relationships:
            db.executemany('INSERT INTO vg_asset_relationships VALUES (?,?,?)', [(assessment_id, r['relationship_id'], json.dumps(r)) for r in relationships])
        if classifications:
            db.executemany('INSERT INTO vg_owasp_classifications VALUES (?,?,?)', [(assessment_id, item['finding_id'], json.dumps(item)) for item in classifications])


def load_vg_evidence(assessment_id):
    initialize()
    with _db() as db:
        result = {}
        for key, table in [('containers', 'vg_containers'), ('relationships', 'vg_asset_relationships'), ('classifications', 'vg_owasp_classifications')]:
            result[key] = [json.loads(row[0]) for row in db.execute(f'SELECT {"container_json" if key=="containers" else "relationship_json" if key=="relationships" else "classification_json"} FROM {table} WHERE assessment_id=?', (assessment_id,))]
        return result
