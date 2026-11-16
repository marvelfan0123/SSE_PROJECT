"""Read-only assessment progress projection for the Phase 2 UI."""
from datetime import datetime

FINAL = {'Completed', 'Failed', 'Skipped'}

def scanner_progress(assessment):
    """Calculate progress from persisted scanner states, without inventing scan percentages."""
    scanners = assessment.get('scanners') or []
    total = len(scanners)
    finished = sum(s.get('status') in FINAL for s in scanners)
    active = [s.get('scanner') for s in scanners if s.get('status') == 'Running']
    failed = [s.get('scanner') for s in scanners if s.get('status') == 'Failed']
    # This is scanner-task completion, not a time/byte completion estimate.
    percent = round(100 * finished / total) if total else 0
    return {'completed_tasks': finished, 'total_tasks': total,
            'percent': percent, 'active': active, 'failed': failed,
            'terminal': assessment.get('status') in {'Completed', 'Partial', 'Failed'}}

def scanner_timeline(assessment):
    rows=[]
    for scanner in assessment.get('scanners') or []:
        start, end = scanner.get('started_at'), scanner.get('completed_at')
        duration=None
        if start and end:
            try:
                duration=max(0, round((datetime.fromisoformat(end)-datetime.fromisoformat(start)).total_seconds(),1))
            except (ValueError, TypeError):
                pass
        rows.append({'Scanner': scanner.get('scanner','Unknown'),
                     'Status': scanner.get('status','Unknown'),
                     'Started': start or '—', 'Finished': end or '—',
                     'Duration (s)': duration, 'Details': scanner.get('message','')})
    return rows
