"""Phase 5: deterministic, assessment-scoped analytics and safe report exports."""
from __future__ import annotations
from security_controls import csv_cell
from collections import Counter
from datetime import datetime, timezone
import csv
import html
import io
import json

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
FINISHED = {'Completed', 'Partial'}


def _vulnerability(f):
    return f.get('is_vulnerability') is not False and f.get('source') != 'Nmap' and f.get('finding_type') != 'network_exposure_observation'


def build_snapshot(assessment, tickets=()):
    if not assessment or assessment.get('status') not in FINISHED:
        raise ValueError('Reports require a completed or partial assessment')
    findings = list(assessment.get('findings') or [])
    vulnerabilities = [f for f in findings if _vulnerability(f)]
    exposures = [f for f in findings if not _vulnerability(f)]
    severity = Counter(str(f.get('severity') or 'UNKNOWN').upper() for f in vulnerabilities)
    severity_counts = {level: severity[level] for level in SEVERITIES}
    scanners = [{'scanner': str(s.get('scanner') or ''), 'status': str(s.get('status') or ''),
                 'message': str(s.get('message') or '')} for s in assessment.get('scanners') or []]
    scores = [float(f['risk_score']) for f in vulnerabilities if isinstance(f.get('risk_score'), (int, float)) and not isinstance(f.get('risk_score'), bool)]
    statuses = Counter(str(t.get('status') or 'Unknown') for t in tickets)
    assets = sorted({str(f.get('asset')).strip() for f in findings if f.get('asset')})
    incomplete = [s['scanner'] for s in scanners if s['status'] != 'Completed']
    return {
        'assessment_id': str(assessment.get('assessment_id') or ''),
        'target': str(assessment.get('target_name') or ''),
        'created_at': assessment.get('created_at'), 'status': assessment['status'],
        'metrics': {'vulnerabilities': len(vulnerabilities), 'exposure_observations': len(exposures),
                    'assets_observed': len(assets), 'average_risk': round(sum(scores)/len(scores), 2) if scores else None,
                    'scored_vulnerabilities': len(scores), 'unscored_vulnerabilities': len(vulnerabilities)},
        'severity': severity_counts, 'scanners': scanners, 'assets': assets,
        'scanner_coverage_complete': assessment['status'] == 'Completed' and not incomplete,
        'incomplete_scanners': incomplete,
        'remediation': {'total_tickets': len(tickets), 'by_status': dict(sorted(statuses.items())),
                        'resolved': statuses['Resolved'], 'unresolved': len(tickets)-statuses['Resolved']},
        'top_findings': sorted([{'finding_id': str(f.get('finding_id') or ''), 'asset': str(f.get('asset') or ''),
                                  'title': str(f.get('title') or ''), 'severity': str(f.get('severity') or 'UNKNOWN'),
                                  'risk_score': f.get('risk_score'), 'cve': str(f.get('cve') or '')}
                                 for f in vulnerabilities], key=lambda x: (x['risk_score'] is not None, x['risk_score'] or 0), reverse=True)[:20],
        'limitations': ['A scan does not prove absence of vulnerabilities.',
                        'Open ports are exposure observations, not confirmed vulnerabilities.',
                        'Incomplete scanner coverage limits conclusions.' if incomplete or assessment['status'] == 'Partial' else 'Scanner success does not imply complete vulnerability coverage.',
                        'Remediation resolution requires independent verification.']}


def build_trend(assessments):
    """Only caller-authorized records for one explicitly selected target identity."""
    if not assessments:
        return []
    target_type = assessments[0].get('target_type')
    target_name = assessments[0].get('target_name')
    rows = []
    for assessment in assessments:
        if assessment.get('target_type') != target_type or assessment.get('target_name') != target_name:
            raise ValueError('Trend records must share target name and type')
        if assessment.get('status') not in FINISHED:
            continue
        snap = build_snapshot(assessment)
        rows.append({'assessment_id': snap['assessment_id'], 'created_at': snap['created_at'],
                     'status': snap['status'], 'vulnerabilities': snap['metrics']['vulnerabilities'],
                     'critical': snap['severity']['CRITICAL'], 'high': snap['severity']['HIGH'],
                     'average_risk': snap['metrics']['average_risk'],
                     'scanner_coverage_complete': snap['scanner_coverage_complete']})
    return sorted(rows, key=lambda x: (str(x['created_at'] or ''), x['assessment_id']))


def export_json(snapshot, trend=()):
    return json.dumps({'schema_version': 'phase5-v1', 'generated_at': datetime.now(timezone.utc).isoformat(),
                       'snapshot': snapshot, 'trend': list(trend)}, indent=2, ensure_ascii=False, default=str)


def _csv_safe(value):
    return csv_cell(value)


def export_csv(snapshot):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=['finding_id', 'asset', 'title', 'severity', 'risk_score', 'cve'])
    writer.writeheader()
    writer.writerows([{key: _csv_safe(value) for key, value in row.items()} for row in snapshot['top_findings']])
    return out.getvalue()


def export_trend_csv(trend):
    out = io.StringIO(newline='')
    fields = ['assessment_id', 'created_at', 'status', 'vulnerabilities', 'critical', 'high', 'average_risk', 'scanner_coverage_complete']
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    writer.writerows([{key: csv_cell(value) for key, value in row.items()} for row in trend])
    return out.getvalue()


def export_html(snapshot):
    """Self-contained, printable HTML. Escape all scanner/user-provided strings."""
    esc = lambda value: html.escape(str(value if value is not None else ''), quote=True)
    sev = ''.join(f'<tr><td>{esc(k)}</td><td>{v}</td></tr>' for k,v in snapshot['severity'].items())
    coverage = ''.join(f'<tr><td>{esc(s["scanner"])}</td><td>{esc(s["status"])}</td></tr>' for s in snapshot['scanners'])
    findings = ''.join('<tr>' + ''.join(f'<td>{esc(f.get(k))}</td>' for k in ('severity','title','asset','cve','risk_score')) + '</tr>' for f in snapshot['top_findings'])
    limitations = ''.join(f'<li>{esc(x)}</li>' for x in snapshot['limitations'])
    metrics = snapshot['metrics']
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>VulnX Assessment {esc(snapshot["assessment_id"])} | Scanning and Vulnerability Management Platform</title>'
            '<style>body{font:15px Arial,sans-serif;max-width:950px;margin:32px auto;color:#17263a}h1{color:#164f80}table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #ccd5df;padding:8px;text-align:left}th{background:#eef3f8}.warning{padding:12px;background:#fff4da}@media print{body{margin:15mm}}</style></head><body>'
            f'<h1>VulnX — Scanning and Vulnerability Management Platform</h1><p><b>Assessment:</b> {esc(snapshot["assessment_id"])}<br><b>Target:</b> {esc(snapshot["target"])}<br><b>Status:</b> {esc(snapshot["status"])}</p>'
            f'<p><b>Confirmed vulnerability findings:</b> {metrics["vulnerabilities"]} &nbsp; <b>Exposure observations:</b> {metrics["exposure_observations"]} &nbsp; <b>Average risk:</b> {esc(metrics["average_risk"] if metrics["average_risk"] is not None else "N/A")}</p>'
            + ('<p class="warning">Partial/incomplete scanner coverage — findings may be missing.</p>' if not snapshot['scanner_coverage_complete'] else '')
            + f'<h2>Severity</h2><table><tr><th>Level</th><th>Count</th></tr>{sev}</table><h2>Scanner coverage</h2><table><tr><th>Scanner</th><th>Status</th></tr>{coverage}</table>'
            + f'<h2>Top findings (up to 20)</h2><table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>CVE</th><th>Risk</th></tr>{findings}</table>'
            + f'<h2>Remediation</h2><p>Tickets: {snapshot["remediation"]["total_tickets"]}; resolved: {snapshot["remediation"]["resolved"]}; unresolved: {snapshot["remediation"]["unresolved"]}</p>'
            + f'<h2>Interpretation limitations</h2><ul>{limitations}</ul></body></html>')
