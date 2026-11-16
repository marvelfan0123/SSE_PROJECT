"""Import an existing Trivy JSON report; this is not a live vulnerability scan."""
import json
from assessment_manager import create_assessment, save_findings, update_assessment, update_scanner
from finding_normalization import normalize_trivy_report

MAX_REPORT_BYTES = 5 * 1024 * 1024


def validate_trivy_json(data: bytes):
    if not data or len(data) > MAX_REPORT_BYTES:
        raise ValueError('Report must be between 1 byte and 5 MiB.')
    try:
        report = json.loads(data.decode('utf-8-sig'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Report must contain valid UTF-8 JSON.') from exc
    if not isinstance(report, dict) or not isinstance(report.get('Results'), list):
        raise ValueError('Expected a Trivy JSON report with a Results array.')
    if len(report['Results']) > 10000:
        raise ValueError('Report contains too many result entries.')
    for result in report['Results']:
        if not isinstance(result, dict) or not isinstance(result.get('Target'), str):
            raise ValueError('Each Trivy result must identify a Target.')
        if not isinstance(result.get('Vulnerabilities', []), (list, type(None))):
            raise ValueError('Invalid vulnerabilities array.')
        if len(result.get('Vulnerabilities') or []) > 50000:
            raise ValueError('Report contains too many vulnerabilities.')
    return report


def import_trivy_report(username, name, criticality, data):
    report = validate_trivy_json(data)
    findings = normalize_trivy_report(report, 'Uploaded Trivy JSON')
    target = {'name': name[:100], 'imported': True, 'scanner_plan': [('Trivy Import', 'Pending', 'Validated uploaded JSON')]}
    assessment_id = create_assessment(username, 'Imported Trivy report', target, criticality)
    for finding in findings:
        finding['assessment_id'] = assessment_id
    try:
        save_findings(assessment_id, findings)
        update_scanner(assessment_id, 'Trivy Import', 'Completed', f'{len(findings)} imported findings')
        update_assessment(assessment_id, 'Completed', stage='Imported report validated and saved')
    except Exception:
        update_assessment(assessment_id, 'Failed', stage='Import failed')
        raise
    return assessment_id
