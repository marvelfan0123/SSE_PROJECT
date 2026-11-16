"""Phase 3: assessment-scoped, explainable prioritization and evidence-aware reporting.

Pure functions; never scan targets or modify persisted findings.
"""
from __future__ import annotations
from security_controls import csv_cell

from collections import Counter
import csv
import io
import json
import re
from datetime import datetime, timezone

from finding_correlation import correlate_findings
from risk_model import EXPOSURE_FACTORS, CRITICALITY_FACTORS, score_assessment_finding

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.I)
LEVELS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')


def analyze_findings(findings, *, exposure='unknown', criticality='Normal', nvd_cache=None):
    """Score only vulnerability findings, preserve observations, and explain provenance.

    Unknown exposure uses a neutral provisional adjustment; no reachability is inferred.
    """
    if exposure not in EXPOSURE_FACTORS:
        raise ValueError('Unsupported exposure context')
    if criticality not in CRITICALITY_FACTORS:
        raise ValueError('Unsupported business criticality')
    scored = []
    for finding in findings:
        original = dict(finding)
        cve = str(original.get('cve') or '').upper()
        nvd = (nvd_cache or {}).get(cve) if CVE_RE.fullmatch(cve) else None
        result = score_assessment_finding(original, None if exposure == "unknown" else EXPOSURE_FACTORS[exposure], CRITICALITY_FACTORS[criticality], nvd)
        if result.get('risk_score') is None:
            explanation = ('Network exposure observation, not a vulnerability score.' if
                           original.get('source') == 'Nmap' or original.get('finding_type') == 'network_exposure_observation'
                           else 'Risk not scored: missing vulnerability severity evidence.')
        else:
            explanation = (f"Base severity evidence {result['base_score']}/10 × exposure factor "
                           f"{result['exposure_factor']} × business criticality factor "
                           f"{result['criticality_factor']}; normalized to 0–100. "
                           'The score is a provisional prioritization estimate, not proof of exploitation.')
        # Independent severity triage for image-only scans. Never claim it is
        # contextual risk or verified exploitability when deployment is unknown.
        base = result.get('cvss')
        if original.get('source') == 'Nmap' or original.get('finding_type') == 'network_exposure_observation':
            result['triage_priority'] = 'Exposure observation'
        elif isinstance(base, (int, float)) and 0 <= base <= 10:
            result['triage_priority'] = ('Critical' if base >= 9 else 'High' if base >= 7
                                         else 'Medium' if base >= 4 else 'Low')
        else:
            result['triage_priority'] = 'Unknown severity'
        result['risk_explanation'] = explanation
        result['risk_context_source'] = 'Saved assessment context (exposure optional)'
        result['nvd_status'] = (nvd or {}).get('status', 'not_requested')
        scored.append(result)
    return sorted(scored, key=lambda x: (x.get('risk_score') is not None, x.get('risk_score') or 0, x.get('base_score') or 0), reverse=True)


def summarize(findings):
    vulnerabilities = [f for f in findings if f.get('risk_score') is not None]
    observations = [f for f in findings if f.get('source') == 'Nmap' or f.get('finding_type') == 'network_exposure_observation']
    return {'total_findings': len(findings), 'scored_vulnerabilities': len(vulnerabilities),
            'unscored_findings': len(findings) - len(vulnerabilities),
            'exposure_observations': len(observations),
            'severity_distribution': dict(Counter(str(f.get('severity') or 'UNKNOWN').upper() for f in vulnerabilities)),
            'average_contextual_risk': round(sum(f['risk_score'] for f in vulnerabilities)/len(vulnerabilities), 2) if vulnerabilities else None}


def correlation_summary(findings):
    unique, duplicates = correlate_findings(findings)
    return {'unique_count': len(unique), 'duplicate_groups': duplicates, 'unique_findings': unique}


def export_csv(findings):
    fields = ['finding_id', 'source', 'asset', 'cve', 'severity', 'title', 'base_score', 'base_score_source', 'cvss_source', 'cvss_version', 'cvss_vector', 'risk_score', 'risk_label', 'triage_priority', 'risk_explanation', 'nvd_status']
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    writer.writerows([{key: csv_cell(value) for key, value in row.items()} for row in findings])
    return buffer.getvalue()


def export_report(assessment_id, findings, *, exposure, criticality):
    return json.dumps({'schema': 'vulnx.phase3.analysis.v1', 'assessment_id': str(assessment_id),
                       'generated_at_utc': datetime.now(timezone.utc).isoformat(),
                       'context': {'exposure': exposure, 'criticality': criticality,
                                   'source': 'Saved assessment context; exposure may be unverified'},
                       'summary': summarize(findings), 'correlation': {
                           'unique_count': correlation_summary(findings)['unique_count'],
                           'duplicate_groups': correlation_summary(findings)['duplicate_groups']},
                       'findings': findings, 'limitations': [
                           'EPSS/KEV values are only used when present in saved evidence.',
                           'Severity proxies are estimates when verified CVSS is absent.',
                           'Context changes in this view do not overwrite saved scan results.',
                           'Missing findings do not prove absence of vulnerabilities.']},
                      indent=2, default=str)
