from security_controls import csv_cell
"""Pure assessment-scoped view helpers. No bundled reports or implicit scans."""
from collections import Counter
import csv
import io

FINISHED = {"Completed", "Partial", "Failed"}
ACTIVE = {"Queued", "Running", "Discovering assets", "Processing findings"}


def visible_assessments(items, username, role):
    return list(items) if role == "Admin" else [item for item in items if item.get("created_by") == username]


def assessment_ready(assessment):
    return bool(assessment and assessment.get("status") in {"Completed", "Partial"})


def findings_for(assessment):
    return list(assessment.get("findings") or []) if assessment_ready(assessment) else []


def severity_counts(findings):
    result = Counter(str(f.get("severity") or "UNKNOWN").upper() for f in findings)
    return {level: result.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}


def _canonical_risk_value(f):
    score = f.get("risk_score")
    ver = str(f.get("model_version") or "")
    if (isinstance(score, (int, float)) and not isinstance(score, bool) and score > 10.0) or ver.startswith("vulnx-"):
        from vulngraph_core import score_finding_canonical
        f = score_finding_canonical(f)
    return f


def findings_rows(findings):
    rows = []
    for raw_f in findings:
        f = _canonical_risk_value(raw_f)
        nvd_st = f.get("nvd_status")
        if not nvd_st:
            if not f.get("cve") or not str(f.get("cve", "")).startswith("CVE-"):
                nvd_st = "N/A"
            elif f.get("cvss") is not None and "NVD" in str(f.get("base_score_source", "")):
                nvd_st = "Cached"
            else:
                nvd_st = "Pending"
        rows.append({
            "Scanner": f.get("source", ""),
            "Severity": f.get("severity", "UNKNOWN"),
            "CVE": f.get("cve") or "Not assigned",
            "NVD Intelligence": nvd_st,
            "Package": f.get("package") or "—",
            "Installed": f.get("installed_version") or "—",
            "Fixed": f.get("fixed_version") or "No fix listed",
            "Asset": f.get("asset", ""),
            "Title": f.get("title", ""),
            "CVSS": f.get("cvss") if f.get("cvss") is not None else f.get("base_score"),
            "EPSS": f.get("epss_probability") if f.get("epss_probability") is not None else f.get("epss"),
            "CVSS / base provenance": f.get("base_score_source") or f.get("cvss_source") or "Not available",
            "Contextual risk": f.get("risk_score"),
            "Priority": f.get("risk_label", "Unscored"),
            "Severity triage (not contextual)": f.get("triage_priority", "Not calculated"),
        })
    return rows


def findings_csv(findings):
    output = io.StringIO()
    rows = findings_rows(findings)
    writer = csv.DictWriter(output, fieldnames=[
        "Scanner", "Severity", "CVE", "NVD Intelligence", "Package", "Installed", "Fixed", "Asset",
        "Title", "CVSS", "EPSS", "CVSS / base provenance", "Contextual risk",
        "Priority", "Severity triage (not contextual)"
    ])
    writer.writeheader()
    writer.writerows([{key: csv_cell(value) for key, value in row.items()} for row in rows])
    return output.getvalue()


def scanner_summary(assessment):
    return [{"Scanner": item.get("scanner"), "Status": item.get("status"), "Details": item.get("message")}
            for item in (assessment.get("scanners") or [])]


def unique_assets(findings):
    return sorted({str(f.get("asset")).strip() for f in findings if f.get("asset")})
