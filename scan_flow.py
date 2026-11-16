"""Scan-first navigation: creation is always accessible; results require saved findings."""
RESULT_PAGES = ("Overview", "Asset Inventory", "Vulnerabilities", "Risk Prioritization",
                "Remediation", "Verification", "Reports", "Scan History")
ACTIVE_STATUSES = ("Queued", "Running", "Discovering assets", "Processing findings")
PUBLISHED_STATUSES = ("Completed", "Partial")


def landing_page(assessment):
    """Dashboard is the first page even for a fresh installation."""
    return "Dashboard"


def allowed_pages(assessment, role):
    """Show all pages; gate result content rather than hiding navigation."""
    pages = ["Dashboard", "New Assessment", "My Scans", "Scan Progress", "Asset Inventory",
             "Vulnerability Findings", "Risk Prioritization", "Attack Paths",
             "Remediation", "Verification", "Reports", "Scan History", "Settings"]
    if role == "Admin":
        pages.extend(["Audit Logs", "User Management"])
    return pages


def results_unlocked(assessment):
    return bool(assessment and assessment.get("status") in PUBLISHED_STATUSES)


def dashboard_metrics(assessment):
    """No scan is not the same as a successful scan with zero findings."""
    from assessment_views import findings_for, severity_counts, unique_assets
    findings = findings_for(assessment)
    severity = severity_counts([f for f in findings if f.get("is_vulnerability", True)])
    exposures = sum(1 for f in findings if not f.get("is_vulnerability", True))
    scored = [float(f["risk_score"]) for f in findings if f.get("is_vulnerability", True) and f.get("risk_score") is not None]
    return {"total": sum(severity.values()), "critical": severity["CRITICAL"],
            "high": severity["HIGH"], "medium": severity["MEDIUM"],
            "low": severity["LOW"], "assets": len(unique_assets(findings)),
            "exposures": exposures, "average_risk": round(sum(scored) / len(scored), 2) if scored else None,
            "status": (assessment or {}).get("status", "Not Scanned")}


def coverage_comparable(first, second):
    """Require same target and identical successful scanner coverage for verification."""
    if not first or not second:
        return False
    if first.get("status") != "Completed" or second.get("status") != "Completed":
        return False
    if first.get("target_type") != second.get("target_type") or first.get("target_name") != second.get("target_name"):
        return False
    def completed_scanners(a):
        return {s.get("scanner") for s in a.get("scanners", []) if s.get("status") == "Completed"}
    def unfinished(a):
        return any(s.get("status") in {"Failed", "Running", "Queued"} for s in a.get("scanners", []))
    return bool(completed_scanners(first)) and completed_scanners(first) == completed_scanners(second) and not unfinished(first) and not unfinished(second)
