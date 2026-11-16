"""Human-reviewed remediation guidance for VulnX findings. No automatic patching."""


def build_remediation_guidance(finding):
    package = str(finding.get("Package", "unknown package"))
    cve = str(finding.get("CVE", "unknown identifier"))
    installed = str(finding.get("Installed Version", "unknown"))
    fixed = str(finding.get("Fixed Version", "No fix listed"))
    target = str(finding.get("Target", "the affected image/asset"))
    severity = str(finding.get("Severity", "UNKNOWN")).upper()
    steps = [
        f"Confirm that {package} {installed} is present in {target} and that {cve} applies to this exact package/version.",
    ]
    if fixed and fixed.lower() not in {"no fix listed", "unknown", "none", "n/a", ""}:
        steps.append(f"Review the package/vendor advisory and plan an update to {fixed} or a vendor-supported version that includes the fix.")
        steps.append("Test the update in an isolated environment, run application/regression tests, then rebuild the image from a trusted base.")
    else:
        steps.append("No fixed version is listed in the imported finding. Check the vendor advisory and current package repository; do not invent a target version.")
        steps.append("If no fix is available, document a temporary mitigation and an owner-reviewed exception/monitoring plan.")
    steps.extend([
        "Have a reviewer approve the change and maintenance window before production changes.",
        "After the change, re-scan the same asset/image and verify the specific finding is absent or explain why it remains.",
        "Record test evidence, scan timestamp, and the resulting image/package version in the remediation notes.",
    ])
    cautions = []
    if severity in {"CRITICAL", "HIGH"}:
        cautions.append("High-priority finding: review promptly, while validating applicability and impact before making changes.")
    if any(token in package.lower() for token in ("libc", "openssl", "apache", "kernel", "systemd")):
        cautions.append("Core system/network package: check compatibility and service restart requirements before rollout.")
    return {"title": f"Remediation plan for {cve} — {package}", "steps": steps, "cautions": cautions}


def validate_approval(status, approver):
    """Require an identified reviewer before approval or work can start."""
    if status in {"Approved", "In Progress"} and not str(approver or "").strip():
        raise ValueError("An approver/reviewer identity is required before approval or work can start.")
    return True


def validate_verification_record(verification_status, verification_evidence):
    """A Pass / Not applicable verification outcome must always carry evidence,
    whatever the item's workflow status is."""
    if verification_status in {"Pass", "Not applicable"} and not str(verification_evidence or "").strip():
        raise ValueError(
            f"Verification '{verification_status}' needs evidence (scan ID, report filename or timestamp). "
            "Add it, or set verification back to 'Not verified'."
        )
    return True


def validate_resolution(verification_status, verification_evidence):
    """Require an explicit verification outcome and evidence before resolution."""
    if verification_status != "Pass":
        raise ValueError("Before marking Resolved, a fresh verification result must be Pass.")
    if not str(verification_evidence or "").strip():
        raise ValueError("Add verification evidence, such as a scan ID/report filename, or explain why verification is not applicable.")
    return True
