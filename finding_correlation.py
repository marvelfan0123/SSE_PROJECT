"""Conservative deduplication and correlation for normalized VulnX findings."""

from collections import defaultdict


def _key(record):
    """Build an identity key; return None when the identity is incomplete."""
    kind = str(record.get("finding_type", "unknown")).strip() or "unknown"
    asset = str(record.get("asset", "")).strip().lower()

    if kind == "package_vulnerability":
        cve = str(record.get("cve", "")).strip().upper()
        package = str(record.get("package", "")).strip().lower()
        version = str(record.get("installed_version", "")).strip()

        # Missing identity fields make a package finding unsafe to merge.
        if not all((asset, cve, package, version)):
            return None
        return (kind, asset, cve, package, version)

    if kind == "network_exposure_observation":
        evidence = record.get("evidence") or {}
        protocol = str(evidence.get("protocol", "tcp")).strip().lower() or "tcp"
        port = str(evidence.get("port", "")).strip()
        service = str(evidence.get("service", "")).strip().lower()
        version = str(evidence.get("version", "")).strip().lower()

        # Asset and port are the minimum identity for a network observation.
        if not asset or not port:
            return None
        return (kind, asset, protocol, port, service, version)

    # Unknown types can only be grouped when a non-empty finding ID exists.
    finding_id = str(record.get("finding_id", "")).strip()
    if not finding_id:
        return None
    return (kind, finding_id)


def correlate_findings(records):
    """Return unique records with duplicate metadata and duplicate groups.

    Package findings require exact asset, CVE, package and installed-version
    matches. Network observations require matching asset/protocol/port/service/
    version. Incomplete identities are preserved separately rather than merged.
    """
    groups = defaultdict(list)
    for index, record in enumerate(records):
        key = _key(record)
        if key is None:
            # Index ensures even the same incomplete object repeated in the input
            # is preserved as a separate record.
            key = ("__incomplete_identity__", index)
        groups[key].append(record)

    unique_records = []
    duplicate_groups = []
    for key, items in groups.items():
        representative = dict(items[0])
        representative["correlated_record_count"] = len(items)
        representative["correlated_finding_ids"] = [
            item.get("finding_id", "") for item in items
        ]
        unique_records.append(representative)
        if len(items) > 1:
            duplicate_groups.append({
                "finding_type": representative.get("finding_type", "unknown"),
                "asset": representative.get("asset", "Unknown"),
                "title": representative.get("title", "Unknown finding"),
                "count": len(items),
                "finding_ids": [item.get("finding_id", "") for item in items],
            })
    return unique_records, duplicate_groups
