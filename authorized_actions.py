"""Permission-checked entry points for state-changing and external operations."""
from auth import require_permission
from trivy_scanner import run_trivy_image_scan
from asset_discovery import scan_target
from zap_scanner import run_zap_baseline_scan
from nvd_enrichment import enrich_cve_batch


def run_trivy_scan(actor_role, image, output_dir, **options):
    require_permission(actor_role, "run_scans")
    return run_trivy_image_scan(image, output_dir, **options)


def run_nmap_scan(actor_role, target, ports):
    require_permission(actor_role, "run_scans")
    return scan_target(target, ports)


def run_zap_scan(actor_role, app_name, output_dir, **options):
    require_permission(actor_role, "run_scans")
    return run_zap_baseline_scan(app_name, output_dir, **options)


def enrich_cves(actor_role, cve_ids, cache_path, **options):
    require_permission(actor_role, "enrich_cves")
    return enrich_cve_batch(cve_ids, cache_path, **options)
