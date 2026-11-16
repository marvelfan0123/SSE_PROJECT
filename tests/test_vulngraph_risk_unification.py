"""Comprehensive unit and integration tests for the canonical VulnGraph 0-10 contextual risk engine.

Covers all 14 mandatory Phase 2 verification scenarios:
1. Minimum input values (CVSS=0, EPSS=0, Reachability=0, Criticality=1).
2. Maximum input values (CVSS=10, EPSS=1, Reachability=1, Criticality=5).
3. Missing CVSS (Manual Review required, provisional_sort=7.0 never exposed as confirmed risk).
4. Missing EPSS (CVSS-only fallback calculation, epss_status='Unavailable', calculation_method='cvss_only_fallback').
5. Both missing (No confirmed risk score, calculation_method='unscored_missing_both').
6. Zero reachability (Reachability=0.0 -> Risk=0.0).
7. Internal reachability (Reachability=0.5).
8. External reachability (Reachability=1.0).
9. Criticality boundaries (1, 2, 3, 4, 5 and out-of-range rejection).
10. Worker persistence (assessment_worker persists canonical 0-10 risk_score and audit rows).
11. Findings display (findings_rows and CSV export display exact canonical 0-10 risk_score).
12. Overview display (average risk and risk distribution bands match canonical 0-10 risk_score).
13. Remediation display (tickets reference findings with canonical 0-10 risk_score).
14. Historical assessment display (legacy 0-100 findings migrate safely while preserving original values).
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import assessment_manager as manager
import assessment_worker as worker
import assessment_views as views
import audit_log
import remediation_workflow as wf
from phase5_reporting import build_snapshot
from vulngraph_core import (
    MODEL_VERSION,
    classify_reachability,
    contextual_risk,
    correlate_ports,
    export_canonical_csv,
    migrate_historical_findings,
    parse_docker_inspect,
    resolve_reachability,
    score_finding_canonical,
    score_findings_canonical,
)


class CanonicalRiskEngineTests(unittest.TestCase):
    # 1. Minimum input values
    def test_01_minimum_input_values(self):
        res = contextual_risk(cvss=0.0, epss=0.0, reachability=0.0, criticality=1)
        self.assertEqual(res["risk"], 0.0)
        self.assertEqual(res["risk_label"], "Zero Risk")
        self.assertEqual(res["status"], "Evidence Complete")
        self.assertEqual(res["calculation_method"], "full_contextual_formula")

    # 2. Maximum input values
    def test_02_maximum_input_values(self):
        res = contextual_risk(cvss=10.0, epss=1.0, reachability=1.0, criticality=5)
        self.assertEqual(res["risk"], 10.0)
        self.assertEqual(res["risk_label"], "Critical")
        self.assertEqual(res["status"], "Evidence Complete")
        self.assertEqual(res["model_version"], MODEL_VERSION)

    # 3. Missing CVSS
    def test_03_missing_cvss_requires_manual_review(self):
        res = contextual_risk(cvss=None, epss=0.8, reachability=1.0, criticality=5)
        self.assertIsNone(res["risk"])
        self.assertEqual(res["status"], "Manual Review")
        self.assertEqual(res["risk_label"], "Manual Review")
        self.assertEqual(res["provisional_sort"], 7.0)
        self.assertEqual(res["calculation_method"], "manual_review_missing_cvss")

        # Verify score_finding_canonical never presents provisional_sort as risk_score
        scored = score_finding_canonical(
            {"finding_id": "f-nocvss", "source": "Trivy", "severity": "CRITICAL", "epss_probability": 0.85, "epss_status": "ok"},
            exposure_kind="all_interfaces",
            criticality="High",
        )
        self.assertIsNone(scored["risk_score"])
        self.assertIsNone(scored["contextual_risk"])
        self.assertEqual(scored["provisional_sort"], 7.0)
        self.assertEqual(scored["risk_label"], "Manual Review")

    # 4. Missing EPSS
    def test_04_missing_epss_uses_cvss_only_fallback(self):
        # CVSS = 9.0, EPSS = None, Reachability = 0.5, Criticality = 3
        # R = 10 * (9.0 / 10.0) * 0.5 * (3 / 5) = 2.7
        res = contextual_risk(cvss=9.0, epss=None, reachability=0.5, criticality=3)
        self.assertEqual(res["risk"], 2.7)
        self.assertEqual(res["status"], "Provisional")
        self.assertEqual(res["epss_status"], "Unavailable")
        self.assertEqual(res["calculation_method"], "cvss_only_fallback")
        self.assertEqual(res["risk_label"], "Low")
        self.assertIn("CVSS-only", res["reason"])

    # 5. Both missing
    def test_05_both_missing_returns_no_confirmed_score(self):
        res = contextual_risk(cvss=None, epss=None, reachability=1.0, criticality=3)
        self.assertIsNone(res["risk"])
        self.assertIsNone(res["provisional_sort"])
        self.assertEqual(res["status"], "Manual Review")
        self.assertEqual(res["epss_status"], "Unavailable")
        self.assertEqual(res["calculation_method"], "unscored_missing_both")

    # 6. Zero reachability
    def test_06_zero_reachability_results_in_zero_risk(self):
        res = contextual_risk(cvss=10.0, epss=1.0, reachability=0.0, criticality=5)
        self.assertEqual(res["risk"], 0.0)
        self.assertEqual(res["risk_label"], "Zero Risk")

    # 7. Internal reachability
    def test_07_internal_reachability_scaling(self):
        # CVSS=8.0, EPSS=0.5 -> component = 0.24 + 0.35 = 0.59
        # Reachability=0.5, Criticality=5 -> R = 10 * 0.59 * 0.5 * 1.0 = 2.95
        res = contextual_risk(cvss=8.0, epss=0.5, reachability=0.5, criticality=5)
        self.assertEqual(res["risk"], 2.95)
        self.assertEqual(res["risk_label"], "Low")

    # 8. External reachability
    def test_08_external_reachability_scaling(self):
        # CVSS=8.0, EPSS=0.5 -> component = 0.59
        # Reachability=1.0, Criticality=5 -> R = 10 * 0.59 * 1.0 * 1.0 = 5.9
        res = contextual_risk(cvss=8.0, epss=0.5, reachability=1.0, criticality=5)
        self.assertEqual(res["risk"], 5.9)
        self.assertEqual(res["risk_label"], "Medium")

    # 9. Criticality boundaries
    def test_09_criticality_boundaries(self):
        scores = [contextual_risk(cvss=10.0, epss=1.0, reachability=1.0, criticality=c)["risk"] for c in (1, 2, 3, 4, 5)]
        self.assertEqual(scores, [2.0, 4.0, 6.0, 8.0, 10.0])

        for invalid_crit in (0, 6, -1, 3.5, True, "5"):
            with self.assertRaises(ValueError):
                contextual_risk(cvss=8.0, epss=0.5, reachability=1.0, criticality=invalid_crit)

        for bad_args in [
            (11.0, 0.5, 1.0, 3),
            (-0.1, 0.5, 1.0, 3),
            (8.0, 1.5, 1.0, 3),
            (8.0, -0.1, 1.0, 3),
            (8.0, 0.5, 1.5, 3),
            (8.0, float("nan"), 1.0, 3),
        ]:
            with self.assertRaises(ValueError):
                contextual_risk(*bad_args)

    # 10, 11, 12, 13: Worker persistence, Findings display, Overview display, Remediation display
    def test_10_to_13_worker_persistence_and_cross_view_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_db, old_audit, old_rep = manager.DB_PATH, audit_log.DB_PATH, worker.REPORT_DIR
            try:
                db_file = Path(tmp) / "canonical_test.db"
                manager.DB_PATH = db_file
                audit_log.DB_PATH = db_file
                worker.REPORT_DIR = Path(tmp) / "reports"
                manager.initialize()
                wf.initialize()

                target = {
                    "name": "juice-shop",
                    "image": "bkimminich/juice-shop:latest",
                    "exposure_kind": "all_interfaces",
                    "scanner_plan": [
                        ("Trivy", "Pending", "image"),
                        ("Nmap", "Skipped", "none"),
                        ("OWASP ZAP", "Skipped", "none"),
                    ],
                }
                aid = manager.create_assessment("analyst1", "Docker image", target, "High")

                def fake_trivy(image, outdir, **kwargs):
                    report = Path(outdir) / "trivy-test.json"
                    report.write_text(json.dumps({
                        "Results": [{
                            "Target": "juice-shop",
                            "Vulnerabilities": [{
                                "VulnerabilityID": "CVE-2024-9999",
                                "PkgName": "express",
                                "Severity": "CRITICAL",
                                "InstalledVersion": "4.17.1",
                                "FixedVersion": "4.19.2",
                                "CVSS": {"nvd": {"V3Score": 9.0}},
                            }]
                        }]
                    }), encoding="utf-8")
                    return {"report_path": report, "report_name": report.name, "vulnerability_count": 1}

                with patch.object(worker, "run_trivy_image_scan", side_effect=fake_trivy), \
                     patch.object(worker, "fetch_nvd_cve", return_value={"status": "ok", "cvss_score": 9.0}), \
                     patch.object(worker, "enrich_findings", side_effect=lambda items: [
                         dict(x, epss_probability=0.5, epss_status="ok") for x in items
                     ]):
                    worker.run(aid)

                # 10. Worker persistence check
                loaded = manager.get_assessment(aid)
                self.assertEqual(loaded["status"], "Completed")
                self.assertEqual(len(loaded["findings"]), 1)
                persisted_finding = loaded["findings"][0]
                # Formula: 10 * [0.3*(9.0/10) + 0.7*(0.5)] * 1.0 * (5/5) = 10 * (0.27 + 0.35) * 1.0 = 6.2
                expected_score = 6.2
                self.assertEqual(persisted_finding["risk_score"], expected_score)
                self.assertEqual(persisted_finding["contextual_risk"], expected_score)
                self.assertEqual(persisted_finding["contextual_risk_score"], expected_score)
                self.assertEqual(persisted_finding["model_version"], MODEL_VERSION)
                self.assertEqual(persisted_finding["calculation_method"], "full_contextual_formula")

                # 11. Findings display check
                rows = views.findings_rows(loaded["findings"])
                self.assertEqual(rows[0]["Contextual risk"], expected_score)
                csv_text = export_canonical_csv(loaded["findings"])
                self.assertIn("6.2", csv_text)
                self.assertIn(MODEL_VERSION, csv_text)

                # 12. Overview & Report snapshot display check
                snap = build_snapshot(loaded)
                self.assertEqual(snap["metrics"]["average_risk"], expected_score)
                self.assertEqual(snap["top_findings"][0]["risk_score"], expected_score)

                # 13. Remediation display check
                tid = wf.create_ticket(aid, persisted_finding["finding_id"], "analyst1", "Analyst", notes="Upgrade express")
                self.assertIsNotNone(tid)
                finding_by_id = {f["finding_id"]: f for f in loaded["findings"]}
                self.assertEqual(finding_by_id[persisted_finding["finding_id"]]["risk_score"], expected_score)
            finally:
                manager.DB_PATH, audit_log.DB_PATH, worker.REPORT_DIR = old_db, old_audit, old_rep

    # 14. Historical assessment display & safe migration
    def test_14_historical_legacy_findings_migrate_safely(self):
        legacy_finding = {
            "finding_id": "legacy-1",
            "source": "Trivy",
            "finding_type": "package_vulnerability",
            "cve": "CVE-2023-0001",
            "severity": "HIGH",
            "cvss": 8.0,
            "epss_probability": 0.5,
            "epss_status": "ok",
            "risk_score": 64.0,  # Legacy 0-100 score
            "model_version": "vulnx-priority-3.1-evidence-guardrails",
        }
        migrated = migrate_historical_findings([legacy_finding], exposure_kind="loopback", criticality="Normal")[0]
        # Preserves original legacy score and model version
        self.assertEqual(migrated["historical_legacy_risk_score"], 64.0)
        self.assertEqual(migrated["historical_model_version"], "vulnx-priority-3.1-evidence-guardrails")
        self.assertTrue(migrated["migrated_from_legacy"])
        # Canonical 0-10 score: 10 * (0.24 + 0.35) * 0.5 * (3/5) = 1.77
        self.assertEqual(migrated["risk_score"], 1.77)
        self.assertEqual(migrated["contextual_risk"], 1.77)
        self.assertEqual(migrated["model_version"], MODEL_VERSION)

    # 15. Unknown reachability remains unknown (never silently converted to confirmed numeric score)
    def test_15_unknown_reachability_never_converted_to_confirmed_score(self):
        self.assertIsNone(resolve_reachability("unknown"))
        self.assertIsNone(resolve_reachability(None))
        scored = score_finding_canonical(
            {
                "finding_id": "f-unknown-reach",
                "source": "Trivy",
                "cve": "CVE-2024-1111",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "epss_probability": 0.9,
                "epss_status": "ok",
            },
            exposure_kind="unknown",
            criticality="High",
        )
        self.assertIsNone(scored["reachability"])
        self.assertIsNone(scored["risk_score"])
        self.assertIsNone(scored["contextual_risk"])
        self.assertEqual(scored["contextual_status"], "Provisional")
        self.assertEqual(scored["calculation_method"], "provisional_missing_reachability")

    # 16. Docker wildcard binding (0.0.0.0) is potential exposure, NOT confirmed public internet exposure
    def test_16_docker_wildcard_binding_is_potential_exposure_not_external(self):
        wildcard_info = classify_reachability(host_ip="0.0.0.0")
        self.assertEqual(wildcard_info["category"], "Potential Exposure")
        self.assertEqual(wildcard_info["reachability"], 0.5)
        self.assertFalse(wildcard_info["confirmed"])
        self.assertNotEqual(wildcard_info["reachability"], 1.0)

        containers = parse_docker_inspect([
            {
                "Id": "c_wild",
                "Name": "/juice",
                "Image": "sha256:juice",
                "Config": {"Image": "bkimminich/juice-shop:latest"},
                "State": {"Running": True},
                "NetworkSettings": {
                    "Ports": {"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3000"}]},
                    "Networks": {"bridge": {}},
                },
            }
        ])
        links = correlate_ports([{"asset": "127.0.0.1", "port": 3000, "state": "open"}], containers, "A-WILD")
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["reachability_category"], "Potential Exposure")
        self.assertIn("not confirmed external", links[0]["reachability"])

    # 17. Distinguish all 5 reachability categories
    def test_17_five_reachability_categories_distinguished(self):
        ext = classify_reachability("confirmed_external")
        internal = classify_reachability("confirmed_internal", host_ip="127.0.0.1")
        potential = classify_reachability("potential_exposure", host_ip="0.0.0.0")
        unknown = classify_reachability("unknown")
        no_path = classify_reachability("isolated", has_open_port=False)

        self.assertEqual((ext["category"], ext["reachability"], ext["confirmed"]), ("Confirmed External Reachability", 1.0, True))
        self.assertEqual((internal["category"], internal["reachability"], internal["confirmed"]), ("Confirmed Internal Exposure", 0.5, True))
        self.assertEqual((potential["category"], potential["reachability"], potential["confirmed"]), ("Potential Exposure", 0.5, False))
        self.assertEqual((unknown["category"], unknown["reachability"], unknown["confirmed"]), ("Unknown Reachability", None, False))
        self.assertEqual((no_path["category"], no_path["reachability"], no_path["confirmed"]), ("No Identified Path", 0.0, True))

    # 18. Canonical scorer rejects stale EPSS cache fallback
    def test_18_canonical_scorer_rejects_stale_epss_cache_fallback(self):
        stale_record = {
            "probability": 0.95,
            "percentile": 0.99,
            "date": "2020-01-01",
            "status": "stale",
            "fetched_at": "2020-01-01T00:00:00+00:00"
        }
        with patch("threat_intelligence.get_cached_epss", return_value=stale_record):
            scored = score_finding_canonical(
                {
                    "finding_id": "f-stale-epss",
                    "source": "Trivy",
                    "cve": "CVE-2026-9999",
                    "severity": "HIGH",
                    "cvss": 8.0,
                },
                exposure_kind="confirmed_external",
                criticality="High",
            )
            # Must fall back to CVSS-only calculation R = 10 * (8.0/10.0) * 1.0 * (5/5) = 8.0
            # (If stale EPSS 0.95 was improperly used, score would be 9.05 and calculation_method='canonical')
            self.assertEqual(scored["risk_score"], 8.0)
            self.assertEqual(scored["calculation_method"], "cvss_only_fallback")
            self.assertEqual(scored["epss_status"], "stale")
            self.assertIsNone(scored["epss"])
            self.assertEqual(scored["contextual_status"], "Provisional")

    # 19. Canonical scorer rejects explicit stale EPSS status on finding
    def test_19_canonical_scorer_rejects_explicit_stale_epss_on_finding(self):
        scored = score_finding_canonical(
            {
                "finding_id": "f-explicit-stale",
                "source": "Trivy",
                "cve": "CVE-2026-8888",
                "severity": "HIGH",
                "cvss": 8.0,
                "epss_probability": 0.95,
                "epss_status": "stale",
            },
            exposure_kind="confirmed_external",
            criticality="High",
        )
        self.assertEqual(scored["risk_score"], 8.0)
        self.assertEqual(scored["calculation_method"], "cvss_only_fallback")
        self.assertEqual(scored["epss_status"], "stale")
        self.assertIsNone(scored["epss"])
        self.assertEqual(scored["contextual_status"], "Provisional")


if __name__ == "__main__":
    unittest.main()
