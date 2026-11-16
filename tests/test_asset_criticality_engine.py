import unittest
from asset_criticality_engine import assess_asset


class AutomaticAssetCriticalityTests(unittest.TestCase):
    def test_explicit_docker_labels_calculate_all_four_categories(self):
        result = assess_asset({"asset_name": "db:1", "evidence_source": "Docker inspect", "containers": [{
            "labels": {
                "com.vulnx.data-sensitivity": "5",
                "com.vulnx.business-importance": "4",
                "com.vulnx.availability-impact": "5",
                "com.vulnx.dependency-impact": "4",
            }
        }]})
        self.assertEqual(result["factor_scores"], {
            "data_sensitivity": 5, "business_importance": 4,
            "availability_impact": 5, "dependency_impact": 4,
        })
        self.assertEqual(result["suggested_criticality"], "Critical")
        self.assertEqual(result["assessment_status"], "Automatically assessed")

    def test_environment_label_only_supports_business_importance(self):
        result = assess_asset({"asset_name": "api:1", "containers": [{"labels": {"environment": "production"}}]})
        self.assertEqual(result["factor_scores"], {"business_importance": 4})
        self.assertEqual(result["suggested_criticality"], "Unassigned")
        self.assertEqual(len(result["missing_factors"]), 3)

    def test_known_lab_target_gets_only_supported_lab_context_scores(self):
        result = assess_asset({"asset_name": "bkimminich/juice-shop:latest", "containers": []})
        self.assertEqual(result["factor_scores"]["business_importance"], 1)
        self.assertEqual(result["factor_scores"]["availability_impact"], 1)
        self.assertNotIn("data_sensitivity", result["factor_scores"])
        self.assertEqual(result["suggested_criticality"], "Unassigned")

    def test_scanner_findings_are_not_used_as_business_criticality_evidence(self):
        result = assess_asset({"asset_name": "prod-db", "containers": [], "trivy_critical_count": 100})
        self.assertEqual(result["factor_scores"], {})
        self.assertEqual(result["suggested_criticality"], "Unassigned")

    def test_invalid_label_values_are_ignored(self):
        result = assess_asset({"asset_name": "db", "containers": [{"labels": {
            "com.vulnx.data-sensitivity": "99", "com.vulnx.business-importance": "unknown"
        }}]})
        self.assertEqual(result["factor_scores"], {})


if __name__ == "__main__":
    unittest.main()
