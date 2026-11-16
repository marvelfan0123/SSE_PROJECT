import tempfile
import unittest
import sqlite3
from contextlib import closing
from pathlib import Path

import asset_criticality
from asset_criticality import (
    image_asset_from_report, register_discovered_asset, list_assets,
    update_asset_profile, criticality_map, suggest_criticality,
)


class AssetCriticalityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = asset_criticality.DB_PATH
        asset_criticality.DB_PATH = Path(self.temp_dir.name) / "test_scan_history.db"

    def tearDown(self):
        asset_criticality.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_extracts_stable_logical_image_asset_from_trivy_metadata(self):
        report = {
            "ArtifactName": "example/api:1.2",
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": "sha256:abc", "RepoDigests": ["example/api@sha256:def"]},
        }
        asset = image_asset_from_report(report, "api-report.json")
        self.assertEqual(asset["asset_name"], "example/api:1.2")
        self.assertEqual(asset["asset_type"], "Container image")
        self.assertEqual(asset["image_id"], "sha256:abc")
        self.assertTrue(asset["asset_id"].startswith("image:"))

    def test_profile_is_persistent_and_discovery_does_not_reset_user_values(self):
        asset = image_asset_from_report({"ArtifactName": "example/api:1.2", "Metadata": {}}, "api.json")
        register_discovered_asset(asset)
        updated = update_asset_profile(asset["asset_id"], "Critical", "Production", "Platform Team", "Customer database API", "admin")
        self.assertEqual(updated["criticality"], "Critical")
        self.assertEqual(updated["environment"], "Production")
        # A later scan should update report metadata but preserve the profile.
        register_discovered_asset({**asset, "last_seen_report": "api-rescan.json"})
        stored = next(item for item in list_assets() if item["asset_id"] == asset["asset_id"])
        self.assertEqual(stored["criticality"], "Critical")
        self.assertEqual(stored["environment"], "Production")
        self.assertEqual(stored["owner"], "Platform Team")
        self.assertEqual(stored["last_seen_report"], "api-rescan.json")

    def test_invalid_criticality_is_rejected(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/api:1.2"}, "api.json"))
        with self.assertRaises(ValueError):
            update_asset_profile(asset["asset_id"], "Urgent")

    def test_criticality_map_returns_profiles_by_asset_id(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/api:1.2"}, "api.json"))
        update_asset_profile(asset["asset_id"], "High")
        self.assertEqual(criticality_map()[asset["asset_id"]], "High")

    def test_new_assets_are_unassigned_not_assumed_medium(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/new:1"}, "new.json"))
        self.assertEqual(asset["criticality"], "Unassigned")
        self.assertEqual(asset["assessment_status"], "Unassessed")

    def test_assessment_suggestion_uses_four_business_impact_factors(self):
        result = suggest_criticality({
            "data_sensitivity": 5,
            "business_importance": 4,
            "availability_impact": 5,
            "dependency_impact": 4,
        })
        self.assertEqual(result["average_score"], 4.5)
        self.assertEqual(result["suggested_criticality"], "Critical")

    def test_confirmed_assessment_persists_factors_and_confirmation(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/assessed:1"}, "assessed.json"))
        factors = {"data_sensitivity": 4, "business_importance": 4, "availability_impact": 3, "dependency_impact": 4}
        updated = update_asset_profile(
            asset["asset_id"], "High", "Production", "Platform Team", "Critical internal service", "admin",
            factor_scores=factors, assessment_status="Confirmed",
        )
        self.assertEqual(updated["criticality"], "High")
        self.assertEqual(updated["suggested_criticality"], "High")
        self.assertEqual(updated["factor_scores"], factors)
        self.assertEqual(updated["assessment_status"], "Confirmed")
        self.assertEqual(updated["confirmed_by"], "admin")

    def test_assessment_rejects_incomplete_or_out_of_range_factors(self):
        with self.assertRaises(ValueError):
            suggest_criticality({"data_sensitivity": 5})
        with self.assertRaises(ValueError):
            suggest_criticality({"data_sensitivity": 6, "business_importance": 3, "availability_impact": 3, "dependency_impact": 3})

    def test_automatic_assessment_evidence_is_persisted(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/auto:1"}, "auto.json"))
        factors = {"data_sensitivity": 4, "business_importance": 4, "availability_impact": 4, "dependency_impact": 4}
        evidence = {"evidence": {"data_sensitivity": "Docker label"}, "overall_confidence": "High"}
        updated = update_asset_profile(
            asset["asset_id"], "Critical", factor_scores=factors,
            assessment_status="Automatically assessed", evidence=evidence,
        )
        self.assertEqual(updated["assessment_status"], "Automatically assessed")
        self.assertEqual(updated["assessment_evidence"], evidence)
        self.assertEqual(updated["confirmed_by"], "")

    def test_legacy_automatic_medium_default_is_migrated_to_unassigned(self):
        now = "2026-10-31T00:00:00+00:00"
        with closing(sqlite3.connect(asset_criticality.DB_PATH)) as connection, connection:
            connection.execute("""CREATE TABLE asset_profiles (
                asset_id TEXT PRIMARY KEY, asset_name TEXT NOT NULL,
                asset_type TEXT NOT NULL DEFAULT 'Container image',
                criticality TEXT NOT NULL DEFAULT 'Medium',
                environment TEXT NOT NULL DEFAULT 'Development', owner TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '', image_id TEXT NOT NULL DEFAULT '',
                image_digest TEXT NOT NULL DEFAULT '', last_seen_report TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT ''
            )""")
            connection.execute("INSERT INTO asset_profiles (asset_id, asset_name, first_seen_at, updated_at) VALUES (?, ?, ?, ?)",
                               ("image:legacy", "legacy/image:1", now, now))
            connection.execute("INSERT INTO asset_profiles (asset_id, asset_name, criticality, first_seen_at, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?)",
                               ("image:confirmed", "confirmed/image:1", "Critical", now, now, "admin"))
        migrated = asset_criticality.get_asset("image:legacy")
        confirmed = asset_criticality.get_asset("image:confirmed")
        self.assertEqual(migrated["criticality"], "Unassigned")
        self.assertEqual(migrated["assessment_status"], "Unassessed")
        self.assertEqual(confirmed["criticality"], "Critical")

    def test_human_can_override_suggestion_and_both_values_are_saved(self):
        asset = register_discovered_asset(image_asset_from_report({"ArtifactName": "example/override:1"}, "override.json"))
        factors = {"data_sensitivity": 5, "business_importance": 5, "availability_impact": 4, "dependency_impact": 4}
        updated = update_asset_profile(
            asset["asset_id"], "High", "Production", "Security Team", "Documented override", "analyst",
            factor_scores=factors, assessment_status="Confirmed",
        )
        self.assertEqual(updated["suggested_criticality"], "Critical")
        self.assertEqual(updated["criticality"], "High")


if __name__ == "__main__":
    unittest.main()
