import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import threat_intelligence as ti
from risk_model import score_assessment_finding


def _fake_network(calls, fail=False):
    def fake(url):
        calls.append(url)
        if fail:
            raise OSError("offline")
        if "epss" in url:
            wanted = [c for c in url.split("cve=")[1].replace("%2C", ",").split(",")]
            return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.9", "date": "d"} for c in wanted if c != "CVE-2099-0000"]}
        return {"vulnerabilities": [{"cveID": "CVE-2021-0001", "dateAdded": "d"}]}
    return fake


class ThreatCacheTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patcher = patch.object(ti, "CACHE_FILE", Path(self.dir.name) / "cache.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        env = patch.dict("os.environ", {"VULNX_THREAT_ENRICHMENT": "1"})
        env.start()
        self.addCleanup(env.stop)

    def test_new_cves_are_fetched_within_ttl(self):
        calls = []
        with patch.object(ti, "_get_json", _fake_network(calls)):
            a = ti.enrich_findings([{"cve": "CVE-2021-0001"}])[0]
            b = ti.enrich_findings([{"cve": "CVE-2022-9999"}])[0]
        self.assertEqual(a["epss_status"], "available")
        self.assertEqual(b["epss_status"], "available")
        self.assertEqual(b["epss_percentile"], 0.9)

    def test_fresh_entries_are_not_refetched(self):
        calls = []
        with patch.object(ti, "_get_json", _fake_network(calls)):
            ti.enrich_findings([{"cve": "CVE-2021-0001"}])
            n = len(calls)
            ti.enrich_findings([{"cve": "CVE-2021-0001"}])
        self.assertEqual(len(calls), n)

    def test_failed_refresh_does_not_poison_cache(self):
        with patch.object(ti, "_get_json", _fake_network([], fail=True)):
            first = ti.enrich_findings([{"cve": "CVE-2021-0001"}])[0]
        self.assertEqual(first["epss_status"], "unavailable")
        self.assertEqual(first["kev_status"], "unavailable")
        calls = []
        with patch.object(ti, "_get_json", _fake_network(calls)):
            retry = ti.enrich_findings([{"cve": "CVE-2021-0001"}])[0]
        self.assertGreater(len(calls), 0)
        self.assertEqual(retry["epss_status"], "available")
        self.assertEqual(retry["kev_status"], "listed")

    def test_failed_kev_refresh_keeps_previous_data_as_stale(self):
        old = "2020-01-01T00:00:00+00:00"
        ti.CACHE_FILE.write_text(json.dumps({"version": 2, "kev": {"fetched_at": old, "data": {"CVE-2021-0001": "x"}},
                                             "epss": {}}))
        with patch.object(ti, "_get_json", _fake_network([], fail=True)):
            x = ti.enrich_findings([{"cve": "CVE-2021-0001"}])[0]
        self.assertEqual(x["kev_evidence_status"], "stale")
        self.assertEqual(x["kev_status"], "unavailable")
        saved = json.loads(ti.CACHE_FILE.read_text()) if ti.CACHE_FILE.exists() else {}
        self.assertEqual(saved.get("kev", {}).get("fetched_at", old), old)

    def test_cve_unknown_to_epss_is_unavailable_and_not_refetched(self):
        calls = []
        with patch.object(ti, "_get_json", _fake_network(calls)):
            x = ti.enrich_findings([{"cve": "CVE-2099-0000"}])[0]
            n = len(calls)
            ti.enrich_findings([{"cve": "CVE-2099-0000"}])
        self.assertEqual(x["epss_status"], "unavailable")
        self.assertEqual(len(calls), n)

    def test_more_than_1000_cves_are_all_requested(self):
        cves = [f"CVE-2020-{i:05d}" for i in range(1, 1206)]
        calls = []
        with patch.object(ti, "_get_json", _fake_network(calls)):
            rows = ti.enrich_findings([{"cve": c} for c in cves])
        self.assertTrue(all(r["epss_status"] == "available" for r in rows))


class LabelCalibrationTests(unittest.TestCase):
    def label(self, severity):
        return score_assessment_finding({"source": "Trivy", "severity": severity})["risk_label"]

    def test_labels_are_not_promoted_without_extra_evidence(self):
        self.assertEqual(self.label("LOW"), "Low")
        self.assertEqual(self.label("MEDIUM"), "Medium")
        self.assertEqual(self.label("HIGH"), "High")
        self.assertEqual(self.label("CRITICAL"), "Critical")

    def test_cvss_band_edges(self):
        for cvss, expected in [(3.9, "Low"), (4.0, "Medium"), (6.9, "Medium"), (7.0, "High"), (8.9, "High"), (9.0, "Critical")]:
            got = score_assessment_finding({"source": "Trivy", "cvss": cvss})["risk_label"]
            self.assertEqual(got, expected, cvss)


if __name__ == "__main__":
    unittest.main()
