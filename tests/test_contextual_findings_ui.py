import unittest
from pathlib import Path
from phase3_analysis import analyze_findings, export_csv, export_report

class ContextualFindingsIntegrationTests(unittest.TestCase):
    def test_verified_loopback_context_produces_priority(self):
        findings = [{"source": "Trivy", "finding_type": "vulnerability", "severity": "HIGH", "cvss": 8.0, "cve": "CVE-2025-12345", "asset": "bkimminich/juice-shop", "title": "Example"}]
        result = analyze_findings(findings, exposure="loopback", criticality="Normal")
        self.assertIsNotNone(result[0]["risk_score"])
        self.assertIn(result[0]["risk_label"], ("Low", "Medium", "High", "Critical"))
        self.assertIn("risk_score", export_csv(result))
        self.assertIn('"exposure": "loopback"', export_report("test", result, exposure="loopback", criticality="Normal"))
    def test_unknown_stays_unscored(self):
        result = analyze_findings([{"source": "Trivy", "severity": "HIGH", "cvss": 8.0}], exposure="unknown")
        self.assertIsNotNone(result[0]["risk_score"])
    def test_main_findings_table_uses_recalculated_results(self):
        source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        block = source.split('elif page == "Vulnerability Findings":', 1)[1].split('elif page == "Risk Prioritization":', 1)[0]
        self.assertIn('st.dataframe(findings_rows(contextual)', block)
        self.assertIn('with st.expander("Original scanner findings (raw evidence)"', block)
        self.assertLess(block.index('st.dataframe(findings_rows(contextual)'), block.index('st.dataframe(findings_rows(filtered)'))

    def test_findings_ui_has_contextual_export(self):
        source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        self.assertIn("Download contextual risk and priority CSV", source)
        self.assertNotIn("Verified deployment exposure", source)

if __name__ == "__main__":
    unittest.main()
