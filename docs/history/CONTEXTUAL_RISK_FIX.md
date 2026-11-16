# Contextual risk workflow fix

The Vulnerability Findings page now provides a contextual risk panel with explicit exposure and business criticality selections, a prioritized table, and contextual CSV/JSON exports. Raw scanner findings remain unchanged. Unknown exposure intentionally yields unscored findings. For a verified localhost deployment of the *same* Docker image, select `loopback`; do not infer public exposure from open ports. The Risk Prioritization page also explains this prerequisite.
