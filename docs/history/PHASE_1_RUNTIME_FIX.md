# Phase 1 runtime fix (November 2026)

Fixed the custom Docker image wizard to avoid reading `vx_target_lab` when the user has never selected a predefined lab. The assessment planner accepts `custom_image` and works with a missing lab selection for Docker image scans. Existing audit-log role forwarding remains intact.

## Apply
Extract this ZIP into a **new** folder, not on top of old source files. Stop the previous Streamlit process, open PowerShell in the extracted `Scanning and Vulnerability Management Platform` directory, activate/create a virtual environment, install requirements, then run `python -m streamlit run app.py`.

Verify the loaded planner with:
`python -c "import inspect, assessment_portal; print(assessment_portal.__file__); print(inspect.signature(assessment_portal.make_plan))"`

Trivy must still be installed and available on PATH for actual image scans. Tests are not a substitute for live Windows scanning.
