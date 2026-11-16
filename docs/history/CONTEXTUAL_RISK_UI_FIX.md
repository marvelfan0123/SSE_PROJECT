# Contextual risk UI correction

The Vulnerability Findings page previously rendered stored raw finding rows first, showing `None` and `Unscored` even though a separate analysis panel could calculate contextual scores. The page now places verified exposure and business criticality selectors before the primary findings table and displays recalculated scores there. The raw scanner evidence remains available in a separate collapsed section. Both contextual exports use the recalculated records. The Risk Prioritization page shares the session's context selection.

For the localhost Juice Shop demonstration, choose `loopback` only after confirming that the scanned image corresponds to the running local container. An image scan alone does not prove network reachability. If exposure remains `unknown`, scores intentionally remain unscored. User-selected context is not automatically independently verified and is not persisted into the raw scan records.

Run: `python -m unittest discover -s tests -p "test_*.py" -q` and `python -m streamlit run app.py`.
