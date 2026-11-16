# Automatic Asset Criticality Assessment Update

## What changed

- Replaced the four manual score sliders as the primary workflow with a **Run automatic criticality assessment** action.
- Added read-only Docker metadata collection for matching containers using `docker ps` and `docker inspect`.
- The collector reads image/container identity, labels, networks, port metadata, restart policy and health-check presence. It deliberately does **not** collect environment-variable values because they can contain secrets.
- Added `asset_criticality_engine.py` to translate supported evidence into the four category scores.
- Results, evidence explanations, confidence, missing categories and assessment status are saved in SQLite (`asset_profiles.evidence_json`); existing databases are migrated in place.
- Fully supported assessments automatically set Low/Medium/High/Critical and flow into the existing per-asset risk engine.
- Incomplete assessments stay **Unassigned** and risk scores remain provisional. VulnX does not invent missing business facts.
- Every automatic assessment is recorded in the audit log.

## Evidence policy

VulnX accepts explicit Docker labels as direct 1–5 category evidence:

- `com.vulnx.data-sensitivity`
- `com.vulnx.business-importance`
- `com.vulnx.availability-impact`
- `com.vulnx.dependency-impact`

Optional environment metadata:

- `com.vulnx.environment=development|testing|staging|production`

A recognized local Juice Shop/DVWA training target can receive lab-context scores for business importance and availability impact. This does not imply anything about its data sensitivity or dependencies.

Trivy CVE counts/severity, Nmap open ports, image names and ZAP alert counts are **not** treated as proof of business importance or data sensitivity.

## Example Docker Compose labels

```yaml
services:
  app:
    image: example/app:1.0
    labels:
      com.vulnx.data-sensitivity: "3"
      com.vulnx.business-importance: "4"
      com.vulnx.availability-impact: "3"
      com.vulnx.dependency-impact: "2"
      com.vulnx.environment: "staging"
```

These values must reflect the actual environment's documented classification; do not copy example values blindly. Recreate/redeploy the container after changing labels so Docker inspect can read them.

## Limitations

- Docker metadata cannot reveal the real contents/classification of a database or prove business criticality by itself.
- Docker network membership is not proof that one service depends on another; network peers are not automatically scored as dependencies.
- The four 1–5 labels represent organization-provided classification metadata. VulnX validates and applies them; it does not independently verify the truth of the business claims.
- If required evidence is missing, the overall result remains Unassigned/Insufficient evidence.

## Validation

- Unit tests cover explicit labels, environment-only evidence, local lab context, missing evidence, invalid labels and the rule that scanner severity cannot create business criticality.
- Full automated suite: 121 tests passed in this build environment.
- Python compilation: passed.
- Live Docker inspection and Streamlit UI still need verification on the user's Windows machine.
