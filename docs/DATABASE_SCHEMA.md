# VulnX Database Architecture & Relational Entity Catalog

## 1. Persistence Layer Architecture

VulnX utilizes an ACID-compliant **SQLite 3 relational engine** with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and synchronous durability (`PRAGMA synchronous = NORMAL;`). Database connection pooling is managed via `db_utils.connect_sqlite()`, enforcing immediate transaction serialization (`BEGIN IMMEDIATE`) during audit event writes to prevent hash-chain forks.

The schema design is compatible with PostgreSQL for distributed enterprise deployments.

---

## 2. Entity Catalog (22 Entities)

| Entity # | Table / View Name | Primary Function | Key Columns / Constraints |
| :--- | :--- | :--- | :--- |
| 1 | `users` | User credentials and role assignments | `username (PK)`, `password_hash (PBKDF2)`, `role`, `status`, `created_at` |
| 2 | `roles` | Role permissions definition | `role_name (PK)`, `description` |
| 3 | `user_roles` | Identity to role mapping | Relational association between users and permissions |
| 4 | `assessments` | Top-level security assessment jobs | `assessment_id (PK)`, `target_type`, `target_name`, `criticality`, `status` |
| 5 | `assessment_scanners` | Individual scanner execution state | `assessment_id`, `scanner`, `status`, `message`, `completed_at` |
| 6 | `assessment_hosts` | Discovered network hosts | `id (PK)`, `assessment_id`, `host_ip`, `hostname`, `state`, `created_at` |
| 7 | `assessment_ports` | Open ports and transport protocols | `id (PK)`, `assessment_id`, `host_ip`, `port`, `protocol`, `state` |
| 8 | `assessment_services` | Service identification & versions | `id (PK)`, `assessment_id`, `port_id`, `service_name`, `version_banner` |
| 9 | `vg_containers` | Container runtime metadata | `assessment_id`, `container_id (PK)`, `container_json` |
| 10 | `assessment_images` | Container base images and digests | `assessment_id`, `image_digest`, `image_name`, `image_tag` |
| 11 | `assessment_dependencies` | Extracted SBOM package manifests | `assessment_id`, `package_name`, `installed_version`, `ecosystem` |
| 12 | `assessment_findings` | Normalized scanner findings | `assessment_id`, `finding_id (PK)`, `cve`, `package`, `cvss`, `risk_score` |
| 13 | `finding_sources` | Scanner attribution mapping | `finding_id`, `source (Trivy, Nmap, ZAP)`, `evidence_json` |
| 14 | `assessment_risk_calculations` | Contextual formula audit record | `assessment_id`, `finding_id`, `cvss`, `epss`, `reachability`, `calculated_risk` |
| 15 | `vg_asset_relationships` | Graph edge relational mapping | `source_id`, `target_id`, `relationship_type`, `status` |
| 16 | `attack_paths` | Computed multi-hop attack paths | `path_id (PK)`, `assessment_id`, `source_node`, `target_cve`, `confidence` |
| 17 | `ai_recommendations` | GenAI copilot playbooks & WAF rules | `id (PK)`, `finding_id`, `assessment_id`, `provider`, `playbook_json` |
| 18 | `remediation_tickets` | Maker-Checker governance tickets | `id (PK)`, `assessment_id`, `finding_id`, `status`, `owner`, `requested_by` |
| 19 | `remediation_ticket_events` | Ticket lifecycle audit history | `id (PK)`, `ticket_id`, `actor`, `actor_role`, `old_status`, `new_status` |
| 20 | `staging_evidence` | Staging test evidence & build logs | `id (PK)`, `ticket_id`, `uploaded_by`, `filename`, `content_summary` |
| 21 | `assessment_comparisons` | Baseline vs. rescan diff evidence | `id (PK)`, `baseline_assessment_id`, `rescan_assessment_id`, `fixed_count` |
| 22 | `audit_events` | Immutable HMAC-SHA256 audit ledger | `id (PK)`, `occurred_at`, `username`, `action`, `previous_hash`, `event_hash` |

