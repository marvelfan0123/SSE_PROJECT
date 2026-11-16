# VulnX Attack Graph Intelligence & Topology Specification

## 1. Graph Construction Principles

The VulnX attack graph transforms flat vulnerability lists into a relational, multi-hop topology using **NetworkX**. It visualizes how an external threat actor can traverse through perimeter ports, web services, container runtimes, and application dependencies to reach exploitable vulnerabilities.

---

## 2. Graph Node Ontology

| Node Type | Color | Visual Icon | Description |
| :--- | :--- | :---: | :--- |
| **Attacker** | `#EF4444` (Red) | 💀 | External untrusted threat actor / Internet origin. |
| **Host** | `#3B82F6` (Blue) | 🖥️ | Physical or virtual host machine / IP address. |
| **Open Port** | `#F59E0B` (Amber) | 🔌 | TCP/UDP port confirmed open by Nmap. |
| **Service** | `#10B981` (Green) | ⚙️ | Detected application service / daemon banner. |
| **Container** | `#6366F1` (Indigo) | 📦 | Docker container runtime instance. |
| **Image** | `#8B5CF6` (Purple) | 💿 | Container base image digest and tag. |
| **Dependency** | `#06B6D4` (Cyan) | 📚 | Software library or package identified by Trivy. |
| **CVE** | Severity-coded | 🚨 | Common Vulnerabilities and Exposures record. |

---

## 3. Relational Edge Semantics

- `EXPOSES`: Host exposes an Open Port.
- `RUNS`: Open Port runs an identified Service.
- `HOSTS`: Host or network hosts a Docker Container.
- `CONTAINS`: Container contains a Software Dependency.
- `AFFECTED_BY`: Dependency or Service is affected by a CVE.
- `POTENTIALLY_REACHABLE`: Inferred path through unsegmented Docker bridges.

---

## 4. Physics Engine & Stability Guarantees

Previous graph engines suffered from spring oscillations when handling complete bipartite subgraphs ($K_{m,n}$). VulnX incorporates:
1. **ForceAtlas2 Layout Solver:** Uses degree-weighted repulsion (`gravitationalConstant: -50`, `damping: 0.6`, `avoidOverlap: 0.5`).
2. **Off-screen Computation & Auto-Freeze:** Graph physics executes in memory for 450ms then invokes `network.stopSimulation()` and `network.setOptions({ physics: false })`. This completely eliminates shaking, hangs, and drops CPU utilization to 0%.

