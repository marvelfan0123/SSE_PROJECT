# VulnX Attack Graph Intelligence & Stability Audit Report

**Date:** November 12, 2026  
**Auditor:** Graph Analytics Engineer & UI Performance Specialist  
**Status:** **PHYSICS STABILIZED (0% IDLE CPU, ZERO OSCILLATIONS)**

---

## 1. Graph Construction & Topology Integrity

The VulnX attack graph uses **NetworkX** to generate multi-hop relational paths connecting:
$$\text{Internet Attacker} \longrightarrow \text{Open Port} \longrightarrow \text{Service} \longrightarrow \text{Container} \longrightarrow \text{Vulnerable Package} \longrightarrow \text{CVE Node}$$

Edges carry explicit relationship types: `EXPOSES`, `RUNS`, `HOSTS`, `CONTAINS`, `AFFECTED_BY`, and `POTENTIALLY_REACHABLE`.

---

## 2. Physics Stabilization & Hang Elimination

### The Problem in Legacy Barnes-Hut Engines:
In earlier iterations, complete bipartite subgraphs (such as 11 open ports connected to 53 container CVE nodes) generated excessive spring forces under quadratic Barnes-Hut repulsion (`-12000`). Continuous physics simulations caused violent oscillations, browser stuttering, and high client CPU usage.

### The Solution Implemented in `graph/` and `vulngraph_core.py`:
1. **ForceAtlas2 Solver:** Degree-weighted repulsion (`gravitationalConstant: -50`, `damping: 0.6`, `avoidOverlap: 0.5`) converges smoothly.
2. **Off-Screen Computation & Auto-Freeze:** Physics computes off-screen for 450ms then invokes `network.stopSimulation()` and `network.setOptions({ physics: false })`.
3. **Performance Result:** Rendering completes smoothly. Physics stops completely once layout is stabilized. Browser CPU drops to 0% at idle, and nodes remain interactive (draggable/clickable) without shaking.
