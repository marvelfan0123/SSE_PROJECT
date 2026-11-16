"""VulnX: Scanning and Vulnerability Management Platform.

Enterprise-grade multi-scanner vulnerability orchestration, asset correlation,
contextual risk prioritization, attack path analysis, and remediation governance:
1. Overview (Real-time assessment metrics, remediation status, and scanner health)
2. Security Assessment (Authorized target validation, scanner configuration, and live execution)
3. Findings (Canonical 0-10 contextual risk prioritization, OWASP Top 10:2025, search & filters)
4. Attack Graph (Evidence-backed NetworkX + PyVis visualization across 8 node types)
5. Asset Inventory (Hosts, ports, services, containers, images, dependencies)
6. Remediation Governance (Analyst recommendations, Approver decisions, Maker-Checker)
7. Scan History (Persisted historical assessments, executive exports, and scan comparisons)
"""
from __future__ import annotations

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import html
import json
import io
import csv
import os
import hashlib
import hmac
import textwrap
from pathlib import Path
from datetime import datetime, timezone

import audit_checkpoint
from config import ensure_audit_checkpoint_config

# Configure the HMAC audit checkpoint key/file (random per-install key, no hardcoded secret)
ensure_audit_checkpoint_config()

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

from auth import (
    authenticate, can_scan, can_manage_approvals, can_create_remediation,
    create_user, list_users, set_user_status, change_password, admin_set_password,
    require_permission, has_permission, is_initial_setup_required, bootstrap_initial_admin,
)
from security_controls import login_allowed, record_login_attempt, deployment_warnings, csv_cell
from audit_log import initialize_audit_table, log_event, get_audit_events, verify_audit_chain
from audit_checkpoint import create_checkpoint, verify_checkpoint
from assessment_manager import (
    REPORT_DIR, create_assessment, find_recent_active_assessment, get_assessment,
    launch_worker, list_assessments, retry_failed_scanners, recover_interrupted_assessment,
    cancel_assessment, load_vg_evidence, save_findings, initialize as initialize_assessments,
)
from docker_lab import scanner_health_summary
from phase2_progress import scanner_progress, scanner_timeline
from assessment_portal import make_plan, validate_docker_image, validate_host, validate_local_web_url
from scan_flow import landing_page, allowed_pages, RESULT_PAGES, coverage_comparable, dashboard_metrics
from assessment_views import (
    visible_assessments, assessment_ready, findings_for,
    severity_counts, findings_rows, findings_csv, scanner_summary, unique_assets,
)
from vulngraph_core import (
    MODEL_VERSION, contextual_risk, make_attack_graph, filter_attack_graph,
    generate_attack_graph_html, parse_docker_inspect, correlate_ports, NODE_STYLES,
    score_findings_canonical as analyze_findings, export_canonical_csv as export_csv,
    make_global_attack_graph, compute_global_graph_stats, filter_global_attack_graph,
    generate_global_attack_graph_html,
)
from owasp_classifier import classify, CATEGORIES as OWASP_CATEGORIES
from remediation_workflow import (
    create_ticket, change_ticket, STATES as REMEDIATION_STATES, initialize as initialize_remediation,
)
from system_reset import reset_all_assessment_data, get_assessment_data_summary
from scan_comparison import compare_scans
from phase5_reporting import build_snapshot, export_html as export_exec_html, export_json as export_exec_json
import importlib
import ui_components
importlib.reload(ui_components)
from ui_components import (
    load_custom_css, section_header, kpi_card, severity_badge,
    scanner_status_pill, empty_state, render_severity_donut, render_risk_histogram,
    render_top_navbar, render_remediation_progress,
    SEVERITY_COLORS,
)

st.set_page_config(
    page_title="VulnX | Scanning and Vulnerability Management Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load unified enterprise design system (Wiz / CrowdStrike / Snyk dark palette)
load_custom_css("styles.css")

if "vulnx_user" not in st.session_state:
    st.session_state.vulnx_user = None

if not st.session_state.vulnx_user:
    initialize_audit_table()
    initialize_assessments()
    st.markdown("<style>[data-testid='stSidebar']{display:none} .block-container{padding-top: max(1.2rem, calc(50vh - 220px)) !important; padding-bottom: 1rem !important; max-width: 1120px !important;} header[data-testid='stHeader']{display:none !important;}</style>", unsafe_allow_html=True)

    # 3D Glowing Cybersecurity Shield SVG Art
    shield_svg = """<svg class="vx-shield-svg" width="300" height="135" viewBox="0 0 380 200" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="shieldGrad" x1="140" y1="20" x2="240" y2="180" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#4285FF"/>
          <stop offset="50%" stop-color="#795BFF"/>
          <stop offset="100%" stop-color="#35C6E8"/>
        </linearGradient>
        <linearGradient id="glowGrad" x1="190" y1="30" x2="190" y2="170" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#795BFF" stop-opacity="0.75"/>
          <stop offset="100%" stop-color="#4285FF" stop-opacity="0.12"/>
        </linearGradient>
        <filter id="neonGlow" x="0" y="0" width="380" height="200" filterUnits="userSpaceOnUse">
          <feGaussianBlur stdDeviation="6" result="blur"/>
          <feMerge>
            <feMergeNode in="blur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <path d="M 40 100 Q 190 20 340 100 Q 190 180 40 100" stroke="#232C45" stroke-width="1.5" stroke-dasharray="4 4" fill="none"/>
      <circle cx="65" cy="85" r="4" fill="#35C6E8"/>
      <line x1="65" y1="85" x2="150" y2="80" stroke="#4285FF" stroke-width="1" stroke-opacity="0.4"/>
      <circle cx="315" cy="115" r="4" fill="#795BFF"/>
      <line x1="315" y1="115" x2="230" y2="120" stroke="#795BFF" stroke-width="1" stroke-opacity="0.4"/>
      <circle cx="100" cy="140" r="3" fill="#4285FF"/>
      <line x1="100" y1="140" x2="160" y2="135" stroke="#35C6E8" stroke-width="1" stroke-opacity="0.3"/>
      <circle cx="280" cy="55" r="3" fill="#35C6E8"/>
      <line x1="280" y1="55" x2="225" y2="70" stroke="#4285FF" stroke-width="1" stroke-opacity="0.3"/>
      <path d="M 190 25 L 245 48 C 245 105 220 148 190 170 C 160 148 135 105 135 48 Z" 
            fill="#0E1528" stroke="url(#shieldGrad)" stroke-width="3" filter="url(#neonGlow)"/>
      <path d="M 190 38 L 233 56 C 233 100 213 135 190 154 C 167 135 147 100 147 56 Z" 
            fill="url(#glowGrad)" stroke="#35C6E8" stroke-width="1.2" stroke-opacity="0.7"/>
      <circle cx="190" cy="95" r="14" fill="#151F32" stroke="#4285FF" stroke-width="2"/>
      <circle cx="190" cy="95" r="6" fill="#35C6E8"/>
      <line x1="190" y1="56" x2="190" y2="81" stroke="#35C6E8" stroke-width="2"/>
      <line x1="190" y1="109" x2="190" y2="136" stroke="#795BFF" stroke-width="2"/>
      <line x1="168" y1="95" x2="176" y2="95" stroke="#4285FF" stroke-width="2"/>
      <line x1="204" y1="95" x2="212" y2="95" stroke="#4285FF" stroke-width="2"/>
      <circle cx="190" cy="95" r="22" stroke="#35C6E8" stroke-width="1" stroke-opacity="0.5" stroke-dasharray="2 2"/>
    </svg>"""

    # Split-Screen Layout: 58% Left (Branding & 3D Art), 42% Right (Glassmorphic Login Card)
    col_left, col_right = st.columns([5.8, 4.2], gap="large")

    with col_left:
        st.markdown(f"""
        <div class="vx-login-hero-container">
            <div class="vx-login-badge">ENTERPRISE SECURITY CONSOLE</div>
            <div class="vx-login-title">VulnX</div>
            <div class="vx-login-subtitle">Scanning and Vulnerability Management Platform</div>
            <div class="vx-login-headline">“Discover vulnerabilities. Understand risks. Stay ahead.”</div>
            <div class="vx-login-desc">
                An integrated platform for vulnerability scanning, security intelligence, risk prioritization and attack path analysis.
            </div>
            <div class="vx-shield-art-wrap">
                {shield_svg}
            </div>
            <div class="vx-login-features-row">
                <div class="vx-login-feature-item">
                    <span style="color:#4285FF; font-size:1.1rem;">🛡️</span>
                    <span>Vulnerability Scanning</span>
                </div>
                <div class="vx-login-feature-item">
                    <span style="color:#795BFF; font-size:1.1rem;">⚡</span>
                    <span>Risk Intelligence</span>
                </div>
                <div class="vx-login-feature-item">
                    <span style="color:#35C6E8; font-size:1.1rem;">🕸️</span>
                    <span>Attack Path Analysis</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_right:
        if is_initial_setup_required():
            with st.form("first_run_admin_form"):
                st.markdown("""
                <div class="vx-login-form-header">
                    <div class="vx-glass-login-title">Administrator Setup</div>
                    <div class="vx-glass-login-sub">Establish the initial platform administrator account to initialize VulnX.</div>
                </div>
                """, unsafe_allow_html=True)
                init_user = st.text_input("Administrator Username", value="admin", autocomplete="username")
                init_pw1 = st.text_input(
                    "Administrator Password",
                    type="password",
                    help="At least 10 characters with uppercase, lowercase, digit, and special character.",
                    autocomplete="new-password",
                )
                init_pw2 = st.text_input("Confirm Password", type="password", autocomplete="new-password")
                init_submit = st.form_submit_button("Establish Administrator & Initialize", type="primary", use_container_width=True)

            if init_submit:
                if init_pw1 != init_pw2:
                    st.error("Passwords do not match.")
                else:
                    try:
                        created = bootstrap_initial_admin(init_user, init_pw1)
                        log_event(created["username"], "Admin", "initial_admin_bootstrapped", "user", created["username"])
                        st.success(f"Administrator '{created['username']}' established. Sign in below.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Initialization failed: {exc}")
        else:
            with st.form("login_form"):
                st.markdown("""
                <div class="vx-login-form-header">
                    <div class="vx-glass-login-title">Welcome back</div>
                    <div class="vx-glass-login-sub">Sign in to access your security workspace.</div>
                </div>
                """, unsafe_allow_html=True)
                username = st.text_input("Username", autocomplete="username")
                password = st.text_input("Password", type="password", autocomplete="current-password")
                submit = st.form_submit_button("Sign in to VulnX", type="primary", use_container_width=True)

            if submit:
                allowed = login_allowed(username)
                if not allowed:
                    log_event(username, "", "login_blocked_rate_limit", "session")
                    st.error("Account temporarily locked due to 5 consecutive failed login attempts. Please try again in 5 minutes.")
                else:
                    user = authenticate(username, password)
                    record_login_attempt(username, bool(user))
                    if user:
                        log_event(user["username"], user["role"], "login_success", "session")
                        st.session_state.vulnx_user = user
                        st.rerun()
                    else:
                        log_event(username, "", "login_failed", "session")
                        st.error("Invalid credentials or account deactivated. Please try again.")

        st.markdown("""
        <div class="vx-auth-notice">
            🔒 Authorized security personnel only.<br>
            All assessment actions and access sessions are cryptographically audited.
        </div>
        """, unsafe_allow_html=True)
    st.stop()

user = st.session_state.get("vulnx_user") or {"username": "anonymous", "role": "Analyst"}
username, role = user["username"], user["role"]

from nvd_queue import ensure_background_enricher_running, get_queue_stats
ensure_background_enricher_running()

all_assessments = visible_assessments(list_assessments(limit=200), username, role)
known_ids = {a["assessment_id"] for a in all_assessments}
selected_id = st.session_state.get("vulnx_selected_assessment")

if selected_id not in known_ids:
    selected_id = all_assessments[0]["assessment_id"] if all_assessments else None
    st.session_state.vulnx_selected_assessment = selected_id

selected = get_assessment(selected_id) if selected_id else None
ready = assessment_ready(selected)
active = bool(selected and selected.get("status") in {"Queued", "Running", "Discovering assets", "Processing findings"})

if "vulnx_page" not in st.session_state:
    st.session_state.vulnx_page = "Overview"

# Track sidebar collapse state
is_sb_collapsed = st.session_state.get("vx_sidebar_collapsed", False)

# Clean Enterprise Navigation Sidebar
with st.sidebar:
    if is_sb_collapsed:
        st.markdown("""
        <style>
        [data-testid="stSidebar"] {
            min-width: 72px !important;
            max-width: 72px !important;
            width: 72px !important;
        }
        [data-testid="stSidebar"] > div:first-child {
            padding-left: 6px !important;
            padding-right: 6px !important;
        }
        .vx-brand-text, .vx-nav-section-title, .vx-scope-header, .vx-scope-empty, .vx-user-card-details, .vx-version-tag, [data-testid="stSelectbox"] {
            display: none !important;
        }
        </style>
        """, unsafe_allow_html=True)

    # 1. Admin Panel (Compact Navigation Item - Top of Sidebar)
    if role == "Admin":
        admin_is_cur = st.session_state.vulnx_page in ("User Management", "Audit Logs", "Audit Verification", "System Management")
        btn_label = "🛡️  Admin Panel" if not is_sb_collapsed else "🛡️"
        btn_key = "nav_btn_top_admin" if not is_sb_collapsed else "nav_btn_top_admin_collapsed"
        if st.button(btn_label, key=btn_key, use_container_width=True, type="primary" if admin_is_cur else "secondary"):
            st.session_state.vulnx_page = "User Management"
            st.rerun()

    # 2. VulnX Branding (Immediately below Admin Panel)
    if not is_sb_collapsed:
        st.markdown("""
        <div class="vx-brand-container">
            <div class="vx-brand-logo">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L3 7V12C3 17.52 6.84 22.74 12 24C17.16 22.74 21 17.52 21 12V7L12 2Z" fill="url(#vx_brand_grad)" stroke="#35C6E8" stroke-width="1.2"/>
                    <path d="M9 12L11 14L15 10" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <defs>
                        <linearGradient id="vx_brand_grad" x1="3" y1="2" x2="21" y2="24" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#4285FF"/>
                            <stop offset="0.6" stop-color="#795BFF"/>
                            <stop offset="1" stop-color="#151F32"/>
                        </linearGradient>
                    </defs>
                </svg>
            </div>
            <div class="vx-brand-text">
                <div class="vx-brand-title">VulnX <span class="vx-brand-badge">SOC</span></div>
                <div class="vx-brand-subtitle">Vulnerability Management</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="display:flex; justify-content:center; padding: 2px 0 6px 0;">
            <div class="vx-brand-logo">VX</div>
        </div>
        """, unsafe_allow_html=True)

    # 3. Active Target Scope (Compact Professional Selector)
    if not is_sb_collapsed:
        st.markdown("""
        <div class="vx-scope-header">
            <span class="vx-status-dot online"></span>
            <span class="vx-scope-title">ACTIVE TARGET SCOPE</span>
        </div>
        """, unsafe_allow_html=True)
        if all_assessments:
            assessment_options = {a["assessment_id"]: a["target_name"] for a in all_assessments}
            chosen_id = st.selectbox(
                "Active Target Scope",
                options=list(assessment_options.keys()),
                index=list(assessment_options.keys()).index(selected_id) if selected_id in assessment_options else 0,
                format_func=lambda x: f"🎯  {assessment_options.get(x, x)}",
                key="sb_assessment_selector",
                label_visibility="collapsed"
            )
            if chosen_id != selected_id:
                st.session_state.vulnx_selected_assessment = chosen_id
                st.rerun()
        else:
            st.markdown('<div class="vx-scope-empty">No active scope recorded</div>', unsafe_allow_html=True)

    # Section: WORKSPACE
    if not is_sb_collapsed:
        st.markdown('<div class="vx-nav-section-title">WORKSPACE</div>', unsafe_allow_html=True)
    workspace_nav_items = [
        ("📊", "Overview", "Overview"),
        ("⚡", "Security Assessments", "Security Assessments"),
        ("🌐", "Assets", "Assets"),
        ("🔍", "Findings", "Findings"),
        ("🕸️", "Attack Graph", "Attack Graph"),
        ("🤖", "AI Security Copilot", "AI Security Copilot"),
    ]
    for icon, label, section_key in workspace_nav_items:
        is_cur = (st.session_state.vulnx_page in (label, section_key)) or \
                 (label == "Overview" and st.session_state.vulnx_page in ("Dashboard", "Overview")) or \
                 (label == "Security Assessments" and st.session_state.vulnx_page in ("Security Assessment", "New Assessment", "Scan Progress")) or \
                 (label == "Assets" and st.session_state.vulnx_page in ("Asset Inventory", "Assets")) or \
                 (label == "Findings" and st.session_state.vulnx_page in ("Vulnerability Findings", "Findings", "Risk Prioritization")) or \
                 (label == "Attack Graph" and st.session_state.vulnx_page in ("Attack Graph", "Attack Paths")) or \
                 (label == "AI Security Copilot" and st.session_state.vulnx_page in ("AI Security Copilot", "AI Copilot", "AI Advisor"))
        btn_text = f"{icon}  {label}" if not is_sb_collapsed else icon
        if st.button(btn_text, key=f"nav_btn_ws_{label}", use_container_width=True, type="primary" if is_cur else "secondary"):
            st.session_state.vulnx_page = section_key
            st.rerun()

    # Section: OPERATIONS
    if not is_sb_collapsed:
        st.markdown('<div class="vx-nav-section-title">OPERATIONS</div>', unsafe_allow_html=True)
    ops_nav_items = [
        ("🛡️", "Remediation", "Remediation"),
        ("📜", "Scan History", "Scan History"),
    ]
    for icon, label, section_key in ops_nav_items:
        is_cur = (st.session_state.vulnx_page in (label, section_key)) or \
                 (label == "Remediation" and st.session_state.vulnx_page in ("Remediation Governance", "Verification")) or \
                 (label == "Scan History" and st.session_state.vulnx_page in ("My Scans", "Reports"))
        btn_text = f"{icon}  {label}" if not is_sb_collapsed else icon
        if st.button(btn_text, key=f"nav_btn_ops_{label}", use_container_width=True, type="primary" if is_cur else "secondary"):
            st.session_state.vulnx_page = section_key
            st.rerun()

    # Section: ADMINISTRATION (Role Gated)
    if not is_sb_collapsed:
        st.markdown('<div class="vx-nav-section-title">ADMINISTRATION</div>', unsafe_allow_html=True)
    if role == "Admin":
        admin_nav_items = [
            ("👥", "User Management", "User Management"),
            ("🔐", "Audit Logs", "Audit Logs"),
            ("🛠️", "System Management", "System Management"),
            ("⚙️", "Settings", "Settings"),
        ]
        for icon, label, section_key in admin_nav_items:
            is_cur = (st.session_state.vulnx_page in (label, section_key)) or \
                     (label == "Audit Logs" and st.session_state.vulnx_page == "Audit Verification")
            btn_text = f"{icon}  {label}" if not is_sb_collapsed else icon
            if st.button(btn_text, key=f"nav_btn_admin_{label}", use_container_width=True, type="primary" if is_cur else "secondary"):
                st.session_state.vulnx_page = section_key
                st.rerun()
    else:
        is_cur = (st.session_state.vulnx_page == "Settings")
        btn_text = "⚙️  Settings" if not is_sb_collapsed else "⚙️"
        if st.button(btn_text, key="nav_btn_settings_user", use_container_width=True, type="primary" if is_cur else "secondary"):
            st.session_state.vulnx_page = "Settings"
            st.rerun()

    # User Profile Card & Sign Out
    initials = (username[:2].upper() if username else "VX")
    if not is_sb_collapsed:
        st.markdown(f"""
        <div class="vx-user-card">
            <div class="vx-user-avatar">{html.escape(initials)}</div>
            <div class="vx-user-card-details">
                <div class="vx-user-card-name">{html.escape(username)}</div>
                <div class="vx-user-card-role">
                    <span>{html.escape(role)}</span>
                    <span class="vx-role-pill">Active</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚪  Sign Out", use_container_width=True, key="btn_signout", type="secondary"):
            log_event(username, role, "logout", "session")
            st.session_state.vulnx_user = None
            st.session_state.pop("vulnx_page", None)
            st.rerun()
        if st.button("◀  Collapse Sidebar", key="btn_sb_toggle_bottom", use_container_width=True, type="secondary"):
            st.session_state.vx_sidebar_collapsed = True
            st.rerun()
        st.markdown('<div class="vx-version-tag">VulnX · Vulnerability Management Platform</div>', unsafe_allow_html=True)
    else:
        if st.button("🚪", use_container_width=True, key="btn_signout_collapsed", type="secondary", help="Sign Out"):
            log_event(username, role, "logout", "session")
            st.session_state.vulnx_user = None
            st.session_state.pop("vulnx_page", None)
            st.rerun()
        if st.button("▶", key="btn_sb_expand_bottom", use_container_width=True, type="secondary", help="Expand navigation sidebar"):
            st.session_state.vx_sidebar_collapsed = False
            st.rerun()

# Resolve page alias routing
page = st.session_state.vulnx_page
if page in {"Findings", "Risk Prioritization"}:
    page = "Vulnerability Findings"
elif page in {"Assets"}:
    page = "Asset Inventory"
elif page in {"Security Assessments", "New Assessment", "Scan Progress"}:
    page = "Security Assessment"
elif page in {"AI Security Copilot", "AI Copilot", "AI Advisor"}:
    page = "AI Security Copilot"
elif page in {"Remediation", "Verification"}:
    page = "Remediation Governance"
elif page in {"Scan History", "My Scans", "Reports"}:
    page = "Scan History"
elif page in {"Audit Logs"}:
    page = "Audit Verification"
elif page in {"System Management"}:
    page = "System Management"

# Context extraction for assessment
target_context = selected.get("target") or {} if selected else {}
chosen_exposure = target_context.get("exposure_kind", "unknown")
chosen_criticality = selected.get("criticality", "Normal") if selected else "Normal"
if chosen_exposure not in ("unknown", "loopback", "internal", "all_interfaces", "isolated"):
    chosen_exposure = "unknown"
if target_context.get("automatic_criticality"):
    chosen_criticality = target_context["automatic_criticality"].get("risk_level") or "Unassigned"

# Render structured enterprise top navigation bar (real scanner readiness + active scan count)
@st.cache_data(ttl=15, show_spinner=False)
def _cached_scanner_readiness():
    try:
        items = scanner_health_summary()
        return sum(1 for i in items if i.get("ready")), len(items)
    except Exception:
        return None, None


_ready_scanners, _total_scanners = _cached_scanner_readiness()
_running_scans = sum(1 for a in all_assessments if a.get("status") in {"Queued", "Running", "Discovering assets", "Processing findings"})
render_top_navbar(
    page,
    target_name=selected.get("target_name") if selected else None,
    role=role,
    pipeline_ready=_ready_scanners,
    pipeline_total=_total_scanners,
    active_scans=_running_scans,
)


# -----------------------------------------------------------------------------
# 1. OVERVIEW SECTION
# -----------------------------------------------------------------------------
if page in {"Overview", "Dashboard"}:
    # 1. Unified Overview Header & Scanner Status
    health_items = scanner_health_summary()
    pills_html = "".join([scanner_status_pill(h["scanner"], h["status"], h.get("detail")) for h in health_items])
    st.markdown(f"""
    <div class="vx-overview-header-row">
        <div class="vx-overview-header-info">
            <div class="vx-overview-title-row">
                <span class="vx-overview-title">Overview</span>
                <span class="vx-badge vx-badge-info">SOC Telemetry</span>
            </div>
            <div class="vx-overview-subtitle">
                Operational security posture, vulnerability prioritization, and multi-scanner intelligence telemetry.
            </div>
        </div>
        <div class="vx-overview-health-bar">
            {pills_html}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if not selected:
        st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)
        _, col_card, _ = st.columns([1, 2.2, 1])
        with col_card:
            st.markdown("""
            <div class="vx-empty-card">
                <div class="vx-empty-icon-shield">🛡️</div>
                <div class="vx-empty-title">No Security Assessments Found</div>
                <div class="vx-empty-desc">
                    The database does not contain any completed or active assessments.<br>
                    Initialize your first assessment to discover assets, run vulnerability scanners, and generate attack paths.
                </div>
            </div>
            """, unsafe_allow_html=True)
            _, col_btn, _ = st.columns([0.5, 3, 0.5])
            with col_btn:
                if st.button("Start First Security Assessment", type="primary", use_container_width=True, key="btn_start_first_assessment"):
                    st.session_state.vulnx_page = "Security Assessments"
                    st.session_state.vx_assessment_subview = "New Assessment Wizard"
                    st.session_state.vx_wizard_step = 1
                    st.rerun()
        st.stop()
    else:
        # 2. Assessment Summary Header
        status_raw = str(selected.get("status", "Unknown"))
        status_cls = "success" if status_raw == "Completed" else "medium" if status_raw == "Partial" else "critical" if status_raw == "Failed" else "low"
        st.markdown(f"""
        <div class='vx-summary-banner'>
            <div class='vx-summary-main'>
                <div class='vx-summary-title-row'>
                    <span class='vx-summary-target'>{html.escape(str(selected.get('target_name', '')))}</span>
                    <span class='vx-badge vx-badge-info'>{html.escape(str(selected.get('target_type', '')))}</span>
                    <span class='vx-badge vx-badge-neutral'>Criticality: {html.escape(str(selected.get('criticality', 'Normal')))}</span>
                </div>
                <div class='vx-summary-meta-grid'>
                    <div class='vx-summary-meta-item'><span class='vx-meta-lbl'>Assessment ID:</span> <code>{html.escape(str(selected_id)[:16])}...</code></div>
                    <div class='vx-summary-meta-item'><span class='vx-meta-lbl'>Target Scope:</span> <b>{html.escape(str(selected.get('target_name', '')))}</b></div>
                    <div class='vx-summary-meta-item'><span class='vx-meta-lbl'>Created:</span> {html.escape(str(selected.get('created_at', '')))}</div>
                    <div class='vx-summary-meta-item'><span class='vx-meta-lbl'>Model:</span> <code>{MODEL_VERSION}</code></div>
                </div>
            </div>
            <div class='vx-summary-status'>
                <span class='vx-badge vx-badge-{status_cls} vx-badge-lg'>{html.escape(status_raw.upper())}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        findings = findings_for(selected)
        metrics = dashboard_metrics(selected)
        st.markdown(
            "<div style='font-size:0.78rem; color:#94A3B8; margin:-4px 0 12px 2px;'>"
            "📌 Metrics below describe the <b style='color:#F8FAFC;'>selected assessment only</b>. "
            "Platform-wide totals across all assets are on the <b style='color:#F8FAFC;'>Attack Graph</b> page."
            "</div>",
            unsafe_allow_html=True,
        )
        initialize_remediation()
        from assessment_manager import _db
        with _db() as con:
            con.row_factory = __import__("sqlite3").Row
            ov_tickets = [dict(t) for t in con.execute("SELECT status FROM remediation_tickets WHERE assessment_id=?", (selected_id,)).fetchall()]
        resolved_tickets = sum(1 for t in ov_tickets if t.get("status") == "Resolved")
        open_tickets = len(ov_tickets) - resolved_tickets

        sev = severity_counts([f for f in findings if f.get("is_vulnerability", True) and f.get("source") != "Nmap"])

        # 3. 6 Metric Cards in Responsive 3-Column x 2-Row Grid
        total_assessed_assets = metrics.get("assets", 0)
        total_findings_count = len(findings)
        critical_vulns_count = sev.get("CRITICAL", 0)
        high_vulns_count = sev.get("HIGH", 0)
        completed_assessments_count = sum(1 for a in all_assessments if a.get("status") == "Completed")
        open_remediation_count = open_tickets

        r1_c1, r1_c2, r1_c3 = st.columns(3)
        with r1_c1:
            kpi_card("Total Assessed Assets", total_assessed_assets, "In this assessment", severity="cyan")
        with r1_c2:
            kpi_card("Total Findings", total_findings_count, "This assessment · correlated issues", severity="accent")
        with r1_c3:
            kpi_card("Critical Vulnerabilities", critical_vulns_count, "This assessment · CVSS ≥ 9.0", severity="critical")

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        r2_c1, r2_c2, r2_c3 = st.columns(3)
        with r2_c1:
            kpi_card("High Vulnerabilities", high_vulns_count, "This assessment · CVSS 7.0–8.9", severity="high")
        with r2_c2:
            kpi_card("Completed Assessments", completed_assessments_count, f"Platform-wide · {len(all_assessments)} scans recorded", severity="success")
        with r2_c3:
            kpi_card("Open Remediation Items", open_remediation_count, f"This assessment · {resolved_tickets} resolved", severity="medium")

        ctx_scores = [float(f["risk_score"]) for f in findings if isinstance(f.get("risk_score"), (int, float)) and not isinstance(f.get("risk_score"), bool)]

        # 4. Row 1: Donut Chart for Findings by Severity + Histogram for Contextual Risk
        st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)
        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("<div class='vx-card'><div class='vx-kpi-label' style='margin-bottom:12px;'>VULNERABILITY SEVERITY DISTRIBUTION</div>", unsafe_allow_html=True)
            sev_dict = {
                "Critical": sev.get("CRITICAL", 0),
                "High": sev.get("HIGH", 0),
                "Medium": sev.get("MEDIUM", 0),
                "Low": sev.get("LOW", 0),
                "Info": sev.get("INFO", 0) + sev.get("UNKNOWN", 0),
            }
            render_severity_donut(sev_dict)
            st.markdown("</div>", unsafe_allow_html=True)

        with c_right:
            st.markdown("<div class='vx-card'><div class='vx-kpi-label' style='margin-bottom:12px;'>CONTEXTUAL RISK DISTRIBUTION (0–10 SCALE)</div>", unsafe_allow_html=True)
            render_risk_histogram(ctx_scores)
            st.markdown("</div>", unsafe_allow_html=True)

        # 5. Row 2: Remediation Progress + Scanner Infrastructure Availability
        gov_left, gov_right = st.columns([1.1, 0.9])
        with gov_left:
            st.markdown("<div class='vx-card'><div class='vx-kpi-label' style='margin-bottom:12px;'>REMEDIATION GOVERNANCE PROGRESS</div>", unsafe_allow_html=True)
            in_prog_tickets = sum(1 for t in ov_tickets if t.get("status") in ("In Progress", "In progress", "Assigned", "Under Review"))
            render_remediation_progress(open_tickets, in_prog_tickets, resolved_tickets)
            st.markdown("</div>", unsafe_allow_html=True)

        with gov_right:
            st.markdown("<div class='vx-card'><div class='vx-kpi-label' style='margin-bottom:12px;'>SCANNER INFRASTRUCTURE TELEMETRY</div>", unsafe_allow_html=True)
            pills_grid_html = "".join([scanner_status_pill(h["scanner"], h["status"], h.get("detail")) for h in health_items])
            st.markdown(f"<div style='display:flex; flex-wrap:wrap; gap:8px; padding-top:4px;'>{pills_grid_html}</div>", unsafe_allow_html=True)
            st.markdown("<div style='margin-top:12px; font-size:0.75rem; color:#94A3B8;'>Pipelines: Trivy (Containers), Nmap (Network), OWASP ZAP (Web Apps).</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        # 6. Row 3: Top Riskiest Actionable Findings Card
        st.markdown("<div class='vx-card'>", unsafe_allow_html=True)
        st.markdown("""
        <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;'>
            <div class='vx-kpi-label' style='margin-bottom:0;'>RECENT HIGH-PRIORITY FINDINGS</div>
            <span style='font-size:0.75rem; color:#8A94AD;'>Ranked by Canonical Contextual Risk Score</span>
        </div>
        """, unsafe_allow_html=True)

        top_findings = [f for f in findings if f.get("is_vulnerability", True)]
        top_findings.sort(key=lambda x: (x.get("risk_score") is not None, x.get("risk_score") if x.get("risk_score") is not None else -1.0, x.get("cvss") or 0.0), reverse=True)

        if top_findings:
            top5 = top_findings[:5]
            top_rows = []
            for f in top5:
                cve = f.get("cve") or "—"
                risk = f.get("risk_score")
                risk_display = f"{risk:.2f} / 10" if isinstance(risk, (int, float)) else "Provisional"
                cvss_val = f.get("cvss")
                cvss_display = f"{cvss_val:.1f}" if isinstance(cvss_val, (int, float)) else "—"
                epss_val = f.get("epss")
                epss_display = f"{epss_val*100:.1f}%" if isinstance(epss_val, (int, float)) else "—"
                top_rows.append({
                    "Severity": f.get("severity", "Info"),
                    "CVE": cve,
                    "Title": f.get("title", "")[:85],
                    "Package": f.get("package") or "—",
                    "CVSS": cvss_display,
                    "EPSS": epss_display,
                    "Contextual Risk": risk_display,
                    "Scanner": f.get("source", "—"),
                })
            st.dataframe(
                pd.DataFrame(top_rows),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Title": st.column_config.TextColumn("Vulnerability Title", width="large"),
                    "Contextual Risk": st.column_config.TextColumn("Contextual Risk", width="medium"),
                }
            )
        else:
            empty_state("🛡️", "No Actionable Vulnerabilities", "Zero high-priority vulnerabilities identified in this target.")
        st.markdown("</div>", unsafe_allow_html=True)

        # 7. Row 4: Recent Security Assessments Pipeline Card
        st.markdown("<div class='vx-card'>", unsafe_allow_html=True)
        st.markdown("""
        <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;'>
            <div class='vx-kpi-label' style='margin-bottom:0;'>RECENT SECURITY ASSESSMENTS</div>
            <span style='font-size:0.75rem; color:#8A94AD;'>Historical Pipeline Executions in SQLite</span>
        </div>
        """, unsafe_allow_html=True)
        if all_assessments:
            recent_recs = []
            for a in all_assessments[:8]:
                recent_recs.append({
                    "Assessment ID": a["assessment_id"],
                    "Target Scope": a.get("target_name", "—"),
                    "Target Type": a.get("target_type", "—"),
                    "Status": a.get("status", "—"),
                    "Created At": a.get("created_at", "—")[:19],
                    "Model": MODEL_VERSION,
                })
            st.dataframe(pd.DataFrame(recent_recs), hide_index=True, use_container_width=True)
        else:
            st.caption("No historical assessments found.")
        st.markdown("</div>", unsafe_allow_html=True)

        # Operational Details: Telemetry and Recent History
        with st.expander("📊 Scanner Execution Telemetry", expanded=False):
            scanners = selected.get("scanners", [])
            if scanners:
                st.dataframe(pd.DataFrame([{
                    "Scanner": s.get("scanner"),
                    "Status": s.get("status"),
                    "Started": s.get("started_at", "—"),
                    "Completed": s.get("completed_at", "—"),
                    "Message": s.get("message", "—")
                } for s in scanners]), hide_index=True, use_container_width=True)
            else:
                st.caption("No scanner telemetry available.")


# -----------------------------------------------------------------------------
# 2. SECURITY ASSESSMENT SECTION
# -----------------------------------------------------------------------------
elif page in {"Security Assessment", "New Assessment", "Scan Progress"}:
    section_header(
        "Security Assessment Center",
        "One Target. One Assessment. Complete Visibility. Configure authorized targets, orchestrate scanners, and monitor live execution states.",
        "TARGET WIZARD"
    )

    if not can_scan(role):
        st.warning("Your role does not permit creating or initiating security assessments.")
        st.stop()

    if st.session_state.get("vx_launch_banner"):
        st.success(st.session_state.pop("vx_launch_banner"))

    subview_options = ["New Assessment Wizard", "Live Execution & Scanner Telemetry"]
    default_subview = st.session_state.get("vx_assessment_subview", "New Assessment Wizard")
    if default_subview not in subview_options:
        default_subview = "New Assessment Wizard"
    chosen_subview = st.radio(
        "Assessment Workspace Mode",
        subview_options,
        index=subview_options.index(default_subview),
        horizontal=True,
        key="vx_ui_subview_radio",
    )
    st.session_state["vx_assessment_subview"] = chosen_subview

    if chosen_subview == "New Assessment Wizard":
        valid_modes = ("Running lab container", "Docker image", "Local web application", "Local host", "Import Trivy JSON report")
        step = st.session_state.get("vx_wizard_step", 1)
        if step not in (1, 2) or (step == 2 and st.session_state.get("vx_target_mode") not in valid_modes):
            step = 1
            st.session_state.vx_wizard_step = 1

        st.markdown(f"""
        <div class='vx-wizard-steps-row'>
            <div class='vx-wizard-step {"active" if step == 1 else ""}'>
                <div class='vx-wizard-step-tag'>STEP 1</div>
                <div class='vx-wizard-step-title'>Target Infrastructure</div>
                <div class='vx-wizard-step-desc'>Validate target scope & asset parameters</div>
            </div>
            <div class='vx-wizard-arrow'>&rarr;</div>
            <div class='vx-wizard-step {"active" if step == 2 else ""}'>
                <div class='vx-wizard-step-tag'>STEP 2</div>
                <div class='vx-wizard-step-title'>Scanners & Risk Model</div>
                <div class='vx-wizard-step-desc'>Configure Trivy, Nmap, ZAP & exposure model</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if step == 1:
            st.subheader("Step 1: Authorized Target Selection")
            current_mode = st.session_state.get("vx_target_mode", "Running lab container")
            mode_idx = list(valid_modes).index(current_mode) if current_mode in valid_modes else 0
            mode = st.selectbox(
                "Target Type",
                list(valid_modes),
                index=mode_idx,
                key="vx_ui_target_mode"
            )
            st.session_state["vx_target_mode"] = mode

            custom_image = None
            custom_host = None
            custom_ports = None
            custom_url = None
            lab = st.session_state.get("vx_saved_lab") if st.session_state.get("vx_saved_lab") in ("Juice Shop", "DVWA") else "Juice Shop"

            if mode == "Running lab container":
                lab = st.selectbox("Target Lab Container", ["Juice Shop", "DVWA"], index=(0 if lab == "Juice Shop" else 1), key="vx_ui_lab_choice")
                st.caption("Connects to a running local Docker container and inspects published port bindings.")
            elif mode == "Docker image":
                src = st.radio("Image Source", ["Configured lab image", "Custom Docker image"], key="vx_ui_img_src")
                if src == "Custom Docker image":
                    custom_image = st.text_input("Docker Image Reference", value=st.session_state.get("vx_saved_custom_image") or "python:3.11-slim", key="vx_ui_custom_image")
                else:
                    lab = st.selectbox("Configured Lab Image", ["Juice Shop", "DVWA"], index=(0 if lab == "Juice Shop" else 1), key="vx_ui_lab_img")
            elif mode == "Local web application":
                custom_url = st.selectbox("Target Web Endpoint", ["http://localhost:3000/", "http://localhost:8081/"], key="vx_ui_custom_url")
            elif mode == "Local host":
                custom_host = st.text_input("Target Host IP", value=st.session_state.get("vx_saved_custom_host") or "127.0.0.1", key="vx_ui_custom_host")
                custom_ports = st.text_input("Ports to Scan (TCP comma-separated)", value=st.session_state.get("vx_saved_custom_ports") or "3000, 8080, 8081", key="vx_ui_custom_ports")
            elif mode == "Import Trivy JSON report":
                st.caption("Upload an authentic Trivy JSON vulnerability scan report (`trivy image --format json`) for ingestion, enrichment, and risk scoring.")
                uploaded_trivy = st.file_uploader("Trivy JSON Report File", type=["json"], key="vx_ui_trivy_upload")
                if uploaded_trivy is not None:
                    st.session_state["vx_saved_trivy_json"] = uploaded_trivy.getvalue().decode("utf-8-sig", errors="replace")
                    st.session_state["vx_saved_trivy_name"] = uploaded_trivy.name
                    t_bytes = uploaded_trivy.getvalue()
                    t_size = len(t_bytes)
                    t_size_str = f"{t_size / 1024:.2f} KB" if t_size >= 1024 else f"{t_size} B"
                    st.markdown(f"""
                    <div class="vx-file-preview-card">
                        <div class="vx-file-preview-left">
                            <div class="vx-file-icon-box">📦</div>
                            <div class="vx-file-meta">
                                <div class="vx-file-name" title="{html.escape(uploaded_trivy.name)}">{html.escape(uploaded_trivy.name)}</div>
                                <div class="vx-file-sub">
                                    <span class="vx-file-type-pill">JSON</span>
                                    <span>•</span>
                                    <span class="vx-file-size-pill">{t_size_str}</span>
                                    <span>•</span>
                                    <span class="vx-badge vx-badge-low" style="font-size: 0.68rem; padding: 2px 8px;">🟢 Report Loaded</span>
                                </div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            st.session_state["vx_saved_lab"] = lab
            st.session_state["vx_saved_custom_image"] = custom_image
            st.session_state["vx_saved_custom_host"] = custom_host
            st.session_state["vx_saved_custom_ports"] = custom_ports
            st.session_state["vx_saved_custom_url"] = custom_url

            if st.button("Continue to Configuration →", type="primary"):
                if mode == "Import Trivy JSON report" and not st.session_state.get("vx_saved_trivy_json"):
                    st.error("Upload a Trivy JSON report file before continuing to configuration.")
                else:
                    if mode == "Import Trivy JSON report":
                        try:
                            parsed_preview = json.loads(st.session_state["vx_saved_trivy_json"])
                            if not isinstance(parsed_preview, dict) or not isinstance(parsed_preview.get("Results"), list):
                                raise ValueError("JSON file does not contain a valid Trivy 'Results' array.")
                        except Exception as exc:
                            st.error(f"Invalid Trivy JSON file: {exc}")
                            st.stop()
                    st.session_state["vx_target_mode"] = mode
                    st.session_state.vx_wizard_step = 2
                    st.rerun()

        elif step == 2:
            st.subheader("Step 2: Scanner Selection & Risk Model Configuration")
            mode = st.session_state.get("vx_target_mode", "Running lab container")
            lab = st.session_state.get("vx_saved_lab") or "Juice Shop"
            custom_image = st.session_state.get("vx_saved_custom_image")
            custom_host = st.session_state.get("vx_saved_custom_host")
            custom_ports = st.session_state.get("vx_saved_custom_ports")
            custom_url = st.session_state.get("vx_saved_custom_url")

            target_summary = custom_image or custom_host or custom_url or (st.session_state.get("vx_saved_trivy_name") if mode == "Import Trivy JSON report" else None) or lab
            st.info(f"**Selected Target Type:** `{mode}`  |  **Target:** `{target_summary}`")

            col_cfg1, col_cfg2 = st.columns(2)
            with col_cfg1:
                st.markdown("<div class='vx-card'>", unsafe_allow_html=True)
                st.markdown("<div class='vx-card-header'>Active Scanners</div>", unsafe_allow_html=True)
                run_trivy = st.checkbox("Trivy Vulnerability Scanner", value=(mode in {"Running lab container", "Docker image", "Import Trivy JSON report"}), help="Scans container image packages for CVEs")
                run_nmap = st.checkbox("Nmap Port & Service Discovery", value=(mode in {"Running lab container", "Local web application", "Local host"}), help="Scans open ports and detects running services")
                run_zap = st.checkbox("OWASP ZAP Baseline Web Scanner", value=(mode in {"Running lab container", "Local web application"}), help="Executes passive web baseline checks")
                st.markdown("</div>", unsafe_allow_html=True)

            with col_cfg2:
                st.markdown("<div class='vx-card'>", unsafe_allow_html=True)
                st.markdown("<div class='vx-card-header'>Contextual Risk Parameters</div>", unsafe_allow_html=True)
                criticality = "Auto"
                st.caption("Asset business criticality: automatically assessed after discovery. Missing evidence remains unassigned.")
                exposure_model = st.selectbox(
                    "Modelled Attacker Reachability",
                    ["Confirmed external exposure (1.0)", "Internal modelled exposure (0.5)", "No identified path (0.0)"],
                    index=1
                )
                st.markdown("</div>", unsafe_allow_html=True)

            col_act1, col_act2 = st.columns([1, 4])
            with col_act1:
                if st.button("← Back to Step 1"):
                    st.session_state.vx_wizard_step = 1
                    st.rerun()
            with col_act2:
                if st.button("🚀 Initiate Assessment", type="primary", use_container_width=True):
                    try:
                        exp_kind = "all_interfaces" if "1.0" in exposure_model else "loopback" if "0.5" in exposure_model else "isolated"
                        if mode == "Import Trivy JSON report":
                            raw_json = st.session_state.get("vx_saved_trivy_json")
                            rep_name = Path(st.session_state.get("vx_saved_trivy_name") or "trivy-report.json").name
                            if not raw_json:
                                raise ValueError("No Trivy JSON report uploaded. Return to Step 1 and upload a report.")
                            parsed_data = json.loads(raw_json)
                            if not isinstance(parsed_data, dict) or not isinstance(parsed_data.get("Results"), list):
                                raise ValueError("Uploaded file does not contain a valid Trivy 'Results' array.")
                            target = {
                                "name": f"Trivy Report: {rep_name}",
                                "image": rep_name,
                                "nmap_host": "",
                                "ports": "",
                                "zap_app": "",
                                "exposure_kind": exp_kind,
                                "scanner_plan": [("Trivy", "Pending", f"Ingest uploaded report {rep_name}")],
                            }
                            dup_id = find_recent_active_assessment(username, target["name"], within_seconds=8)
                            if dup_id:
                                new_id = dup_id
                                pid = None
                            else:
                                new_id = create_assessment(username, mode, target, criticality)
                                dest_dir = REPORT_DIR / new_id
                                dest_dir.mkdir(parents=True, exist_ok=True)
                                dest_file = dest_dir / rep_name
                                dest_file.write_text(raw_json, encoding="utf-8")
                                target["imported_trivy_report_path"] = str(dest_file)
                                from assessment_manager import _db
                                with _db() as con:
                                    con.execute("UPDATE assessments SET target_json=? WHERE assessment_id=?", (json.dumps(target), new_id))
                                pid = launch_worker(new_id)
                                log_event(username, role, "assessment_started", "assessment", new_id, {"pid": pid, "target": target["name"]})
                        else:
                            target = make_plan(mode, lab, criticality, run_trivy=run_trivy, run_nmap=run_nmap, run_zap=run_zap, custom_image=custom_image, custom_host=custom_host, custom_ports=custom_ports, custom_url=custom_url)
                            target["exposure_kind"] = exp_kind
                            dup_id = find_recent_active_assessment(username, target.get("name", ""), within_seconds=8)
                            if dup_id:
                                new_id = dup_id
                                pid = None
                            else:
                                new_id = create_assessment(username, mode, target, criticality)
                                pid = launch_worker(new_id)
                                log_event(username, role, "assessment_started", "assessment", new_id, {"pid": pid, "target": target.get("name")})

                        st.session_state.vulnx_selected_assessment = new_id
                        st.session_state.vx_wizard_step = 1
                        st.session_state["vx_assessment_subview"] = "Live Execution & Scanner Telemetry"
                        st.session_state["vx_launch_banner"] = (
                            f"Assessment {new_id} is already running." if pid is None
                            else f"Assessment {new_id} initiated (Worker PID: {pid}). Tracking live execution below."
                        )
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to initiate assessment: {exc}")

    else:
        st.subheader("Live Assessment Execution & Scanner Telemetry")
        if not selected:
            st.info("No assessments available. Create a new security assessment to begin.")
            if st.button("➕ Create New Assessment", type="primary"):
                st.session_state["vx_assessment_subview"] = "New Assessment Wizard"
                st.session_state.vx_wizard_step = 1
                st.rerun()
        else:
            prog_info = scanner_progress(selected)
            prog = int(prog_info.get("percent", 0)) if isinstance(prog_info, dict) else int(prog_info or 0)
            prog = max(0, min(100, prog))
            cur_status = selected.get("status", "Queued")
            cur_stage = selected.get("stage") or cur_status
            status_badge_class = (
                "vx-badge-low" if cur_status == "Completed"
                else "vx-badge-critical" if cur_status in {"Failed", "Cancelled"}
                else "vx-badge-info" if cur_status in {"Running", "Discovering assets", "Processing findings"}
                else "vx-badge-neutral"
            )
            # Calculate genuine elapsed execution duration from persisted timestamps
            t_created_raw = selected.get("created_at", "")
            t_updated_raw = selected.get("updated_at", "")
            duration_str = "—"
            if t_created_raw:
                try:
                    c_dt = datetime.fromisoformat(t_created_raw.replace("Z", "+00:00"))
                    if not c_dt.tzinfo:
                        c_dt = c_dt.replace(tzinfo=timezone.utc)
                    if cur_status in {"Completed", "Failed", "Cancelled", "Partial"} and t_updated_raw:
                        u_dt = datetime.fromisoformat(t_updated_raw.replace("Z", "+00:00"))
                        if not u_dt.tzinfo:
                            u_dt = u_dt.replace(tzinfo=timezone.utc)
                    else:
                        u_dt = datetime.now(timezone.utc)
                    diff_s = max(0, int((u_dt - c_dt).total_seconds()))
                    d_mins, d_secs = divmod(diff_s, 60)
                    duration_str = f"{d_mins}m {d_secs}s" if d_mins > 0 else f"{d_secs}s"
                except Exception:
                    duration_str = "—"

            st.markdown(
                f"""<div class='vx-card' style='margin-bottom: 16px;'>
                    <div style='display:flex; justify-content:space-between; align-items:center; flex-wrap: wrap; gap: 10px;'>
                        <div>
                            <span class='vx-card-header'>Assessment: <code>{html.escape(str(selected_id))}</code></span>
                            <span style='margin-left:14px; color:#8A94AD; font-size:0.9rem;'>Target: <b style='color:#FFFFFF;'>{html.escape(str(selected.get('target_name', '')))}</b> ({html.escape(str(selected.get('target_type', '')))})</span>
                        </div>
                        <div>
                            <span class='vx-badge {status_badge_class}'>Status: {html.escape(str(cur_status))}</span>
                        </div>
                    </div>
                    <div style='margin-top:8px; font-size:0.84rem; color:#8A94AD;'>
                        Current Pipeline Stage: <b style='color:#22D3EE;'>{html.escape(str(cur_stage))}</b> · 
                        Execution Time: <b style='color:#38BDF8;'>{duration_str}</b> · 
                        Tasks Completed: <b style='color:#FFFFFF;'>{prog_info.get('completed_tasks', 0) if isinstance(prog_info, dict) else 0} / {prog_info.get('total_tasks', 0) if isinstance(prog_info, dict) else 0}</b> · 
                        Started: {html.escape(str(selected.get('created_at', '—')))}
                    </div>
                </div>""",
                unsafe_allow_html=True,
            )

            # Scanner Pipeline Stage View (Trivy -> Nmap -> ZAP -> Risk Engine)
            scanners = selected.get("scanners", [])
            s_map = {s.get("scanner"): s for s in scanners}
            pipeline_steps = [
                ("Trivy", "📦 Package & CVE Scan"),
                ("Nmap", "🌐 Port & Service Discovery"),
                ("OWASP ZAP", "🛡️ Web Baseline Audit"),
            ]
            pipeline_cols = st.columns(3)
            for p_idx, (p_name, p_desc) in enumerate(pipeline_steps):
                s_rec = s_map.get(p_name)
                if not s_rec:
                    p_stat = "Not Configured"
                    p_color = "#64748B"
                    p_badge = "SKIPPED"
                else:
                    st_val = s_rec.get("status", "Pending")
                    p_stat = st_val
                    p_color = "#22C55E" if st_val == "Completed" else "#EF4444" if st_val == "Failed" else "#22D3EE" if st_val == "Running" else "#EAB308"
                    p_badge = st_val.upper()

                with pipeline_cols[p_idx]:
                    st.markdown(f"""
                    <div class='vx-card' style='padding: 10px 14px; border-left: 3px solid {p_color}; margin-bottom: 12px;'>
                        <div style='display: flex; justify-content: space-between; align-items: center;'>
                            <span style='font-weight: 700; color: #FFFFFF; font-size: 0.88rem;'>{p_name}</span>
                            <span class='vx-badge' style='background: {p_color}22; color: {p_color}; border: 1px solid {p_color}44; font-size: 0.70rem;'>{p_badge}</span>
                        </div>
                        <div style='font-size: 0.74rem; color: #8A94AD; margin-top: 4px;'>{p_desc}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.progress(prog / 100.0, text=f"Pipeline Execution Progress: {prog}% · Stage: {cur_stage}")

            # Granular Finding Processing Telemetry
            is_proc_findings = cur_status == "Processing findings" or "processing findings" in str(cur_stage).lower()
            if is_proc_findings or cur_status == "Completed":
                st.markdown("<div style='margin-top: 14px; margin-bottom: 8px; font-weight: 700; color: #FFFFFF; font-size: 0.88rem;'>⚙️ Finding Processing Sub-Pipeline (Granular Engine Telemetry)</div>", unsafe_allow_html=True)
                proc_stages = [
                    ("1. Normalization", "1/7"),
                    ("2. Deduplication", "2/7"),
                    ("3. Risk Calculation", "3/7"),
                    ("4. Asset Correlation", "4/7"),
                    ("5. OWASP Taxonomy", "5/7"),
                    ("6. Attack Graph", "6/7"),
                    ("7. DB Persistence", "7/7"),
                ]
                st_cols = st.columns(7)
                for s_i, (s_title, s_num) in enumerate(proc_stages):
                    if cur_status == "Completed":
                        s_state = "DONE"
                        s_bg = "#22C55E"
                    elif s_num in str(cur_stage):
                        s_state = "RUNNING"
                        s_bg = "#22D3EE"
                    elif any(f"{prev}/7" in str(cur_stage) for prev in range(s_i + 2, 8)):
                        s_state = "DONE"
                        s_bg = "#22C55E"
                    else:
                        s_state = "PENDING"
                        s_bg = "#64748B"

                    with st_cols[s_i]:
                        st.markdown(f"""
                        <div class='vx-card' style='padding: 8px 4px; text-align: center; border-top: 3px solid {s_bg}; margin-bottom: 12px;'>
                            <div style='font-size: 0.68rem; color: #8A94AD; font-weight: 700;'>{s_title}</div>
                            <span class='vx-badge' style='background: {s_bg}22; color: {s_bg}; border: 1px solid {s_bg}44; font-size: 0.62rem; margin-top: 4px;'>{s_state}</span>
                        </div>
                        """, unsafe_allow_html=True)

            # Persistent Background NVD Threat Intelligence Queue Telemetry
            q_stats = get_queue_stats(selected_id)
            with st.expander("⚡ NIST NVD Threat Intelligence Background Queue Telemetry", expanded=(q_stats.get("pending", 0) > 0 or cur_status == "Completed")):
                nq_c1, nq_c2, nq_c3, nq_c4, nq_c5 = st.columns(5)
                with nq_c1:
                    st.metric("Cached", q_stats.get("cached", 0), help="Instantly resolved from local SQLite intelligence cache")
                with nq_c2:
                    st.metric("Enriched", q_stats.get("enriched", 0), help="Enriched via official NIST NVD v2.0 API in background")
                with nq_c3:
                    st.metric("Pending in Queue", q_stats.get("pending", 0), help="Queued for background enrichment respecting NIST rate limits (6.0s / 0.6s)")
                with nq_c4:
                    st.metric("Unavailable", q_stats.get("unavailable", 0), help="Confirmed unassigned or not present in NIST registry")
                with nq_c5:
                    st.metric("Failed", q_stats.get("failed", 0), help="API errors after exponential backoff retries")
                if q_stats.get("pending", 0) > 0:
                    st.caption(f"🔄 Background enrichment is actively processing {q_stats.get('pending')} CVEs at NIST-compliant rate limits. Dashboard findings and risk scores are immediately accessible without blocking.")

            if selected.get("error"):
                st.error(f"Pipeline Execution Error: {selected.get('error')}")

            for s in scanners:
                s_name = s.get("scanner")
                s_status = s.get("status")
                s_msg = s.get("message") or "—"
                badge_class = "vx-badge-low" if s_status == "Completed" else "vx-badge-critical" if s_status == "Failed" else "vx-badge-info" if s_status == "Running" else "vx-badge-medium"

                with st.expander(f"{s_name} — Status: {s_status} ({s_msg[:80]})", expanded=(s_status in {"Running", "Failed"})):
                    st.markdown(f"<span class='vx-badge {badge_class}'>{html.escape(str(s_status).upper())}</span>", unsafe_allow_html=True)
                    st.write(f"**Execution Message:** {s_msg}")
                    st.write(f"**Started:** `{s.get('started_at') or '—'}` | **Completed:** `{s.get('completed_at') or '—'}`")
                    if s.get("result"):
                        st.json(s.get("result"))

            worker_log_file = REPORT_DIR / f"{selected_id}-worker.log"
            if worker_log_file.is_file():
                log_text = worker_log_file.read_text(encoding="utf-8", errors="replace").strip()
                if log_text:
                    with st.expander("📄 Worker Process Live SOC Telemetry", expanded=True):
                        st.markdown(f"""
                        <div style='background: #080D1A; border: 1px solid #232C45; border-radius: 8px; overflow: hidden;'>
                            <div style='background: #0F1524; padding: 8px 14px; border-bottom: 1px solid #232C45; display: flex; align-items: center; justify-content: space-between;'>
                                <div style='display: flex; gap: 6px;'>
                                    <span style='width: 8px; height: 8px; border-radius: 50%; background: #EF4444;'></span>
                                    <span style='width: 8px; height: 8px; border-radius: 50%; background: #EAB308;'></span>
                                    <span style='width: 8px; height: 8px; border-radius: 50%; background: #22C55E;'></span>
                                </div>
                                <span style='font-family: monospace; font-size: 0.72rem; color: #8A94AD;'>telemetry-stream://{html.escape(selected_id)}</span>
                            </div>
                            <div style='padding: 12px 14px; font-family: monospace; font-size: 0.78rem; color: #35C6E8; max-height: 240px; overflow-y: auto; white-space: pre-wrap; line-height: 1.45;'>{html.escape(log_text[-3000:])}</div>
                        </div>
                        """, unsafe_allow_html=True)

            c_btn1, c_btn2, c_btn3, c_btn4 = st.columns(4)
            with c_btn1:
                if st.button("🔄 Refresh Status", key="btn_refresh_prog", type="primary", use_container_width=True):
                    st.rerun()
            with c_btn2:
                if cur_status == "Completed":
                    if st.button("Inspect Findings →", key="btn_to_findings", use_container_width=True):
                        st.session_state.vulnx_page = "Vulnerability Findings"
                        st.rerun()
                elif cur_status in {"Failed", "Partial"}:
                    if st.button("🔁 Retry Failed Scanners", key="btn_retry_scanners", use_container_width=True):
                        try:
                            retried = retry_failed_scanners(selected_id, username)
                            launch_worker(selected_id)
                            st.session_state["vx_launch_banner"] = f"Retrying failed scanners ({', '.join(retried)}) for {selected_id}."
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Retry failed: {exc}")
                elif cur_status in {"Queued", "Running", "Discovering assets", "Processing findings"}:
                    if st.button("🛑 Cancel Assessment", key="btn_cancel_assessment", use_container_width=True):
                        try:
                            c_res = cancel_assessment(selected_id, username)
                            st.session_state["vx_launch_banner"] = f"Assessment {selected_id} cancelled (Status: {c_res['status']})."
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Cancellation failed: {exc}")
            with c_btn3:
                if cur_status == "Completed":
                    if st.button("Explore Attack Graph →", key="btn_to_graph", use_container_width=True):
                        st.session_state.vulnx_page = "Attack Graph"
                        st.rerun()
                elif cur_status in {"Queued", "Running", "Discovering assets", "Processing findings"}:
                    if cur_status == "Queued":
                        if st.button("▶️ Start Worker Now", key="btn_start_queued_worker", use_container_width=True):
                            launch_worker(selected_id)
                            st.session_state["vx_launch_banner"] = f"Worker process started for {selected_id}."
                            st.rerun()
                    elif st.button("🛠️ Recover Stale Worker", key="btn_recover_worker", use_container_width=True):
                        try:
                            recovered = recover_interrupted_assessment(selected_id, username, min_age_seconds=60)
                            st.session_state["vx_launch_banner"] = f"Recovered interrupted scanners: {', '.join(recovered)}."
                            st.rerun()
                        except Exception as exc:
                            st.warning(f"Recovery notice: {exc}")
            with c_btn4:
                if st.button("➕ New Assessment", key="btn_new_from_prog", use_container_width=True):
                    st.session_state["vx_assessment_subview"] = "New Assessment Wizard"
                    st.session_state.vx_wizard_step = 1
                    st.rerun()


# -----------------------------------------------------------------------------
# 3. FINDINGS SECTION
# -----------------------------------------------------------------------------
elif page == "Vulnerability Findings":
    section_header(
        "Vulnerability Findings",
        "Normalized multi-scanner findings enriched with NVD CVSS, FIRST EPSS, OWASP Top 10:2025, and Canonical 0–10 Contextual Risk.",
        "INTELLIGENCE"
    )

    if not selected:
        st.info("No assessments available. Create a new security assessment to begin.")
        st.stop()

    raw_findings = findings_for(selected)
    if not ready:
        st.warning("Assessment is currently running or incomplete. Findings will be published upon completion.")
        st.stop()

    if not raw_findings:
        st.success("No vulnerability findings detected in this assessment!")
        st.stop()

    # Canonical 0-10 risk evaluation across all findings
    contextual = analyze_findings(findings_for(selected), exposure_kind=chosen_exposure, criticality=chosen_criticality)
    if target_context.get("automatic_criticality"):
        with st.expander("Automatic asset criticality evidence"):
            st.json(target_context["automatic_criticality"])

    # Top Severity Metrics Row
    sev_summary = severity_counts([f for f in contextual if f.get("is_vulnerability", True) and f.get("source") != "Nmap"])
    nmap_info_count = sum(1 for f in contextual if f.get("source") == "Nmap")

    fc0, fc1, fc2, fc3, fc4, fc5 = st.columns(6)
    with fc0:
        kpi_card("TOTAL FINDINGS", str(len(contextual)), "All scanners", "#6366F1")
    with fc1:
        kpi_card("CRITICAL", str(sev_summary.get("CRITICAL", 0)), "Immediate fix", "#EF4444")
    with fc2:
        kpi_card("HIGH", str(sev_summary.get("HIGH", 0)), "Severe risk", "#F97316")
    with fc3:
        kpi_card("MEDIUM", str(sev_summary.get("MEDIUM", 0)), "Moderate risk", "#EAB308")
    with fc4:
        kpi_card("LOW", str(sev_summary.get("LOW", 0)), "Low risk", "#3B82F6")
    with fc5:
        kpi_card("INFORMATIONAL", str(sev_summary.get("INFO", 0) + nmap_info_count), "Audit / config", "#64748B")

    # NVD Intelligence Telemetry Bar
    q_stats = get_queue_stats(selected_id)
    nvd_total_unique = q_stats.get("cached", 0) + q_stats.get("enriched", 0) + q_stats.get("pending", 0) + q_stats.get("unavailable", 0) + q_stats.get("failed", 0)
    if nvd_total_unique > 0:
        st.markdown(f"""
        <div class='vx-card' style='padding: 10px 16px; margin-top: 10px; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;'>
            <div style='display: flex; align-items: center; gap: 8px; flex-wrap: wrap;'>
                <span style='font-size: 0.90rem; font-weight: 700; color: #FFFFFF;'>⚡ NIST NVD Intelligence:</span>
                <span class='vx-badge' style='background: rgba(59, 130, 246, 0.15); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.3); font-size: 0.72rem;'>Cached: {q_stats.get("cached", 0)}</span>
                <span class='vx-badge' style='background: rgba(34, 197, 94, 0.15); color: #22C55E; border: 1px solid rgba(34, 197, 94, 0.3); font-size: 0.72rem;'>Enriched: {q_stats.get("enriched", 0)}</span>
                <span class='vx-badge' style='background: rgba(234, 179, 8, 0.15); color: #FACC15; border: 1px solid rgba(234, 179, 8, 0.3); font-size: 0.72rem;'>Pending: {q_stats.get("pending", 0)}</span>
                <span class='vx-badge' style='background: rgba(148, 163, 184, 0.15); color: #94A3B8; border: 1px solid rgba(148, 163, 184, 0.3); font-size: 0.72rem;'>Unavailable: {q_stats.get("unavailable", 0)}</span>
                <span class='vx-badge' style='background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.72rem;'>Failed: {q_stats.get("failed", 0)}</span>
            </div>
            <div style='font-size: 0.75rem; color: #8A94AD;'>
                {'🔄 Background rate-limited queue processing' if q_stats.get("pending", 0) > 0 else '✅ All CVE intelligence synchronized'}
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Search and Filter Controls
    f_c1, f_c2, f_c3, f_c4, f_c5 = st.columns([1.5, 1, 1, 1, 1])
    with f_c1:
        search_query = st.text_input("🔍 Search Findings", placeholder="CVE, package, weakness, or asset...", key="vx_find_search").strip().lower()
    with f_c2:
        sev_filter = st.multiselect("Filter Severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"], default=[], key="vx_find_sev")
    with f_c3:
        scanner_filter = st.selectbox("Scanner Source", options=["All Scanners", "Trivy", "Nmap", "OWASP ZAP"], key="vx_find_scanner")
    with f_c4:
        all_owasp_cats = sorted(set(f.get("owasp_top_10") for f in contextual if f.get("owasp_top_10")))
        owasp_filter = st.selectbox("OWASP Top 10", options=["All Categories"] + all_owasp_cats, key="vx_find_owasp")
    with f_c5:
        sort_by = st.selectbox("Sort Order", options=["Contextual Risk (0-10)", "CVSS Score", "Severity"], key="vx_find_sort")

    # Filtering logic
    filtered = list(contextual)
    if search_query:
        filtered = [f for f in filtered if search_query in (str(f.get("cve", "")) + " " + str(f.get("package", "")) + " " + str(f.get("title", "")) + " " + str(f.get("asset", "")) + " " + str(f.get("owasp_category", ""))).lower()]
    if sev_filter:
        filtered = [f for f in filtered if str(f.get("severity", "UNKNOWN")).upper() in sev_filter]
    if scanner_filter != "All Scanners":
        filtered = [f for f in filtered if f.get("source") == scanner_filter]
    if owasp_filter != "All Categories":
        filtered = [f for f in filtered if f.get("owasp_top_10") == owasp_filter]

    # Sorting
    if sort_by == "Contextual Risk (0-10)":
        filtered.sort(key=lambda x: (x.get("risk_score") is not None, x.get("risk_score") if x.get("risk_score") is not None else -1.0, x.get("cvss") or 0.0), reverse=True)
    elif sort_by == "CVSS Score":
        filtered.sort(key=lambda x: (x.get("cvss") is not None, x.get("cvss") or 0.0), reverse=True)
    else:
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
        filtered.sort(key=lambda x: sev_order.get(str(x.get("severity", "")).upper(), 0), reverse=True)

    st.markdown(f"""
    <div style='display: flex; justify-content: space-between; align-items: center; margin-top: 10px; margin-bottom: 12px;'>
        <div style='font-size: 0.85rem; color: #8A94AD;'>
            Showing <strong style='color: #22D3EE;'>{len(filtered)}</strong> of {len(contextual)} findings · Canonical Risk Engine: <code>{MODEL_VERSION}</code>
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_cards, tab_table = st.tabs(["🔍 Interactive Findings Cards", "📊 Tabular Data & Export"])

    with tab_cards:
        if not filtered:
            empty_state("No Findings Match Filters", "Adjust your search query or severity filters to view vulnerability records.")
        else:
            sev_colors = {
                "CRITICAL": "#EF4444",
                "HIGH": "#F97316",
                "MEDIUM": "#EAB308",
                "LOW": "#3B82F6",
                "INFO": "#64748B",
                "UNKNOWN": "#64748B",
            }
            # Paginated or top display
            display_count = min(len(filtered), 40)
            for idx, f in enumerate(filtered[:display_count]):
                cve_val = f.get("cve") or f.get("title") or f"Finding-{idx}"
                ctx_val = f.get("risk_score")
                ctx_disp = f"{ctx_val:.2f} / 10" if isinstance(ctx_val, (int, float)) else str(f.get("risk_label", "Manual Review"))
                sev_val = str(f.get("severity", "UNKNOWN")).upper()
                sev_border = sev_colors.get(sev_val, "#6366F1")
                cvss_val = f.get("cvss")
                cvss_str = f"{cvss_val:.1f}" if isinstance(cvss_val, (int, float)) else "N/A"
                source_str = f.get("source", "VulnX")
                pkg_str = f.get("package")
                installed_str = f.get("installed_version")
                fixed_str = f.get("fixed_version")
                title_str = f.get("title") or "No description provided."
                c_owasp = classify(f, selected_id)
                owasp_cat = c_owasp.get("category_name", "Security Finding")

                nvd_st_val = f.get("nvd_status")
                if not nvd_st_val:
                    if not f.get("cve") or not str(f.get("cve", "")).startswith("CVE-"):
                        nvd_st_val = "N/A"
                    elif f.get("cvss") is not None and "NVD" in str(f.get("base_score_source", "")):
                        nvd_st_val = "Cached"
                    else:
                        nvd_st_val = "Pending"

                nvd_badge_color = (
                    "#22C55E" if nvd_st_val == "Enriched"
                    else "#60A5FA" if nvd_st_val == "Cached"
                    else "#FACC15" if nvd_st_val == "Pending"
                    else "#F87171" if nvd_st_val == "Failed"
                    else "#94A3B8"
                )

                meta_parts = []
                if installed_str:
                    meta_parts.append(f"<span>Installed: <code style='color: #F87171;'>{html.escape(installed_str)}</code></span>")
                if fixed_str:
                    meta_parts.append(f"<span>Fixed in: <code style='color: #4ADE80;'>{html.escape(fixed_str)}</code></span>")
                meta_parts.append(f"<span>OWASP: <b style='color: #E6EAF2;'>{html.escape(owasp_cat)}</b></span>")
                meta_line = " ".join(meta_parts)
                pkg_badge = f"<span class='vx-badge' style='background: rgba(34, 211, 238, 0.15); color: #22D3EE; border: 1px solid rgba(34, 211, 238, 0.3); font-size: 0.75rem;'>{html.escape(pkg_str)}</span>" if pkg_str else ""

                card_html = textwrap.dedent(f"""
                <div class='vx-card' style='padding: 14px 18px; margin-bottom: 12px; border-left: 4px solid {sev_border};'>
                    <div style='display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap;'>
                        <div style='flex: 1; min-width: 320px;'>
                            <div style='display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;'>
                                {severity_badge(sev_val)}
                                <span style='font-size: 1.05rem; font-weight: 700; color: #FFFFFF;'>{html.escape(cve_val)}</span>
                                <span class='vx-badge' style='background: rgba(99, 102, 241, 0.15); color: #818CF8; border: 1px solid rgba(99, 102, 241, 0.3); font-size: 0.75rem;'>{html.escape(source_str)}</span>
                                <span class='vx-badge' style='background: {nvd_badge_color}22; color: {nvd_badge_color}; border: 1px solid {nvd_badge_color}55; font-size: 0.75rem;'>NVD: {html.escape(nvd_st_val.upper())}</span>
                                {pkg_badge}
                            </div>
                            <div style='font-size: 0.88rem; color: #E6EAF2; margin-bottom: 8px; line-height: 1.4;'>
                                {html.escape(title_str)}
                            </div>
                            <div style='display: flex; gap: 16px; font-size: 0.78rem; color: #8A94AD; flex-wrap: wrap;'>
                                {meta_line}
                            </div>
                        </div>
                        <div style='display: flex; flex-direction: column; align-items: flex-end; gap: 6px;'>
                            <div style='display: flex; gap: 8px;'>
                                <div style='background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 6px; padding: 4px 10px; text-align: center; min-width: 65px;'>
                                    <div style='font-size: 0.62rem; color: #8A94AD; font-weight: 700; letter-spacing: 0.05em;'>CVSS</div>
                                    <div style='font-size: 0.95rem; font-weight: 700; color: #EF4444;'>{cvss_str}</div>
                                </div>
                                <div style='background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 6px; padding: 4px 10px; text-align: center; min-width: 75px;'>
                                    <div style='font-size: 0.62rem; color: #8A94AD; font-weight: 700; letter-spacing: 0.05em;'>RISK (0-10)</div>
                                    <div style='font-size: 0.95rem; font-weight: 700; color: #818CF8;'>{ctx_disp}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                """).strip()
                st.markdown(card_html, unsafe_allow_html=True)

                with st.expander(f"Details & Remediation Guidance: {cve_val}", expanded=False):
                    col_d1, col_d2 = st.columns(2)
                    with col_d1:
                        st.markdown("**Vulnerability & Threat Intelligence Metadata**")
                        st.write(f"- **Package:** `{pkg_str or 'N/A'}`")
                        st.write(f"- **Installed Version:** `{installed_str or 'N/A'}`")
                        st.write(f"- **Fixed Version:** `{fixed_str or 'None listed'}`")
                        st.write(f"- **Scanner Source:** {source_str}")
                        st.write(f"- **NVD Intelligence Status:** `{nvd_st_val}` ({f.get('base_score_source', 'NVD / Scanner')})")
                        st.write(f"- **CVSS:** {f.get('cvss')} ({f.get('base_score_source', 'NVD / Scanner')})")
                        epss_val = f.get('epss_probability')
                        epss_pct = f.get('epss_percentile')
                        if epss_val is not None:
                            pct_str = f" · {epss_pct * 100:.1f}th percentile" if epss_pct is not None else ""
                            epss_display_str = f"`{epss_val:.5f}` ({epss_val * 100:.2f}% exploitation probability in wild{pct_str} · Status: `{f.get('epss_status', 'Available')}`)"
                        else:
                            epss_display_str = f"`None` (Status: `{f.get('epss_status', 'Unavailable')}`)"
                        st.write(f"- **FIRST.org EPSS:** {epss_display_str}")
                        if f.get('kev_status') == 'listed':
                            st.markdown("- **CISA Known Exploited (KEV):** <span style='color: #EF4444; font-weight: bold;'>⚠️ Yes (Actively Exploited in the Wild)</span>", unsafe_allow_html=True)
                        else:
                            st.write(f"- **CISA Known Exploited (KEV):** No")
                        st.write(f"- **OWASP Top 10:2025:** `{c_owasp['category']}` — {c_owasp['category_name']}")
                        st.caption(f"Rationale: {c_owasp.get('explanation')}")

                    with col_d2:
                        st.markdown("**Canonical Contextual Risk Formula Breakdown**")
                        st.latex(r"R = 10 \times [0.3 \times (CVSS/10) + 0.7 \times EPSS] \times Reachability \times (Criticality / 5)")
                        st.write(f"- **Reachability Factor:** `{f.get('reachability', 0.5)}`")
                        st.write(f"- **Criticality Level:** `{f.get('criticality_level', 3)} / 5`")
                        st.write(f"- **Canonical Score:** **{ctx_disp}**")

                        # Quick Remediate Action Button
                        if can_create_remediation(role):
                            if st.button("Create Remediation Ticket", key=f"btn_ticket_card_{idx}", type="secondary"):
                                try:
                                    tid = create_ticket(
                                        selected_id, f.get("finding_id", ""), username, role,
                                        notes=f"Remediate {cve_val} in {pkg_str or 'asset'} (fixed in {fixed_str or 'latest release'})"
                                    )
                                    log_event(username, role, "remediation_ticket_created", "ticket", str(tid))
                                    st.success(f"Remediation ticket #{tid} created successfully!")
                                except Exception as exc:
                                    st.info(f"Ticket notice: {exc}")

            if len(filtered) > display_count:
                st.info(f"Showing top {display_count} of {len(filtered)} findings. Use filters to narrow results or switch to Tabular View for full export.")

    with tab_table:
        st.dataframe(findings_rows(contextual), hide_index=True, use_container_width=True)
        with st.expander("Original scanner findings (raw evidence)"):
            st.dataframe(findings_rows(filtered), hide_index=True, use_container_width=True)
        st.download_button(
            "Download contextual risk and priority CSV",
            data=export_csv(contextual),
            file_name=f"{selected_id}-contextual-findings.csv",
            mime="text/csv",
            type="primary",
        )

elif page == "Risk Prioritization":
    # Compatibility hook
    pass


# -----------------------------------------------------------------------------
# 4. ATTACK GRAPH SECTION
# -----------------------------------------------------------------------------
elif page in {"Attack Graph", "Attack Paths"}:
    section_header(
        "Enterprise Attack Path Graph",
        "Contextual NetworkX attack graph modeling cross-target reachability, container runtimes, exposed ports, dependencies, and shared CVE vulnerability paths.",
        "MULTI-ASSET ONTOLOGY"
    )

    all_raw_assessments = list_assessments(limit=200)
    if not all_raw_assessments:
        empty_state(
            "No Assessed Environments",
            "Run an assessment with Nmap, Docker Inspect, or Trivy to generate attack paths and vulnerability graphs.",
            "Start Assessment",
        )
        st.stop()

    # Generate Platform Global Attack Graph
    global_graph = make_global_attack_graph(all_raw_assessments)
    if global_graph.number_of_nodes() == 0:
        empty_state("No Attack Path Evidence", "No graph nodes or relationships could be correlated from the current assessments.")
        st.stop()

    global_stats = compute_global_graph_stats(global_graph)

    # 1. Top Platform Global Statistics Row
    st.markdown(
        "<div style='font-size:0.78rem; color:#94A3B8; margin:0 0 8px 2px;'>"
        "🌐 Totals below cover <b style='color:#F8FAFC;'>all assessed assets</b> (graph nodes, not a single assessment). "
        "Per-assessment severity counts are on the <b style='color:#F8FAFC;'>Overview</b> page."
        "</div>",
        unsafe_allow_html=True,
    )
    gk1, gk2, gk3, gk4, gk5, gk6 = st.columns(6)
    with gk1:
        kpi_card("ASSESSED ASSETS", str(global_stats["total_assets"]), "Target environments", "#795BFF")
    with gk2:
        kpi_card("GRAPH NODES", str(global_stats["total_nodes"]), "Entities & assets", "#35C6E8")
    with gk3:
        kpi_card("RELATIONSHIPS", str(global_stats["total_relationships"]), "Evidence links", "#4285FF")
    with gk4:
        kpi_card("UNIQUE CVES", str(global_stats["unique_cves"]), f"{global_stats['total_cve_instances']} instances · {global_stats['shared_cves']} shared", "#EF4444")
    with gk5:
        kpi_card("CRITICAL CVES", str(global_stats["critical_count"]), "CVSS ≥ 9.0 · High exploit", "#EF4444")
    with gk6:
        kpi_card("HIGH CVES", str(global_stats["high_count"]), "CVSS 7.0 – 8.9", "#F97316")

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Available Assets List for filtering
    discovered_assets = sorted(list({
        d.get("asset") or d.get("cluster")
        for _, d in global_graph.nodes(data=True)
        if d.get("kind") == "Asset" and (d.get("asset") or d.get("cluster"))
    }))

    # 2. View Mode and Multi-Filter Controls Bar
    with st.container():
        ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([1.3, 1.1, 1.0, 1.1])
        with ctrl_col1:
            view_mode = st.radio(
                "Graph View Mode",
                ["🌐 Global View (All Assets)", "🎯 Asset Focus View"],
                horizontal=True,
                label_visibility="collapsed",
            )
        with ctrl_col2:
            if "Asset Focus" in view_mode:
                default_idx = 0
                if selected and selected.get("target_name") in discovered_assets:
                    default_idx = discovered_assets.index(selected.get("target_name"))
                target_filter = st.selectbox(
                    "Select Asset to Focus",
                    options=discovered_assets,
                    index=default_idx,
                    help="Isolates the attack path subgraph for this specific asset target.",
                )
            else:
                target_filter = st.selectbox(
                    "Asset Cluster Filter",
                    options=["All Assets"] + discovered_assets,
                    index=0,
                    help="Filter compound graph to a specific asset or view all interconnected assets.",
                )
        with ctrl_col3:
            node_filter = st.selectbox(
                "Filter Node Type",
                ["All", "Asset", "Attacker", "Host", "Open Port", "Service", "Container", "Image", "Dependency", "CVE"],
            )
        with ctrl_col4:
            sev_filter = st.selectbox(
                "CVE Severity Filter",
                ["All", "Critical", "High", "Medium", "Low", "Info"],
            )

        f_col1, f_col2, f_col3 = st.columns([1.5, 1.2, 1.3])
        with f_col1:
            edge_filter = st.selectbox(
                "Relationship Status",
                ["All", "Confirmed Only", "Potential / Inferred Only"],
                help="Confirmed: verified scanner evidence. Potential: wildcard bindings or unconfirmed exposure.",
            )
        with f_col2:
            graph_search = st.text_input(
                "🔍 Search Graph",
                placeholder="CVE ID, package, port, or asset name...",
                help="Real-time graph filter with 1-hop path context expansion.",
            ).strip()
        with f_col3:
            active_target = "All" if target_filter == "All Assets" else target_filter
            filtered_graph = filter_global_attack_graph(
                global_graph,
                selected_asset=active_target,
                selected_node_type=node_filter,
                severity_filter=sev_filter,
                status_filter=edge_filter,
                search_query=graph_search,
            )
            st.markdown(f"""
            <div style='padding-top: 26px; font-size: 0.82rem; color: #8A94AD;'>
                Active View: <strong style='color: #22D3EE;'>{filtered_graph.number_of_nodes()}</strong> / {global_graph.number_of_nodes()} Nodes · <strong style='color: #6366F1;'>{filtered_graph.number_of_edges()}</strong> Edges
            </div>
            """, unsafe_allow_html=True)

    # 3. Interactive PyVis Visualization (Tuned Barnes-Hut Anti-Hairball Physics)
    graph_html = generate_global_attack_graph_html(
        global_graph,
        height="680px",
        selected_asset=active_target,
        selected_node_type=node_filter,
        severity_filter=sev_filter,
        status_filter=edge_filter,
        search_query=graph_search,
    )
    components.html(graph_html, height=710)

    # 4. Ontology & Node Legend
    st.markdown("""
    <div class='vx-card' style='padding: 12px 16px; margin-top: 10px; margin-bottom: 20px;'>
        <div style='font-size: 0.72rem; font-weight: 700; color: #8A94AD; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 10px;'>GRAPH NODE ONTOLOGY & RISK MAPPING</div>
        <div style='display: flex; gap: 10px; flex-wrap: wrap; align-items: center;'>
            <span class='vx-badge' style='background: rgba(121, 91, 255, 0.2); color: #9D85FF; border: 1px solid #795BFF;'>⭐ Asset Target</span>
            <span class='vx-badge vx-badge-critical'>🔷 Attacker Vantage</span>
            <span class='vx-badge' style='background: rgba(59, 130, 246, 0.15); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.3);'>⬡ Host Interface</span>
            <span class='vx-badge' style='background: rgba(6, 182, 212, 0.15); color: #22D3EE; border: 1px solid rgba(6, 182, 212, 0.3);'>■ Open Port</span>
            <span class='vx-badge' style='background: rgba(20, 184, 166, 0.15); color: #2DD4BF; border: 1px solid rgba(20, 184, 166, 0.3);'>⬭ Network Service</span>
            <span class='vx-badge' style='background: rgba(99, 102, 241, 0.15); color: #818CF8; border: 1px solid rgba(99, 102, 241, 0.3);'>■ Container</span>
            <span class='vx-badge' style='background: rgba(139, 92, 246, 0.15); color: #A78BFA; border: 1px solid rgba(139, 92, 246, 0.3);'>■ Container Image</span>
            <span class='vx-badge vx-badge-medium'>● Package Dependency</span>
            <span class='vx-badge vx-badge-critical'>● Critical CVE</span>
            <span class='vx-badge vx-badge-high'>● High CVE</span>
            <span class='vx-badge vx-badge-medium'>● Medium CVE</span>
            <span class='vx-badge vx-badge-low'>● Low CVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 5. Interactive Node Selection & Cross-Asset Inspector
    node_ids = list(filtered_graph.nodes())
    if node_ids:
        with st.expander("🎯 Interactive Node Selection & Cross-Asset Vulnerability Inspector", expanded=True):
            chosen_node = st.selectbox(
                "Select Graph Node to Inspect",
                options=node_ids,
                format_func=lambda n: f"[{filtered_graph.nodes[n].get('kind', 'Node')}] {filtered_graph.nodes[n].get('label', n)} ({n})",
            )
            if chosen_node and chosen_node in filtered_graph:
                n_data = filtered_graph.nodes[chosen_node]
                in_edges = list(filtered_graph.in_edges(chosen_node, data=True))
                out_edges = list(filtered_graph.out_edges(chosen_node, data=True))
                ni_col1, ni_col2 = st.columns([1.2, 1.8])

                with ni_col1:
                    st.markdown(f"### `{chosen_node}`")
                    st.write(f"- **Kind:** `{n_data.get('kind')}`")
                    st.write(f"- **Label:** {n_data.get('label')}")
                    if n_data.get("asset") or n_data.get("cluster"):
                        st.write(f"- **Asset Target:** `{n_data.get('asset') or n_data.get('cluster')}`")

                    # Cross-Asset CVE Impact
                    if n_data.get("kind") == "CVE":
                        sev = n_data.get("severity", "Info")
                        st.markdown(f"- **Severity:** {severity_badge(sev)}", unsafe_allow_html=True)
                        st.write(f"- **CVSS Base:** `{n_data.get('cvss', 'N/A')}`")
                        st.write(f"- **Contextual Risk:** `{n_data.get('risk_score', 'N/A')}`")
                        affected = n_data.get("affected_assets", [])
                        if affected:
                            st.markdown(f"**Impacted Assets Across Enterprise ({len(affected)}):**")
                            pills_html = " ".join([f"<span class='vx-badge' style='background: rgba(121, 91, 255, 0.2); color: #9D85FF; border: 1px solid #795BFF; margin-right: 4px;'>{a}</span>" for a in affected])
                            st.markdown(pills_html, unsafe_allow_html=True)

                    props = n_data.get("properties", {})
                    if props:
                        with st.expander("Raw Properties JSON", expanded=False):
                            st.json(props)

                with ni_col2:
                    st.markdown("**Connected Attack Path Relationships**")
                    if in_edges:
                        st.markdown(f"**Inbound Attack Vectors ({len(in_edges)}):**")
                        for u, _, ed in in_edges:
                            st.markdown(f"- `{u}` &rarr; **{ed.get('label', 'connects')}** (`{ed.get('status', 'Confirmed')}`)<br/><span style='font-size: 0.76rem; color: #8A94AD;'>Evidence: {ed.get('evidence', 'None')}</span>", unsafe_allow_html=True)
                    else:
                        st.caption("No inbound attack vectors.")

                    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
                    if out_edges:
                        st.markdown(f"**Outbound Impact Paths ({len(out_edges)}):**")
                        for _, v, ed in out_edges:
                            st.markdown(f"- &rarr; `{v}` : **{ed.get('label', 'leads to')}** (`{ed.get('status', 'Confirmed')}`)<br/><span style='font-size: 0.76rem; color: #8A94AD;'>Evidence: {ed.get('evidence', 'None')}</span>", unsafe_allow_html=True)
                    else:
                        st.caption("No outbound impact paths.")

    # 6. Traceable Edge Evidence & Provenance Inspector
    with st.expander("🔍 Traceable Edge Evidence & Provenance Inspector", expanded=False):
        edges_data = []
        for u, v, d in filtered_graph.edges(data=True):
            edges_data.append({
                "Source Node": u,
                "Target Node": v,
                "Relationship": d.get("label", "connected"),
                "Status": d.get("status", "Confirmed"),
                "Discovery Source": d.get("source", "VulnX Engine"),
                "Evidence": str(d.get("evidence", "—")),
            })
        if edges_data:
            st.dataframe(pd.DataFrame(edges_data), use_container_width=True, hide_index=True)
        else:
            st.caption("No edges match the current filter criteria.")


# -----------------------------------------------------------------------------
# 4.5. AI SECURITY COPILOT WORKSPACE
# -----------------------------------------------------------------------------
elif page == "AI Security Copilot":
    section_header(
        "AI Security Copilot & Remediation Advisor",
        "Grounded DevSecOps assistance: synthesize remediation playbooks, predict breaking changes, generate compensating virtual patches, and explain attack graphs.",
        "GENAI COPILOT"
    )

    if not selected:
        empty_state("No Active Assessment Selected", "Select an assessment scope from the sidebar to analyze findings with the AI Copilot.")
        st.stop()

    from ai.ai_provider import get_ai_provider
    from ai.ai_remediation import AIRemediationGenerator
    from ai.ai_impact_analyzer import AIImpactAnalyzer
    from ai.ai_virtual_patch import AIVirtualPatchGenerator
    from ai.ai_attack_storyteller import AIAttackStoryteller

    provider = get_ai_provider()
    provider_name = getattr(provider, "model_name", provider.__class__.__name__)

    st.markdown(f"""
    <div class='vx-card' style='padding: 12px 18px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;'>
        <div>
            <span style='font-size: 0.75rem; color: #8A94AD; font-weight: 700; text-transform: uppercase;'>ACTIVE INFERENCE ENGINE:</span>
            <span style='font-size: 0.95rem; font-weight: 700; color: #22D3EE; margin-left: 8px;'>{html.escape(provider_name)}</span>
        </div>
        <div>
            <span class='vx-badge' style='background: rgba(34, 197, 94, 0.15); color: #4ADE80; border: 1px solid rgba(34, 197, 94, 0.3); font-size: 0.75rem;'>
                ● Grounded Telemetry Active
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    findings_list = findings_for(selected)
    if not findings_list:
        empty_state("No Findings Available", "This assessment contains no verified findings to analyze.")
        st.stop()

    # Finding selection
    f_options = {
        f.get("finding_id"): f"{f.get('cve') or f.get('title')} · {f.get('package') or 'Asset'} (Severity: {f.get('severity', 'UNKNOWN')}, Risk: {f.get('risk_score') if f.get('risk_score') is not None else 'Manual Review'}/10)"
        for f in findings_list if f.get("finding_id")
    }

    selected_f_id = st.selectbox(
        "Select Vulnerability to Analyze with AI Copilot",
        options=list(f_options.keys()),
        format_func=lambda x: f_options.get(x, x),
        help="Select a finding to synthesize fix commands, evaluate regression risk, or generate WAF rules."
    )

    chosen_finding = next((f for f in findings_list if f.get("finding_id") == selected_f_id), None)
    if not chosen_finding:
        st.stop()

    # Grounded Finding Metadata Card
    cve_name = chosen_finding.get("cve") or "Unknown CVE"
    pkg_name = chosen_finding.get("package") or "Asset"
    inst_ver = chosen_finding.get("installed_version") or "N/A"
    fix_ver = chosen_finding.get("fixed_version") or "None listed"
    risk_val = chosen_finding.get("risk_score")
    risk_str = f"{risk_val:.2f} / 10" if isinstance(risk_val, (int, float)) else "Manual Review"

    st.markdown(f"""
    <div class='vx-card' style='padding: 14px 18px; margin-bottom: 18px; border-left: 4px solid #6366F1;'>
        <div style='display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap;'>
            <div>
                <div style='font-size: 1.1rem; font-weight: 700; color: #FFFFFF; margin-bottom: 4px;'>
                    {html.escape(cve_name)} — {html.escape(pkg_name)}
                </div>
                <div style='font-size: 0.85rem; color: #8A94AD;'>
                    Installed: <code style='color: #F87171;'>{html.escape(inst_ver)}</code> · 
                    Vendor Fix: <code style='color: #4ADE80;'>{html.escape(fix_ver)}</code> · 
                    Source: <b style='color: #E6EAF2;'>{html.escape(chosen_finding.get("source", "VulnX"))}</b>
                </div>
            </div>
            <div style='text-align: right;'>
                <div style='font-size: 0.65rem; color: #8A94AD; font-weight: 700; text-transform: uppercase;'>Canonical Risk</div>
                <div style='font-size: 1.15rem; font-weight: 700; color: #818CF8;'>{risk_str}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_playbook, tab_impact, tab_waf, tab_story = st.tabs([
        "🛠️ Remediation Playbook",
        "⚠️ Breaking Change Analyzer",
        "🛡️ Virtual Patch (WAF)",
        "🎙️ Attack Path Storyteller"
    ])

    with tab_playbook:
        st.markdown("**Automated DevSecOps Remediation Synthesis**")
        st.caption("AI analyzes package metadata, vendor advisories, and runtime environment to draft exact upgrade commands and Dockerfile diffs.")
        
        btn_key = f"btn_gen_playbook_{selected_f_id}"
        if st.button("🤖 Generate AI Remediation Playbook", key=btn_key, type="primary"):
            with st.spinner("Synthesizing patch playbooks and verifying upgrade syntax..."):
                gen = AIRemediationGenerator(provider)
                res = gen.generate_playbook(chosen_finding)
                st.session_state[f"ai_pb_{selected_f_id}"] = res

        pb_res = st.session_state.get(f"ai_pb_{selected_f_id}")
        if pb_res:
            pb_data = pb_res.get("playbook", {})
            st.markdown(f"<div style='font-size: 0.8rem; color: #8A94AD; margin-bottom: 10px;'>Generated by: <strong style='color: #22D3EE;'>{html.escape(pb_res.get('source', 'AI Copilot'))}</strong></div>", unsafe_allow_html=True)
            
            c_p1, c_p2 = st.columns([1.2, 0.8])
            with c_p1:
                st.markdown(f"**Root Cause:**\n{pb_data.get('root_cause', 'N/A')}")
                st.markdown(f"**Fix Strategy:** `{pb_data.get('fix_strategy', 'Upgrade')}`")
                
                cmds = pb_data.get("terminal_commands", [])
                if cmds:
                    st.markdown("**Terminal Upgrade Commands:**")
                    st.code("\n".join(cmds), language="bash")
                
                df_diff = pb_data.get("dockerfile_patch")
                if df_diff:
                    st.markdown("**Dockerfile Patch:**")
                    st.code(df_diff, language="dockerfile")

            with c_p2:
                st.markdown(f"**Verification Step:**\n`{pb_data.get('verification_command', 'Re-scan with VulnX')}`")
                st.markdown(f"**Rollback Procedure:**\n{pb_data.get('rollback_procedure', 'Revert to prior container tag.')}")
                
                if can_create_remediation(role):
                    st.markdown("---")
                    st.markdown("**Maker-Checker Hand-off:**")
                    if st.button("➕ Create Remediation Ticket with this AI Draft", key=f"btn_ticket_from_ai_{selected_f_id}", type="secondary"):
                        try:
                            from governance.ticket_manager import TicketManager
                            notes_body = f"[AI-Generated Playbook]\nStrategy: {pb_data.get('fix_strategy')}\nCommands: {', '.join(cmds) if cmds else 'N/A'}\nVerification: {pb_data.get('verification_command')}"
                            new_tid = TicketManager.create_ticket(
                                assessment_id=selected_id,
                                finding_id=selected_f_id,
                                actor=username,
                                role=role,
                                owner=username,
                                due_date="2026-12-31",
                                notes=notes_body
                            )
                            log_event(username, role, "remediation_ticket_created_via_ai", "ticket", str(new_tid))
                            st.success(f"Ticket #{new_tid} created from AI draft and submitted to Maker-Checker queue!")
                        except Exception as exc:
                            st.info(f"Ticket notice: {exc}")

    with tab_impact:
        st.markdown("**Breaking Change & Regression Risk Analysis**")
        st.caption("Evaluates whether upgrading this library introduces API breaking changes, library conflicts, or service downtime.")
        
        if st.button("🔍 Assess Change Impact", key=f"btn_impact_{selected_f_id}", type="primary"):
            with st.spinner("Analyzing dependency trees and ABI compatibility..."):
                impact_analyzer = AIImpactAnalyzer(provider)
                imp_res = impact_analyzer.analyze_change_impact(chosen_finding)
                st.session_state[f"ai_imp_{selected_f_id}"] = imp_res

        imp_res = st.session_state.get(f"ai_imp_{selected_f_id}")
        if imp_res:
            imp_data = imp_res.get("impact", {})
            risk_badge = imp_data.get("change_risk", "Unknown")
            risk_color = "#22C55E" if risk_badge == "Low" else "#F97316" if risk_badge == "Medium" else "#EF4444"
            
            c_i1, c_i2, c_i3 = st.columns(3)
            with c_i1:
                kpi_card("CHANGE RISK", risk_badge, "Likelihood of breaking changes", risk_color)
            with c_i2:
                downtime_str = "YES" if imp_data.get("downtime_required") else "NO"
                kpi_card("DOWNTIME REQUIRED", downtime_str, "Requires service restart", "#22D3EE")
            with c_i3:
                kpi_card("CONFIDENCE", imp_data.get("confidence_level", "High"), "Impact prediction confidence", "#818CF8")

            st.markdown(f"<div style='margin-top: 14px;'><b>Impact Details:</b> {html.escape(imp_data.get('breaking_change_details', ''))}</div>", unsafe_allow_html=True)
            precautions = imp_data.get("recommended_precautions", [])
            if precautions:
                st.markdown("**Recommended Staging Precautions:**")
                for p in precautions:
                    st.write(f"- {p}")

    with tab_waf:
        st.markdown("**Virtual Patching & Compensating Perimeter Controls**")
        st.caption("Synthesizes ModSecurity WAF rules and Nginx ingress filters for zero-day vulnerabilities where no official patch is yet available.")
        
        if st.button("🛡️ Synthesize Compensating WAF Rule", key=f"btn_waf_{selected_f_id}", type="primary"):
            with st.spinner("Synthesizing regex patterns and ModSecurity SecRules..."):
                waf_gen = AIVirtualPatchGenerator(provider)
                waf_res = waf_gen.generate_virtual_patch(chosen_finding)
                st.session_state[f"ai_waf_{selected_f_id}"] = waf_res

        waf_res = st.session_state.get(f"ai_waf_{selected_f_id}")
        if waf_res:
            waf_data = waf_res.get("patch", {})
            st.warning("⚠️ " + waf_data.get("unverified_warning", "Compensating control draft. Test in staging."))
            st.markdown(f"**Control Mechanism:** `{waf_data.get('control_type')}` — {waf_data.get('mitigation_mechanism')}")
            st.markdown("**Rule Configuration Syntax:**")
            st.code(waf_data.get("rule_syntax", ""), language="nginx")
            st.markdown(f"**Staging Verification Test:**\n`{waf_data.get('verification_curl_test', 'curl -i http://localhost/')}`")

    with tab_story:
        st.markdown("**Attack Path Storyteller & Executive Explainer**")
        st.caption("Translates complex multi-hop network graphs into executive briefings for leadership and adversary chaining sequences for security engineers.")
        
        if st.button("📖 Generate Dual Attack Narrative", key=f"btn_story_{selected_f_id}", type="primary"):
            with st.spinner("Translating graph topology into executive and technical narratives..."):
                storyteller = AIAttackStoryteller(provider)
                story_res = storyteller.generate_briefing({
                    "nodes": ["Internet Attacker", "Port 80/TCP", "Web Service", chosen_finding.get("package") or "Asset", cve_name],
                    "critical_cves": [cve_name],
                    "confidence": 0.95,
                    "target_name": chosen_finding.get("target") or "Target"
                })
                st.session_state[f"ai_story_{selected_f_id}"] = story_res

        story_res = st.session_state.get(f"ai_story_{selected_f_id}")
        if story_res:
            narrative = story_res.get("narrative", {})
            exec_b = narrative.get("executive_briefing", {})
            tech_b = narrative.get("technical_briefing", {})

            col_exec, col_tech = st.columns(2)
            with col_exec:
                st.markdown("### 👔 Executive Risk Briefing")
                st.markdown(f"**Business Risk Summary:**\n{exec_b.get('business_risk_summary', '')}")
                st.markdown(f"**Operational Impact:**\n{exec_b.get('potential_financial_operational_impact', '')}")
                st.markdown(f"**Recommended CISO Priority:** `{exec_b.get('ciso_priority', 'Immediate Attention')}`")

            with col_tech:
                st.markdown("### 🛠️ Technical Adversary Narrative")
                st.markdown(f"**Entry Point:** `{tech_b.get('adversary_entry_point', 'Internet')}`")
                st.markdown(f"**Critical Pivot:** `{tech_b.get('critical_pivot_point', 'Container')}`")
                st.markdown(f"**Target Impact:** `{tech_b.get('target_impact_vulnerability', cve_name)}`")
                chain = tech_b.get("exploitation_chain", [])
                if chain:
                    st.markdown("**Exploitation Sequence:**")
                    for hop in chain:
                        st.write(f"- **Hop {hop.get('hop_number')}:** `{hop.get('source_node')}` → `{hop.get('destination_node')}` ({hop.get('technique', '')})")


# -----------------------------------------------------------------------------
# 5. ASSET INVENTORY SECTION
# -----------------------------------------------------------------------------
elif page == "Asset Inventory":
    section_header(
        "Asset & Technology Inventory",
        "Normalized attack surface inventory of hosts, open ports, network services, container runtimes, and package dependencies.",
        "ATTACK SURFACE"
    )

    if not selected:
        empty_state(
            "No Assessment Selected",
            "Select an existing assessment from the sidebar or initiate a new assessment to inspect asset infrastructure.",
            "Create Assessment",
        )
        st.stop()

    evidence = load_vg_evidence(selected_id)
    hosts_list = selected.get("hosts", [])
    services_list = selected.get("services", [])
    ports_list = selected.get("ports", [])
    containers_list = evidence.get("containers", [])
    images_list = selected.get("images", [])
    deps_list = selected.get("dependencies", [])

    # Asset Context Header Card
    t_name = selected.get("target_name", "Target")
    t_type = selected.get("target_type", "Target")
    t_crit = selected.get("criticality", "Normal")
    t_exp = selected.get("target", {}).get("exposure_kind", "loopback")

    st.markdown(f"""
    <div class='vx-card' style='margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;'>
        <div>
            <div style='font-size: 0.72rem; font-weight: 700; color: #8A94AD; letter-spacing: 0.08em; text-transform: uppercase;'>ACTIVE ASSET TARGET</div>
            <div style='font-size: 1.25rem; font-weight: 700; color: #FFFFFF; margin-top: 2px;'>{html.escape(t_name)}</div>
            <div style='font-size: 0.82rem; color: #8A94AD; margin-top: 2px;'>
                Type: <span style='color: #E6EAF2; font-weight: 500;'>{html.escape(t_type)}</span> · 
                Assessment ID: <code>{html.escape(selected_id)}</code>
            </div>
        </div>
        <div style='display: flex; gap: 8px; align-items: center;'>
            <span class='vx-badge' style='background: rgba(99, 102, 241, 0.15); color: #818CF8; border: 1px solid rgba(99, 102, 241, 0.3);'>Criticality: {html.escape(t_crit)}</span>
            <span class='vx-badge' style='background: rgba(53, 198, 232, 0.15); color: #35C6E8; border: 1px solid rgba(53, 198, 232, 0.3);'>Exposure: {html.escape(t_exp)}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Asset Inventory KPI Summary Row
    ak1, ak2, ak3, ak4 = st.columns(4)
    with ak1:
        kpi_card("HOSTS & SERVICES", str(len(hosts_list)), f"{len(services_list)} network services", "#3B82F6")
    with ak2:
        kpi_card("OPEN PORTS", str(len(ports_list)), "Listening TCP endpoints", "#06B6D4")
    with ak3:
        kpi_card("CONTAINERS & IMAGES", str(len(containers_list)), f"{len(images_list)} container images", "#8B5CF6")
    with ak4:
        kpi_card("SOFTWARE PACKAGES", str(len(deps_list)), "SBOM dependencies", "#22C55E")

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    tab_hosts, tab_ports, tab_containers, tab_deps = st.tabs([
        "🌐 Hosts & Services", "🚪 Open Ports", "🐳 Containers & Images", "📦 Package Dependencies"
    ])

    with tab_hosts:
        if not hosts_list and not services_list:
            empty_state("No Hosts or Services Discovered", f"Nmap discovery was not executed or identified no responding hosts for {t_name}.")
        else:
            if hosts_list:
                st.markdown("<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-bottom: 8px;'>Discovered Host Interfaces</div>", unsafe_allow_html=True)
                for h in hosts_list:
                    h_ip = h.get("host_ip") or h.get("hostname") or "127.0.0.1"
                    h_state = h.get("state", "up")
                    st.markdown(f"""
                    <div class='vx-card' style='padding: 12px 16px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;'>
                        <div style='display: flex; align-items: center; gap: 12px;'>
                            <span style='font-size: 1.2rem;'>🖥️</span>
                            <div>
                                <div style='font-weight: 600; color: #FFFFFF; font-size: 0.95rem;'>Host: <code>{html.escape(h_ip)}</code></div>
                                <div style='font-size: 0.78rem; color: #8A94AD;'>Hostname: {html.escape(h.get('hostname') or 'None')} · OS: {html.escape(h.get('os') or 'Linux / Container')}</div>
                            </div>
                        </div>
                        <span class='vx-badge' style='background: rgba(34, 197, 94, 0.15); color: #22C55E; border: 1px solid rgba(34, 197, 94, 0.3);'>STATE: {html.escape(h_state.upper())}</span>
                    </div>
                    """, unsafe_allow_html=True)

            if services_list:
                st.markdown("<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-top: 14px; margin-bottom: 8px;'>Detected Network Services</div>", unsafe_allow_html=True)
                s_rows = []
                for s in services_list:
                    s_rows.append({
                        "Port": s.get("port"),
                        "Protocol": s.get("protocol", "tcp"),
                        "Service": s.get("service_name", "unknown"),
                        "Product": s.get("product", "—"),
                        "Version": s.get("version", "—"),
                        "Confidence": f"{s.get('confidence', 100)}%",
                    })
                st.dataframe(pd.DataFrame(s_rows), use_container_width=True, hide_index=True)

    with tab_ports:
        if not ports_list:
            empty_state("No Open Ports Discovered", f"Port scanning did not detect any open listening ports on {t_name}.")
        else:
            st.markdown(f"<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-bottom: 12px;'>Discovered Listening Ports ({len(ports_list)})</div>", unsafe_allow_html=True)
            for p in ports_list:
                p_num = p.get("port", "")
                p_proto = p.get("protocol", "tcp")
                p_state = p.get("state", "open")
                p_service = p.get("service_name") or p.get("service") or "http"
                p_host = p.get("host") or "127.0.0.1"

                st.markdown(f"""
                <div class='vx-card' style='padding: 12px 16px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;'>
                    <div style='display: flex; align-items: center; gap: 14px;'>
                        <div style='background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); border-radius: 8px; padding: 6px 12px; font-weight: 700; color: #22D3EE; font-family: monospace;'>
                            {html.escape(str(p_num))}/{html.escape(str(p_proto))}
                        </div>
                        <div>
                            <div style='font-weight: 600; color: #FFFFFF; font-size: 0.92rem;'>Service: {html.escape(str(p_service))}</div>
                            <div style='font-size: 0.78rem; color: #8A94AD;'>Host: <code>{html.escape(str(p_host))}</code> · Evidence: Nmap verified state</div>
                        </div>
                    </div>
                    <span class='vx-badge' style='background: rgba(34, 197, 94, 0.15); color: #22C55E; border: 1px solid rgba(34, 197, 94, 0.3);'>
                        ● {html.escape(str(p_state).upper())}
                    </span>
                </div>
                """, unsafe_allow_html=True)

    with tab_containers:
        if not containers_list and not images_list:
            empty_state("No Container Runtimes Detected", f"Docker inspect did not detect active container workloads or image manifests for {t_name}.")
        else:
            if containers_list:
                st.markdown(f"<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-bottom: 12px;'>Running Containers ({len(containers_list)})</div>", unsafe_allow_html=True)
                for c in containers_list:
                    cid = c.get("container_id", "")[:12]
                    cname = c.get("name") or cid
                    cimage = c.get("image") or "—"
                    crunning = c.get("running", True)
                    status_color = "#22C55E" if crunning else "#EF4444"
                    status_label = "RUNNING" if crunning else "STOPPED"

                    # Clean formatted port bindings (NO raw dicts or {})
                    raw_maps = c.get("mappings") or []
                    if raw_maps:
                        map_strs = []
                        for m in raw_maps:
                            if isinstance(m, dict):
                                h_ip = m.get("host_ip", "0.0.0.0")
                                h_p = m.get("host_port", "")
                                c_p = m.get("container_port", "")
                                proto = m.get("protocol", "tcp")
                                map_strs.append(f"<code>{h_ip}:{h_p} &rarr; {c_p}/{proto}</code>")
                            else:
                                map_strs.append(f"<code>{html.escape(str(m))}</code>")
                        port_maps_html = ", ".join(map_strs)
                    else:
                        port_maps_html = "<span style='color: #8A94AD;'>None (internal container networking only)</span>"

                    nets = ", ".join(c.get("networks", ["bridge"])) or "bridge"

                    st.markdown(f"""
                    <div class='vx-card' style='padding: 14px 18px; margin-bottom: 12px;'>
                        <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;'>
                            <div style='display: flex; align-items: center; gap: 10px;'>
                                <span style='display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: {status_color}; box-shadow: 0 0 6px {status_color};'></span>
                                <span style='font-weight: 700; color: #FFFFFF; font-size: 1.0rem;'>{html.escape(str(cname))}</span>
                                <code style='font-size: 0.78rem;'>{html.escape(str(cid))}</code>
                            </div>
                            <span class='vx-badge' style='background: rgba(34, 197, 94, 0.15); color: {status_color}; border: 1px solid {status_color};'>
                                {status_label}
                            </span>
                        </div>
                        <div style='font-size: 0.82rem; color: #8A94AD; margin-top: 6px;'>
                            Image: <code style='color: #A78BFA;'>{html.escape(str(cimage))}</code> · Networks: <span style='color: #E6EAF2;'>{html.escape(str(nets))}</span>
                        </div>
                        <div style='font-size: 0.82rem; color: #8A94AD; margin-top: 4px;'>
                            Published Port Bindings: {port_maps_html}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            if images_list:
                st.markdown(f"<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-top: 16px; margin-bottom: 8px;'>Container Images ({len(images_list)})</div>", unsafe_allow_html=True)
                st.dataframe(pd.DataFrame(images_list), use_container_width=True, hide_index=True)

    with tab_deps:
        if not deps_list:
            empty_state("No Package Manifests Recorded", f"Trivy SBOM extraction did not identify software package manifests for {t_name}.")
        else:
            st.markdown(f"<div style='font-size: 0.92rem; font-weight: 600; color: #FFFFFF; margin-bottom: 12px;'>Extracted Software Packages ({len(deps_list)})</div>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(deps_list), use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# 6. REMEDIATION GOVERNANCE SECTION
# -----------------------------------------------------------------------------
elif page in {"Remediation Governance", "Remediation", "Verification"}:
    section_header(
        "Remediation Governance & Verification",
        "Role-separated remediation lifecycle management: Analysts propose fixes, Approvers independently authorize under strict Maker-Checker enforcement.",
        "MAKER-CHECKER"
    )

    if not selected:
        st.info("No assessments available. Create a new security assessment to begin.")
        st.stop()

    initialize_remediation()
    from assessment_manager import _db

    findings_list = findings_for(selected)
    findings_by_id = {f.get("finding_id"): f for f in findings_list if f.get("finding_id")}

    with _db() as con:
        con.row_factory = __import__("sqlite3").Row
        tickets = con.execute("SELECT * FROM remediation_tickets WHERE assessment_id=?", (selected_id,)).fetchall()
        tickets = [dict(t) for t in tickets]
        events = con.execute(
            """SELECT e.*, t.finding_id FROM remediation_ticket_events e 
            JOIN remediation_tickets t ON e.ticket_id = t.id 
            WHERE t.assessment_id=? ORDER BY e.id DESC""", (selected_id,)
        ).fetchall()
        events = [dict(e) for e in events]

    # Metrics
    t_c1, t_c2, t_c3, t_c4 = st.columns(4)
    with t_c1:
        kpi_card("TOTAL TICKETS", str(len(tickets)), "Assigned remediation", "#6366F1")
    with t_c2:
        kpi_card("PENDING APPROVAL", str(sum(1 for t in tickets if t["status"] == "Pending Approval")), "Awaiting sign-off", "#F97316")
    with t_c3:
        kpi_card("IN PROGRESS", str(sum(1 for t in tickets if t["status"] == "In Progress")), "Work underway", "#22D3EE")
    with t_c4:
        kpi_card("RESOLVED", str(sum(1 for t in tickets if t["status"] == "Resolved")), "Verified closed", "#22C55E")

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    tab_review, tab_create, tab_audit = st.tabs(["📝 Active Tickets & Decisioning", "➕ Propose Remediation", "📜 Governance Audit Log"])

    with tab_review:
        if not tickets:
            empty_state("No Remediation Tickets", "No tickets have been created for this assessment yet. You can create tickets from the Findings page or propose a fix using the Propose tab above.")
        else:
            for t in tickets:
                tid = t["id"]
                f_obj = findings_by_id.get(t["finding_id"], {})
                f_risk = f_obj.get("risk_score")
                f_risk_str = f"{f_risk:.2f} / 10" if isinstance(f_risk, (int, float)) else "Manual Review"
                t_stat = t.get("status", "Open")
                stat_badge_color = "#22C55E" if t_stat == "Resolved" else "#F97316" if t_stat == "Pending Approval" else "#22D3EE" if t_stat == "In Progress" else "#6366F1"
                
                with st.expander(f"Ticket #{tid} · [{t_stat}] · Finding: {f_obj.get('cve') or t['finding_id']} · Risk: {f_risk_str}"):
                    c_info, c_action = st.columns([1.2, 0.8])
                    with c_info:
                        st.write(f"- **Finding ID:** `{t['finding_id']}` (Canonical Risk: **{f_risk_str}**)")
                        st.write(f"- **Requested By:** `{t['requested_by']}` | **Created:** `{t['created_at']}`")
                        st.write(f"- **Owner Assigned:** `{t.get('owner') or 'Unassigned'}` | **Due Date:** `{t.get('due_date') or 'None'}`")
                        st.write(f"- **Approved By:** `{t.get('approved_by') or 'Pending'}`")
                        st.write(f"- **Remediation Notes:** {t.get('notes', '—')}")
                        if t.get("verification_evidence"):
                            st.write(f"- **Decision / Verification Evidence:** {t.get('verification_evidence')}")

                    with c_action:
                        st.markdown("**Governance Actions**")
                        if role in ("Analyst", "Security Analyst", "Admin") and t["status"] == "Open":
                            if st.button(f"Submit #{tid} for Approval", key=f"btn_sub_app_{tid}"):
                                try:
                                    change_ticket(tid, "Pending Approval", username, role)
                                    log_event(username, role, "ticket_submitted_for_approval", "ticket", str(tid))
                                    st.rerun()
                                except Exception as exc:
                                    st.error(f"Action failed: {exc}")

                        # Approver Action
                        if can_manage_approvals(role):
                            if t["status"] in ("Open", "Pending Approval"):
                                dec = st.radio(f"Decision for #{tid}", ["Approve", "Reject"], key=f"dec_{tid}")
                                just = st.text_input(f"Decision Justification", key=f"just_{tid}")
                                if st.button(f"Submit Decision for #{tid}", type="primary", key=f"btn_dec_{tid}"):
                                    if not just.strip():
                                        st.error("Decision justification is mandatory.")
                                        st.stop()
                                    try:
                                        if t["status"] == "Open":
                                            change_ticket(tid, "Pending Approval", t["requested_by"], "Analyst")
                                        new_st = "Approved" if dec == "Approve" else "Rejected"
                                        change_ticket(tid, new_st, username, role, evidence=just.strip())
                                        log_event(username, role, f"ticket_{new_st.lower()}", "ticket", str(tid), {"justification": just.strip()})
                                        st.success(f"Ticket #{tid} {new_st} successfully!")
                                        st.rerun()
                                    except PermissionError as p_err:
                                        st.error(f"Maker-Checker Violation: {p_err}")
                                    except Exception as exc:
                                        st.error(f"Action failed: {exc}")

                        # Analyst Progress Action
                        if role in ("Analyst", "Security Analyst", "Admin") and t["status"] == "Approved":
                            if st.button(f"Mark In Progress (#{tid})", key=f"btn_prog_{tid}"):
                                change_ticket(tid, "In Progress", username, role)
                                st.rerun()

    with tab_create:
        if not can_create_remediation(role):
            st.warning("Your role does not allow creating remediation tickets.")
        else:
            f_options = {
                f.get("finding_id"): f"{f.get('cve') or f.get('title')} (Severity: {f.get('severity', '')}, Risk: {f.get('risk_score') if f.get('risk_score') is not None else 'Manual Review'}/10)"
                for f in findings_list if f.get("finding_id")
            }
            if not f_options:
                st.caption("No eligible findings to remediate.")
            else:
                with st.form("new_ticket_form"):
                    f_choice = st.selectbox("Select Finding to Remediate", options=list(f_options.keys()), format_func=lambda x: f_options.get(x, x))
                    owner_input = st.text_input("Assignee / Owner", value=username)
                    due_date_input = st.text_input("Target Due Date (YYYY-MM-DD)", value="2026-12-31")
                    notes_input = st.text_area("Remediation Strategy & Upgrade Commands")
                    sub_ticket = st.form_submit_button("Submit Remediation Recommendation", type="primary")

                if sub_ticket:
                    try:
                        new_tid = create_ticket(selected_id, f_choice, username, role, owner=owner_input, due_date=due_date_input, notes=notes_input)
                        log_event(username, role, "remediation_ticket_created", "ticket", str(new_tid))
                        st.success(f"Ticket #{new_tid} created and submitted for approval!")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to create ticket: {exc}")

    with tab_audit:
        if events:
            st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
        else:
            st.caption("No ticket events recorded yet.")


# -----------------------------------------------------------------------------
# 7. SCAN HISTORY SECTION
# -----------------------------------------------------------------------------
elif page in {"Scan History", "My Scans", "Reports"}:
    section_header(
        "Assessment Scan History & Reports",
        "Comprehensive audit record of all persisted assessments stored in SQLite with full historical reloadability and canonical 0–10 risk metrics.",
        "AUDIT RECORDS"
    )

    if not all_assessments:
        st.info("No assessments available. Create a new security assessment to begin.")
        if st.button("Start Assessment"):
            st.session_state.vulnx_page = "Security Assessment"
            st.rerun()
        st.stop()

    history_rows = []
    total_findings_all = 0
    completed_scans = 0
    for a in all_assessments:
        full_a = get_assessment(a["assessment_id"])
        f_list = findings_for(full_a) if full_a else []
        total_findings_all += len(f_list)
        if a.get("status") == "Completed":
            completed_scans += 1
        scores = [float(f["risk_score"]) for f in f_list if isinstance(f.get("risk_score"), (int, float)) and not isinstance(f.get("risk_score"), bool)]
        avg_r = f"{sum(scores)/len(scores):.2f} / 10" if scores else "N/A"
        history_rows.append({
            "Assessment ID": a["assessment_id"],
            "Target Name": a["target_name"],
            "Target Type": a["target_type"],
            "Criticality": a["criticality"],
            "Status": a["status"],
            "Findings": len(f_list),
            "Avg Risk (0-10)": avg_r,
            "Created At": a["created_at"],
            "Created By": a["created_by"],
        })

    # Scan History KPI Metrics
    hk1, hk2, hk3, hk4 = st.columns(4)
    with hk1:
        st.markdown(f"""
        <div class='vx-card'>
            <div class='vx-kpi-label'>TOTAL ASSESSMENTS</div>
            <div class='vx-kpi-value' style='color: #3B82F6;'>{len(all_assessments)}</div>
        </div>
        """, unsafe_allow_html=True)
    with hk2:
        st.markdown(f"""
        <div class='vx-card'>
            <div class='vx-kpi-label'>COMPLETED RUNS</div>
            <div class='vx-kpi-value' style='color: #22C55E;'>{completed_scans}</div>
        </div>
        """, unsafe_allow_html=True)
    with hk3:
        st.markdown(f"""
        <div class='vx-card'>
            <div class='vx-kpi-label'>TOTAL FINDINGS LOGGED</div>
            <div class='vx-kpi-value' style='color: #F59E0B;'>{total_findings_all}</div>
        </div>
        """, unsafe_allow_html=True)
    with hk4:
        active_target_display = html.escape(str(selected.get("target_name", "None") if selected else "None"))
        st.markdown(f"""
        <div class='vx-card'>
            <div class='vx-kpi-label'>ACTIVE WORKSPACE TARGET</div>
            <div style='font-size: 1.1rem; font-weight: 700; color: #06B6D4; margin-top: 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;'>{active_target_display}</div>
        </div>
        """, unsafe_allow_html=True)

    st.dataframe(pd.DataFrame(history_rows), use_container_width=True, hide_index=True)

    # Scan Selection & Reopen
    col_hist1, col_hist2 = st.columns([2, 1])
    with col_hist1:
        hist_options = {a["assessment_id"]: f"{a['target_name']} · {a['status']} · {a['assessment_id']}" for a in all_assessments}
        chosen_hist = st.selectbox("Select Historical Assessment to Open", options=list(hist_options.keys()), format_func=lambda x: hist_options[x])
    with col_hist2:
        st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
        if st.button("📂 Open Selected Assessment", type="primary", use_container_width=True):
            st.session_state.vulnx_selected_assessment = chosen_hist
            st.session_state.vulnx_page = "Overview"
            st.rerun()

    # Executive Report Export for Selected Assessment
    if selected and selected.get("status") in {"Completed", "Partial"}:
        with st.expander("📊 Export Executive Report for Selected Assessment", expanded=False):
            try:
                snap = build_snapshot(selected)
                rep_c1, rep_c2 = st.columns(2)
                with rep_c1:
                    st.download_button(
                        "📄 Download Printable HTML Report",
                        data=export_exec_html(snap),
                        file_name=f"{selected_id}-executive-report.html",
                        mime="text/html",
                        use_container_width=True,
                    )
                with rep_c2:
                    st.download_button(
                        "🧾 Download JSON Snapshot Report",
                        data=export_exec_json(snap),
                        file_name=f"{selected_id}-snapshot.json",
                        mime="application/json",
                        use_container_width=True,
                    )
            except Exception as exc:
                st.caption(f"Report export unavailable: {exc}")

    # Scan Comparison Tool
    if len(all_assessments) >= 2:
        with st.expander("🔄 Compare Two Scans"):
            c_a, c_b = st.columns(2)
            with c_a:
                scan_a = st.selectbox("Base Scan", options=list(hist_options.keys()), index=0, key="scan_cmp_a", format_func=lambda x: hist_options[x])
            with c_b:
                scan_b = st.selectbox("Target Scan", options=list(hist_options.keys()), index=1, key="scan_cmp_b", format_func=lambda x: hist_options[x])

            if st.button("Run Scan Comparison", type="secondary"):
                obj_a = get_assessment(scan_a)
                obj_b = get_assessment(scan_b)
                if obj_a and obj_b:
                    diff = compare_scans(obj_a, obj_b)
                    sc1, sc2, sc3 = st.columns(3)
                    sc1.metric("New Findings", len(diff.get("new_findings", [])))
                    sc2.metric("Resolved Findings", len(diff.get("resolved_findings", [])))
                    sc3.metric("Common Findings", len(diff.get("common_findings", [])))


# -----------------------------------------------------------------------------
# ADMIN CONTROLS: USER MANAGEMENT
# -----------------------------------------------------------------------------
elif page == "User Management" and role == "Admin":
    section_header(
        "User Management & Access Control",
        "Manage persistent database-backed user accounts, secure authentication credentials, and role-based permissions (RBAC).",
        "ACCESS CONTROL"
    )

    tab_users, tab_new_user, tab_reset_pw = st.tabs(["👥 Registered Users", "➕ Provision New User", "🔑 Admin Password Reset"])

    with tab_users:
        users = list_users(actor_role=role)
        st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)

        other_users = [u["username"] for u in users if u["username"] != username]
        if other_users:
            st.subheader("Account Status Management")
            u_col1, u_col2 = st.columns(2)
            with u_col1:
                u_target = st.selectbox("Select User", options=other_users)
            with u_col2:
                st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
                u_obj = next((u for u in users if u["username"] == u_target), None)
                cur_active = bool(u_obj.get("is_active")) if u_obj else True
                new_state = not cur_active
                label = "Deactivate Account" if cur_active else "Activate Account"
                if st.button(label, type="secondary"):
                    set_user_status(u_target, new_state, role)
                    log_event(username, role, "user_status_changed", "user", u_target, {"is_active": new_state})
                    st.success(f"User {u_target} {'activated' if new_state else 'deactivated'}!")
                    st.rerun()

    with tab_new_user:
        with st.form("new_user_form"):
            new_u = st.text_input("New Username")
            new_p = st.text_input("Strong Initial Password", type="password", help="Min 10 chars with uppercase, lowercase, digit, and special character.")
            new_r = st.selectbox("Assigned Role", ["Security Analyst", "Approver", "Admin"])
            sub_u = st.form_submit_button("Create User Account", type="primary")

        if sub_u:
            try:
                res = create_user(new_u, new_p, new_r, actor_role=role)
                log_event(username, role, "user_created", "user", new_u, {"role": new_r})
                st.success(f"User '{new_u}' successfully created with role '{new_r}'!")
                st.rerun()
            except Exception as exc:
                st.error(f"Failed to create user: {exc}")

    with tab_reset_pw:
        users = list_users(actor_role=role)
        with st.form("admin_reset_pw_form"):
            target_u = st.selectbox("User to Reset", options=[u["username"] for u in users])
            reset_pw = st.text_input("New Strong Password", type="password")
            sub_reset = st.form_submit_button("Reset User Password", type="primary")
        if sub_reset:
            try:
                admin_set_password(target_u, reset_pw, actor_role=role)
                log_event(username, role, "admin_password_reset", "user", target_u)
                st.success(f"Password updated for user '{target_u}'.")
            except Exception as exc:
                st.error(f"Password reset failed: {exc}")


# -----------------------------------------------------------------------------
# ADMIN CONTROLS: AUDIT VERIFICATION
# -----------------------------------------------------------------------------
elif page == "Audit Verification" and role == "Admin":
    section_header(
        "Audit Trail & Cryptographic Checkpoints",
        "Cryptographic SHA-256 hash-chain verification and HMAC external integrity checkpoints protecting all system audit records.",
        "CRYPTOGRAPHIC CHAIN"
    )

    tab_verify, tab_events = st.tabs(["🔐 Chain Verification", "📜 Audit Event Stream"])

    with tab_verify:
        v_res = verify_audit_chain(role)
        if v_res.get("valid"):
            st.markdown(f"""
            <div class='vx-card' style='border-left: 4px solid #22C55E; margin-bottom: 16px;'>
                <div style='display:flex; justify-content:space-between; align-items:center;'>
                    <div>
                        <div style='font-size: 1.05rem; font-weight: 700; color: #F1F5F9;'>Cryptographic Audit Chain Intact</div>
                        <div style='color: #94A3B8; font-size: 0.85rem; margin-top: 4px;'>{v_res.get('checked')} records cryptographically validated. Hash chain unbroken.</div>
                    </div>
                    <span class='vx-badge vx-badge-low'>CHAIN VALID</span>
                </div>
                <div style='margin-top: 10px; font-family: monospace; font-size: 0.78rem; color: #64748B;'>Last Block Hash (SHA-256): {v_res.get('last_hash')}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class='vx-card' style='border-left: 4px solid #EF4444; margin-bottom: 16px;'>
                <div style='display:flex; justify-content:space-between; align-items:center;'>
                    <div>
                        <div style='font-size: 1.05rem; font-weight: 700; color: #EF4444;'>Audit Chain Integrity Failure</div>
                        <div style='color: #94A3B8; font-size: 0.85rem; margin-top: 4px;'>{v_res.get('reason')} at record #{v_res.get('event_id')}</div>
                    </div>
                    <span class='vx-badge vx-badge-critical'>INTEGRITY VIOLATION</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.subheader("External HMAC Checkpoint & Artifact Verification")
        st.markdown(
            "<div style='color: #94A3B8; font-size: 0.86rem; margin-bottom: 12px;'>"
            "Secure audit checkpoints against external tampering using SHA-256 digests and HMAC authentication. "
            "Select an audit file, JSON checkpoint, or compliance document (PDF, TXT, JSON, LOG, CSV) to verify "
            "cryptographic integrity or generate an immutable signed checkpoint."
            "</div>",
            unsafe_allow_html=True
        )

        if "vx_chk_uploader_nonce" not in st.session_state:
            st.session_state.vx_chk_uploader_nonce = 0

        chk_uploader_key = f"vx_audit_checkpoint_uploader_{st.session_state.vx_chk_uploader_nonce}"
        uploaded_chk_file = st.file_uploader(
            "Select or drop a security artifact (PDF, TXT, JSON, LOG, CSV) — Max 200MB",
            type=["json", "txt", "pdf", "log", "csv"],
            key=chk_uploader_key,
            help="Select an external audit artifact or checkpoint JSON to generate or verify HMAC-SHA256 signatures."
        )

        if uploaded_chk_file is not None:
            # File metadata directly from Streamlit's UploadedFile object
            file_name = uploaded_chk_file.name
            file_bytes = uploaded_chk_file.getvalue()
            file_size_bytes = len(file_bytes)
            file_ext = Path(file_name).suffix.lower()

            # Determine appropriate icon and type label
            if file_ext == ".pdf":
                file_icon = "📄"
                type_label = "PDF Document"
            elif file_ext == ".json":
                file_icon = "📦"
                type_label = "JSON Artifact / Checkpoint"
            elif file_ext in (".txt", ".log"):
                file_icon = "📝"
                type_label = "Text / Audit Log Stream"
            elif file_ext == ".csv":
                file_icon = "📊"
                type_label = "CSV Security Report"
            else:
                file_icon = "📁"
                type_label = (file_ext.upper()[1:] if file_ext else "Binary")

            # Formatted size in B / KB / MB
            if file_size_bytes < 1024:
                formatted_size = f"{file_size_bytes} B"
            elif file_size_bytes < 1024 * 1024:
                formatted_size = f"{file_size_bytes / 1024:.2f} KB"
            else:
                formatted_size = f"{file_size_bytes / (1024 * 1024):.2f} MB"

            # Compute real cryptographic SHA-256 digest of the actual file bytes
            file_sha256 = hashlib.sha256(file_bytes).hexdigest()

            # Dedicated Selected File Preview Card
            st.markdown(f"""
            <div class="vx-file-preview-card">
                <div class="vx-file-preview-left">
                    <div class="vx-file-icon-box">{file_icon}</div>
                    <div class="vx-file-meta">
                        <div class="vx-file-name" title="{html.escape(file_name)}">{html.escape(file_name)}</div>
                        <div class="vx-file-sub">
                            <span class="vx-file-type-pill">{html.escape(type_label)}</span>
                            <span>•</span>
                            <span class="vx-file-size-pill">{formatted_size}</span>
                            <span>•</span>
                            <span class="vx-badge vx-badge-low" style="font-size: 0.68rem; padding: 2px 8px;">🟢 File Selected & Ready</span>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_meta_digest, col_clear_action = st.columns([4, 1])
            with col_meta_digest:
                st.caption(f"SHA-256 Digest: `{file_sha256}`")
            with col_clear_action:
                if st.button("🗑️ Clear Selection", key="btn_clear_chk_file", use_container_width=True, type="secondary", help="Remove this selected file"):
                    st.session_state.vx_chk_uploader_nonce += 1
                    st.rerun()

            if file_size_bytes == 0:
                st.warning("⚠️ The selected file is completely empty (0 bytes). Checkpoints cannot be generated for empty files.")
            else:
                chk_col1, chk_col2 = st.columns(2)
                with chk_col1:
                    if st.button("🛡️ Generate Protected Checkpoint", key="btn_gen_file_chk", type="primary", use_container_width=True):
                        try:
                            # Use existing create_checkpoint function from audit_checkpoint
                            chk = create_checkpoint(v_res)
                            
                            # Real HMAC-SHA256 of file bytes with the audit secret
                            file_mac = hmac.new(audit_checkpoint._secret(), file_bytes, hashlib.sha256).hexdigest()
                            
                            st.success(f"HMAC Checkpoint Created for '{file_name}'!")
                            st.json({
                                "status": "CHECKPOINT_PROTECTED",
                                "file_name": file_name,
                                "file_sha256": file_sha256,
                                "file_hmac_sha256": file_mac,
                                "audit_checked_records": chk["payload"]["checked"],
                                "audit_last_hash": chk["payload"]["last_hash"],
                                "checkpoint_hmac_sha256": chk["hmac_sha256"],
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                        except Exception as exc:
                            st.error(f"Checkpoint Notice: {exc}")
                with chk_col2:
                    if st.button("🔍 Verify Checkpoint Integrity", key="btn_ver_file_chk", type="secondary", use_container_width=True):
                        try:
                            # Check if uploaded file is a structured JSON checkpoint
                            is_json_checkpoint = False
                            if file_ext == ".json":
                                try:
                                    parsed = json.loads(file_bytes.decode("utf-8"))
                                    if isinstance(parsed, dict) and "payload" in parsed and "hmac_sha256" in parsed:
                                        is_json_checkpoint = True
                                        expected_mac = audit_checkpoint._mac(parsed["payload"])
                                        if hmac.compare_digest(parsed["hmac_sha256"], expected_mac):
                                            if parsed["payload"].get("checked") == v_res.get("checked") and parsed["payload"].get("last_hash") == v_res.get("last_hash"):
                                                st.success(f"External Checkpoint Valid! Matches active audit chain ({parsed['payload'].get('checked')} records).")
                                            else:
                                                st.info(f"Checkpoint signature valid, but chain has progressed (Checkpoint: {parsed['payload'].get('checked')} records, Active: {v_res.get('checked')} records).")
                                        else:
                                            st.error("Checkpoint Verification Failed: Signature mismatch (Tampering detected!)")
                                except (ValueError, UnicodeDecodeError):
                                    pass

                            if not is_json_checkpoint:
                                c_ver = verify_checkpoint(v_res)
                                if c_ver.get("valid"):
                                    st.success(f"System Checkpoint Valid! Matches {c_ver.get('checked')} records. Artifact '{file_name}' SHA-256 ({file_sha256[:16]}...) validated.")
                                else:
                                    st.error(f"Checkpoint Verification Failed: {c_ver.get('reason')}")
                        except Exception as exc:
                            st.error(f"Verification Error: {exc}")
        else:
            st.info("ℹ️ Select a file above (PDF, TXT, JSON, LOG, CSV) to inspect its cryptographic digest and generate or verify an external HMAC checkpoint.")
            chk_col1, chk_col2 = st.columns(2)
            with chk_col1:
                if st.button("Generate Protected Checkpoint", key="btn_gen_standalone_chk", type="primary", use_container_width=True):
                    try:
                        chk = create_checkpoint(v_res)
                        st.success(f"HMAC Checkpoint Created: {chk.get('hmac_sha256')[:24]}...")
                        st.json(chk)
                    except Exception as exc:
                        st.warning(f"Checkpoint Notice: {exc}")
            with chk_col2:
                if st.button("Verify External Checkpoint", key="btn_ver_standalone_chk", type="secondary", use_container_width=True):
                    try:
                        c_ver = verify_checkpoint(v_res)
                        if c_ver.get("valid"):
                            st.success(f"External Checkpoint Valid! Matches {c_ver.get('checked')} records.")
                        else:
                            st.error(f"Checkpoint Verification Failed: {c_ver.get('reason')}")
                    except Exception as exc:
                        st.warning(f"Checkpoint Notice: {exc}")

    with tab_events:
        a_events = get_audit_events(limit=100, actor_role=role)
        st.dataframe(pd.DataFrame(a_events), use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# SYSTEM MANAGEMENT (Admin Only)
# -----------------------------------------------------------------------------
elif page == "System Management" and role == "Admin":
    section_header(
        "System Management & Disaster Recovery",
        "Platform operations, database storage metrics, background worker telemetry, and disaster recovery controls.",
        "ADMINISTRATION"
    )

    if st.session_state.get("vx_reset_success_banner"):
        st.success(st.session_state.pop("vx_reset_success_banner"))

    # Summary metrics of current assessment database
    summary = get_assessment_data_summary()

    sk1, sk2, sk3, sk4 = st.columns(4)
    with sk1:
        kpi_card("ASSESSMENTS", str(summary["total_assessments"]), "Target environments", "#6366F1")
    with sk2:
        kpi_card("TOTAL FINDINGS", str(summary["total_findings"]), "Normalized records", "#EF4444")
    with sk3:
        kpi_card("DISCOVERED ASSETS", f"{summary['total_hosts']} hosts / {summary['total_ports']} ports", "Network entities", "#22D3EE")
    with sk4:
        kpi_card("REMEDIATION TICKETS", str(summary["total_tickets"]), "Lifecycle tickets", "#22C55E")

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # System Health & Storage Details
    st.markdown("<div class='vx-card' style='margin-bottom: 24px;'>", unsafe_allow_html=True)
    st.markdown("<div class='vx-card-header'>Platform Architecture & Storage Health</div>", unsafe_allow_html=True)
    h_col1, h_col2, h_col3 = st.columns(3)
    with h_col1:
        st.write("- **Database Storage:** `scan_history.db` (WAL Mode)")
        st.write("- **Foreign Key Policy:** `Enforced (ON DELETE CASCADE)`")
    with h_col2:
        st.write("- **Audit Log Integrity:** `Cryptographic SHA-256 Hash Chain`")
        st.write(f"- **Active Administrator:** `{username}`")
    with h_col3:
        st.write("- **Report Storage:** `assessment_reports/`")
        st.write(f"- **Total Stored Records:** `{summary['grand_total_records']}`")
    st.markdown("</div>", unsafe_allow_html=True)

    # Danger Zone: Reset Everything
    st.markdown("""
    <div class='vx-danger-zone'>
        <div class='vx-danger-badge'>DANGER ZONE</div>
        <div style='font-size: 1.15rem; font-weight: 700; color: #FFFFFF; margin-bottom: 6px;'>
            Reset All Assessment Data
        </div>
        <div style='font-size: 0.88rem; color: #8A94AD; margin-bottom: 16px; line-height: 1.5;'>
            Permanently purge all assessment history, scanner results (Trivy, Nmap, ZAP), normalized findings, attack graph models, discovered asset inventory, and remediation tickets.
            <br/><strong style='color: #22C55E;'>Preserved:</strong> User credentials, authentication settings, roles, permissions, database schema, and audit logs.
        </div>
    </div>
    """, unsafe_allow_html=True)

    @st.dialog("⚠️ Confirm Complete Platform Reset")
    def show_reset_confirmation_modal():
        st.markdown("""
        <div class='vx-modal-warning-box'>
            <div style='font-weight: 700; color: #EF4444; font-size: 1.0rem; margin-bottom: 6px;'>
                ⚠️ Destructive Action: Permanent Assessment Data Purge
            </div>
            <div style='font-size: 0.85rem; color: #E6EAF2; line-height: 1.5;'>
                This action will delete all operational security data across the platform:
                <ul style='color: #8A94AD; margin-top: 6px; margin-bottom: 4px; padding-left: 20px;'>
                    <li>Assessment history and scan execution records</li>
                    <li>Trivy, Nmap, and OWASP ZAP raw and normalized results</li>
                    <li>Normalized findings and vulnerability records</li>
                    <li>Attack graph nodes, edges, and topologies</li>
                    <li>Discovered asset, container, image, and dependency inventory</li>
                    <li>Remediation tickets, statuses, owners, and notes</li>
                    <li>Cached NVD threat intelligence and contextual risk scores</li>
                    <li>Generated assessment reports and worker logs on disk</li>
                </ul>
            </div>
        </div>
        <div class='vx-modal-preserve-box'>
            <div style='font-weight: 700; color: #22C55E; font-size: 0.88rem; margin-bottom: 4px;'>
                🛡️ Preserved Entities (Safe)
            </div>
            <div style='font-size: 0.82rem; color: #8A94AD;'>
                User accounts, passwords, roles, permissions, application configurations, database schema, and all audit logs (including this reset event).
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.88rem; font-weight: 600; color: #FFFFFF; margin-bottom: 6px;'>To confirm this action, type <code style='color: #EF4444; font-weight: 700;'>RESET</code> in all capital letters:</div>", unsafe_allow_html=True)
        user_input_token = st.text_input("Confirmation Code", key="reset_token_input_field", placeholder="RESET", label_visibility="collapsed").strip()

        col_cancel, col_confirm = st.columns([1, 1.3])
        with col_cancel:
            if st.button("Cancel", key="btn_cancel_reset_modal", use_container_width=True):
                st.rerun()

        with col_confirm:
            token_valid = (user_input_token == "RESET")
            if st.button("🗑️ Confirm Reset Everything", key="btn_confirm_reset_execute", type="primary", disabled=not token_valid, use_container_width=True):
                with st.spinner("Executing system reset and cleaning assessment records..."):
                    try:
                        res = reset_all_assessment_data(
                            actor=username,
                            actor_role=role,
                            confirmation_token=user_input_token,
                        )
                        if res.get("success"):
                            st.session_state["vx_reset_success_banner"] = (
                                f"Platform reset completed successfully! Purged {res.get('records_deleted', 0)} assessment records."
                            )
                            # Clear assessment state from session
                            st.session_state.pop("vulnx_selected_assessment", None)
                            st.session_state.pop("vx_target_mode", None)
                            st.session_state.pop("vx_saved_lab", None)
                            st.session_state.pop("vx_saved_custom_image", None)
                            st.session_state.pop("vx_saved_custom_host", None)
                            st.session_state.pop("vx_saved_custom_ports", None)
                            st.session_state.pop("vx_saved_custom_url", None)
                            st.session_state.pop("vx_saved_trivy_json", None)
                            st.session_state.pop("vx_saved_trivy_name", None)
                            st.session_state.vulnx_page = "System Management"
                            st.rerun()
                        else:
                            st.error(f"Reset failed: {res.get('error', 'Unknown error')}")
                    except Exception as exc:
                        st.error(f"Reset operation failed: {exc}")

    # Red/destructive Reset Everything button
    btn_col1, btn_col2 = st.columns([1.2, 3])
    with btn_col1:
        if st.button("⚠️ Reset Everything", key="btn_open_reset_modal", type="primary", use_container_width=True):
            show_reset_confirmation_modal()


# -----------------------------------------------------------------------------
# ACCOUNT & SYSTEM SETTINGS
# -----------------------------------------------------------------------------
elif page in {"Settings"}:
    section_header(
        "Account & Security Settings",
        "Manage session credentials, password rotation, and review platform deployment security posture.",
        "SECURITY"
    )
    st.write(f"Signed in as: **{username}** | Role: **{role}**")

    st.subheader("Change Password")
    with st.form("self_change_pw_form"):
        cur_pw = st.text_input("Current Password", type="password")
        nxt_pw1 = st.text_input("New Strong Password", type="password", help="Min 10 chars with uppercase, lowercase, digit, and special character.")
        nxt_pw2 = st.text_input("Confirm New Password", type="password")
        sub_cpw = st.form_submit_button("Update Password", type="primary")
    if sub_cpw:
        if nxt_pw1 != nxt_pw2:
            st.error("New passwords do not match.")
        else:
            try:
                change_password(username, cur_pw, nxt_pw1)
                log_event(username, role, "password_changed", "user", username)
                st.success("Your password has been updated.")
            except Exception as exc:
                st.error(f"Password update failed: {exc}")

    if role == "Admin":
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.subheader("🎭 Viva & Presentation Demonstration Mode")
        from core.demo_mode import is_demo_active, activate_demo_scenario, deactivate_demo_scenario
        
        demo_status = is_demo_active()
        if demo_status:
            st.success("● Demonstration Scenario is currently ACTIVE (`OWASP Juice Shop [DEMO SIMULATION]`).")
            if st.button("🗑️ Deactivate Demo Scenario", key="btn_deactivate_demo", type="secondary"):
                deactivate_demo_scenario()
                log_event(username, role, "demo_scenario_deactivated", "system")
                st.info("Demonstration scenario deactivated.")
                st.rerun()
        else:
            st.caption("Injects an isolated, clearly labeled demonstration scenario featuring an exposed container, critical CVE-2021-3517, EPSS/KEV intelligence, canonical 8.1/10 risk, attack path, AI playbook, and Maker-Checker ticket.")
            if st.button("🚀 Activate Viva / Presentation Demo Scenario", key="btn_activate_demo", type="primary"):
                activate_demo_scenario()
                log_event(username, role, "demo_scenario_activated", "system")
                st.session_state.vulnx_selected_assessment = "VX-DEMO-2026-JUICESHOP"
                st.success("Demonstration scenario activated and selected in scope!")
                st.rerun()

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.subheader("🤖 AI Security Copilot Settings")
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        st.write(f"- **Google Gemini API Key Status:** {'Configured (Active)' if gemini_key else 'Not configured (Operating in Local / Deterministic fallback mode)'}")
        st.write(f"- **FIRST.org EPSS Threat Enrichment:** {'Enabled (Cached & Live)' if os.getenv('VULNX_THREAT_ENRICHMENT') == '1' else 'Disabled'}")
        st.write(f"- **Maker-Checker Governance:** Enforced across all remediation state transitions.")

        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.subheader("System Administration & Data Management")
        if st.button("Open System Management (Operational Reset) →", key="btn_goto_sys_mgmt_from_settings", type="secondary"):
            st.session_state.vulnx_page = "System Management"
            st.rerun()

        with st.expander("Deployment security warnings"):
            for w in deployment_warnings():
                st.warning(w)
