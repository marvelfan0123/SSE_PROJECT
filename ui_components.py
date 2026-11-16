"""
VulnX UI Components — Modern Cybersecurity Product Presentation Layer
Design System: Wiz / CrowdStrike / Snyk dark aesthetic.
"""

import html
from typing import Any, Dict, List, Optional
import streamlit as st


# Palette Constants
COLOR_BG = "#080D1A"
COLOR_SIDEBAR = "#101827"
COLOR_CARD = "#151F32"
COLOR_CARD_SEC = "#1B263B"
COLOR_BORDER = "#232F48"
COLOR_TEXT = "#F8FAFC"
COLOR_MUTED = "#94A3B8"
COLOR_PRIMARY = "#4285FF"
COLOR_VIOLET = "#795BFF"
COLOR_CYAN = "#35C6E8"
COLOR_ACCENT = "#4285FF"
COLOR_HIGHLIGHT = "#35C6E8"

SEVERITY_COLORS = {
    "Critical": "#EF4444",
    "High": "#F97316",
    "Medium": "#EAB308",
    "Low": "#3B82F6",
    "Info": "#64748B",
    "Informational": "#64748B",
    "Unknown": "#64748B",
}


def load_custom_css(css_path: str = "styles.css") -> None:
    """Inject the unified design system CSS stylesheet."""
    try:
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)
    except Exception as exc:
        st.caption(f"CSS styling failed to load: {exc}")


def section_header(title: str, subtitle: Optional[str] = None, badge_text: Optional[str] = None) -> None:
    """Render a clean, high-hierarchy section header with optional badge."""
    badge_html = f"<span class='vx-badge vx-badge-info' style='margin-left: 10px; font-size: 0.75rem; vertical-align: middle;'>{html.escape(badge_text)}</span>" if badge_text else ""
    sub_html = f"<div class='vx-header-subtitle'>{html.escape(subtitle)}</div>" if subtitle else ""
    st.markdown(
        f"""
        <div class='vx-header'>
            <div class='vx-header-title'>{html.escape(title)}{badge_html}</div>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_top_navbar(
    current_page: str,
    target_name: Optional[str] = None,
    role: str = "Analyst",
    pipeline_ready: Optional[int] = None,
    pipeline_total: Optional[int] = None,
    active_scans: int = 0,
    **kwargs: Any,
) -> None:
    """Render a structured enterprise top navigation bar with breadcrumbs and active context.

    Pipeline and scan-activity pills show real values: ``pipeline_ready`` / ``pipeline_total`` come
    from the live scanner health checks and ``active_scans`` from queued/running assessments.
    """
    if current_page in {"Overview", "Dashboard", "Security Assessments", "Security Assessment", "New Assessment", "Scan Progress", "Assets", "Asset Inventory", "Findings", "Vulnerability Findings", "Attack Graph", "Attack Paths"}:
        section = "WORKSPACE"
    elif current_page in {"Remediation", "Remediation Governance", "Scan History", "My Scans", "Reports", "Verification"}:
        section = "OPERATIONS"
    else:
        section = "ADMINISTRATION"

    clean_page = (
        current_page
        .replace("Vulnerability ", "")
        .replace("Asset Inventory", "Assets")
        .replace("Governance & Verification", "")
        .replace("Governance", "")
        .replace("Audit Verification", "Audit Logs")
        .strip()
    )
    target_display = target_name[:24] + "..." if target_name and len(target_name) > 24 else (target_name or "Global Scope")

    if pipeline_ready is None or not pipeline_total:
        pipe_dot, pipe_color, pipe_text = "warning", "#EAB308", "Checking"
    elif pipeline_ready >= pipeline_total:
        pipe_dot, pipe_color, pipe_text = "online", "#22C55E", f"{pipeline_ready}/{pipeline_total} Ready"
    elif pipeline_ready == 0:
        pipe_dot, pipe_color, pipe_text = "offline", "#EF4444", f"0/{pipeline_total} Ready"
    else:
        pipe_dot, pipe_color, pipe_text = "warning", "#EAB308", f"{pipeline_ready}/{pipeline_total} Ready"

    if active_scans > 0:
        scan_dot = "<span class='vx-pulse-dot'></span>"
        scan_text = f"{active_scans} Scan{'s' if active_scans != 1 else ''} Running"
        scan_color = "#35C6E8"
    else:
        scan_dot = "<span class='vx-status-dot' style='background:#64748B;'></span>"
        scan_text = "No Active Scans"
        scan_color = "#94A3B8"

    st.markdown(
        f"""
        <div class='vx-topbar'>
            <div class='vx-topbar-left'>
                <div class='vx-topbar-logo-badge'>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <span class='vx-topbar-brand'>VulnX</span>
                <span class='vx-topbar-sep'>/</span>
                <span class='vx-topbar-section'>{html.escape(section)}</span>
                <span class='vx-topbar-sep'>/</span>
                <span class='vx-topbar-page'>{html.escape(clean_page)}</span>
            </div>
            <div class='vx-topbar-right'>
                <div class='vx-topbar-pill' title='Current target scope context'>
                    <span class='vx-status-dot online'></span>
                    <span style='color:#94A3B8;'>Scope:</span>
                    <span style='color:#F8FAFC; font-weight:600;'>{html.escape(target_display)}</span>
                </div>
                <div class='vx-topbar-pill' title='Scanners (Nmap, Trivy, Docker Inspect, OWASP ZAP) detected and ready on this host'>
                    <span class='vx-status-dot {pipe_dot}'></span>
                    <span style='color:#94A3B8;'>Scanners:</span>
                    <span style='color:{pipe_color}; font-weight:600;'>{html.escape(pipe_text)}</span>
                </div>
                <div class='vx-topbar-pill' title='Queued or running assessments'>
                    {scan_dot}
                    <span style='color:{scan_color}; font-weight:600; font-size:0.72rem;'>{html.escape(scan_text)}</span>
                </div>
                <div class='vx-topbar-role-badge' title='User Role Context'>
                    <span style='color:#94A3B8;'>Role:</span>
                    <span style='color:#4285FF; font-weight:600;'>{html.escape(role)}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def kpi_card(
    title: str,
    value: Any,
    subtitle: Optional[str] = None,
    severity: Optional[str] = None,
    border_color: Optional[str] = None,
) -> None:
    """
    Render a clean enterprise KPI card with a colored left accent border.
    Labels are short and never truncated; typography is prominent and clean.
    """
    sev_class = ""
    custom_border = ""
    if severity:
        sev_class = severity.lower()
    elif border_color:
        custom_border = f"border-left-color: {border_color};"

    sub_html = f"<div class='vx-kpi-sub'>{html.escape(str(subtitle))}</div>" if subtitle else ""

    st.markdown(
        f"""
        <div class='vx-kpi-card {sev_class}' style='{custom_border}'>
            <div class='vx-kpi-label'>{html.escape(str(title))}</div>
            <div class='vx-kpi-value'>{html.escape(str(value))}</div>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(severity: str) -> str:
    """Return an HTML snippet for a pill-style colored severity badge."""
    sev = str(severity).capitalize()
    cls_map = {
        "Critical": "vx-badge-critical",
        "High": "vx-badge-high",
        "Medium": "vx-badge-medium",
        "Low": "vx-badge-low",
        "Info": "vx-badge-info",
        "Informational": "vx-badge-info",
    }
    badge_cls = cls_map.get(sev, "vx-badge-neutral")
    return f"<span class='vx-badge {badge_cls}'>{html.escape(sev.upper())}</span>"


def scanner_status_pill(scanner_name: str, status: str, message: Optional[str] = None) -> str:
    """Return an HTML snippet for a scanner health pill with status dot."""
    st_lower = str(status).lower()
    if st_lower in ("available", "completed", "online", "healthy", "ok"):
        dot_class = "online"
        badge_text = "Available"
    elif st_lower in ("running", "partial", "warning"):
        dot_class = "warning"
        badge_text = status
    else:
        dot_class = "offline"
        badge_text = status or "Unavailable"

    msg_attr = f" title='{html.escape(message)}'" if message else ""
    return (
        f"<div class='vx-health-pill'{msg_attr}>"
        f"<span class='vx-status-dot {dot_class}'></span>"
        f"<span><b>{html.escape(scanner_name)}</b>: {html.escape(badge_text)}</span>"
        f"</div>"
    )


def empty_state(
    arg1: str = "🛡️",
    arg2: Optional[str] = None,
    arg3: Optional[str] = None,
    *,
    icon: Optional[str] = None,
    title: Optional[str] = None,
    message: Optional[str] = None,
) -> None:
    """
    Render a friendly, modern empty-state container.
    Supports:
      - empty_state(icon, title, message)
      - empty_state(title, message) [defaults icon to 🛡️]
      - empty_state(title) [defaults icon to 🛡️, message to ""]
      - Keyword arguments
    """
    if arg3 is not None:
        ic = icon or arg1
        ti = title or arg2 or ""
        msg = message or arg3
    elif arg2 is not None:
        # Check if arg1 is likely an icon/emoji or a full title string
        if len(arg1) <= 4 and any(ord(c) > 127 for c in arg1):
            ic = icon or arg1
            ti = title or arg2
            msg = message or ""
        else:
            ic = icon or "🛡️"
            ti = title or arg1
            msg = message or arg2
    else:
        ic = icon or "🛡️"
        ti = title or arg1
        msg = message or ""

    st.markdown(
        f"""
        <div class='vx-empty-state'>
            <div class='vx-empty-icon'>{html.escape(ic)}</div>
            <div class='vx-empty-title'>{html.escape(ti)}</div>
            <div class='vx-empty-desc'>{html.escape(msg)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_remediation_progress(open_count: int, in_progress_count: int, resolved_count: int) -> None:
    """Render a clean progress bar and metrics breakdown for remediation tickets."""
    total = open_count + in_progress_count + resolved_count
    closure_rate = (resolved_count / total * 100.0) if total > 0 else 0.0
    st.markdown(
        f"""
        <div class='vx-card-secondary' style='margin-bottom:0;'>
            <div style='display:flex; justify-content:space-between; align-items:center;'>
                <span style='font-size:0.84rem; font-weight:600; color:#F8FAFC;'>Remediation Closure Rate</span>
                <span style='font-size:0.95rem; font-weight:700; color:#35C6E8;'>{closure_rate:.1f}%</span>
            </div>
            <div class='vx-progress-track'>
                <div class='vx-progress-fill' style='width: {closure_rate:.1f}%;'></div>
            </div>
            <div style='display:flex; justify-content:space-between; margin-top:8px; font-size:0.78rem; color:#94A3B8;'>
                <span>Open: <b style='color:#F97316;'>{open_count}</b></span>
                <span>In Progress: <b style='color:#EAB308;'>{in_progress_count}</b></span>
                <span>Resolved: <b style='color:#22C55E;'>{resolved_count}</b></span>
                <span>Total: <b style='color:#F8FAFC;'>{total}</b></span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_severity_donut(counts: Dict[str, int]) -> None:
    """
    Render a modern security donut chart of findings by severity.
    Prefers Plotly (dark theme, transparent bg, hover info), with seamless Altair fallback.
    """
    ordered_keys = ["Critical", "High", "Medium", "Low", "Info"]
    labels = [k for k in ordered_keys if counts.get(k, 0) > 0]
    values = [counts[k] for k in labels]
    colors = [SEVERITY_COLORS[k] for k in labels]

    if not labels or sum(values) == 0:
        empty_state("🛡️", "No Findings Recorded", "Zero vulnerabilities or exposure alerts detected.")
        return

    try:
        import plotly.graph_objects as go
        fig = go.Figure(
            data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    hole=0.68,
                    marker=dict(colors=colors, line=dict(color="#0B0F1A", width=2)),
                    textinfo="value",
                    textfont=dict(color="#FFFFFF", size=13, family="Inter, sans-serif"),
                    hoverinfo="label+value+percent",
                )
            ]
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=5, b=5, l=5, r=5),
            height=195,
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.22,
                xanchor="center",
                x=0.5,
                font=dict(color="#8A94AD", size=10, family="Inter, sans-serif"),
            ),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    except ImportError:
        # Fallback to Altair
        import pandas as pd
        import altair as alt
        df = pd.DataFrame({"Severity": labels, "Count": values})
        chart = (
            alt.Chart(df)
            .mark_arc(innerRadius=45, stroke="#0B0F1A", strokeWidth=2)
            .encode(
                theta=alt.Theta("Count:Q"),
                color=alt.Color(
                    "Severity:N",
                    scale=alt.Scale(domain=labels, range=colors),
                    legend=alt.Legend(orient="bottom", title=None, labelColor="#8A94AD"),
                ),
                tooltip=["Severity", "Count"],
            )
            .properties(height=195, background="transparent")
            .configure_view(strokeWidth=0)
        )
        st.altair_chart(chart, use_container_width=True)


def render_risk_histogram(scores: List[float]) -> None:
    """
    Render a contextual risk score distribution chart (0–10 scale).
    Prefers Plotly with transparent bg and minimal gridlines, with Altair fallback.
    """
    valid_scores = [float(s) for s in scores if isinstance(s, (int, float)) and not isinstance(s, bool)]
    if not valid_scores:
        empty_state("📊", "No Risk Scores Available", "No contextual risk evaluations have been computed.")
        return

    bands = ["0.0 – 1.9", "2.0 – 3.9", "4.0 – 6.9", "7.0 – 8.9", "9.0 – 10.0"]
    band_colors = ["#64748B", "#3B82F6", "#EAB308", "#F97316", "#EF4444"]
    b_counts = [0, 0, 0, 0, 0]
    for s in valid_scores:
        if s < 2.0:
            b_counts[0] += 1
        elif s < 4.0:
            b_counts[1] += 1
        elif s < 7.0:
            b_counts[2] += 1
        elif s < 9.0:
            b_counts[3] += 1
        else:
            b_counts[4] += 1

    try:
        import plotly.graph_objects as go
        fig = go.Figure(
            data=[
                go.Bar(
                    x=bands,
                    y=b_counts,
                    marker=dict(color=band_colors, line=dict(color="#232C45", width=1), opacity=0.9),
                    text=b_counts,
                    textposition="auto",
                    textfont=dict(color="#FFFFFF", size=12, family="Inter, sans-serif"),
                    hoverinfo="x+y",
                )
            ]
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(t=5, b=5, l=5, r=5),
            height=195,
            xaxis=dict(
                tickfont=dict(color="#8A94AD", size=10, family="Inter, sans-serif"),
                gridcolor="#1E263C",
                showgrid=False,
            ),
            yaxis=dict(
                tickfont=dict(color="#8A94AD", size=10, family="Inter, sans-serif"),
                gridcolor="#1E263C",
                showgrid=True,
            ),
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    except ImportError:
        import pandas as pd
        import altair as alt
        df = pd.DataFrame({"Score Band": bands, "Findings": b_counts})
        chart = (
            alt.Chart(df)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("Score Band:N", sort=None, axis=alt.Axis(labelColor="#8A94AD", title=None)),
                y=alt.Y("Findings:Q", axis=alt.Axis(labelColor="#8A94AD", title=None, gridColor="#1E263C")),
                color=alt.Color("Score Band:N", scale=alt.Scale(domain=bands, range=band_colors), legend=None),
                tooltip=["Score Band", "Findings"],
            )
            .properties(height=195, background="transparent")
            .configure_view(strokeWidth=0)
        )
        st.altair_chart(chart, use_container_width=True)

