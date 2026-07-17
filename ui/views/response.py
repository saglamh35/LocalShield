"""Active Response (SOAR) tab: blocked IPs and the response audit trail."""

import html

import pandas as pd
import streamlit as st

import config
from db_manager import get_blocked_ips, get_recent_actions, record_action, remove_blocked_ip
from modules.response_engine import FirewallManager
from ui.components import render_kpi


def render() -> None:
    st.subheader("🛡️ Active Response (SOAR)")
    st.caption(
        "Automated Windows Firewall actions — IPs blocked in response to high-risk events, with a full audit trail."
    )

    try:
        blocked_ips = get_blocked_ips(config.DB_PATH)
        actions = get_recent_actions(limit=100, db_path=config.DB_PATH)
    except Exception as e:
        blocked_ips, actions = [], []
        st.error(f"Could not load response data: {e}")

    r1, r2, r3 = st.columns(3)
    render_kpi(r1, "⛔", "Currently Blocked", f"{len(blocked_ips)}", "firewall rules active", "var(--ls-high)")
    render_kpi(r2, "📜", "Logged Actions", f"{len(actions)}", "audit-trail entries", "var(--ls-info)")
    render_kpi(
        r3,
        "🔐",
        "Allowlisted IPs",
        f"{len(getattr(config, 'SAFE_IPS', []))}",
        "never auto-blocked",
        "var(--ls-low)",
    )
    st.markdown("")

    col_block, col_audit = st.columns([1, 1])

    with col_block:
        st.markdown("##### ⛔ Blocked IP Addresses")
        if blocked_ips:
            for ip, rule_name, blocked_at, reason in blocked_ips:
                when = str(blocked_at or "")
                ip_col, unblock_col = st.columns([4, 1])
                with ip_col:
                    st.markdown(
                        f"""
                        <div class="ls-ip-card">
                            <div>
                                <div class="ip">{html.escape(str(ip))}</div>
                                <div class="meta">{html.escape(str(reason or "Blocked"))} · {html.escape(when)}</div>
                            </div>
                            <span class="tag">{html.escape(str(rule_name or "BLOCKED"))}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with unblock_col:
                    # Mirrors the watcher's block-expiry path: lift the
                    # firewall rule first, then clear the DB row and audit it.
                    if st.button("Unblock", key=f"unblock_{ip}", use_container_width=True):
                        if FirewallManager().unblock_ip(ip):
                            remove_blocked_ip(ip, db_path=config.DB_PATH)
                            record_action(
                                "unblock_ip",
                                target=ip,
                                details="manual unblock from dashboard",
                                db_path=config.DB_PATH,
                            )
                            st.rerun()
                        else:
                            st.error(f"Could not unblock {ip} (admin rights / Windows Firewall required).")
        else:
            st.info("✅ No IPs are currently blocked. High-risk events with a hostile source IP will appear here.")

    with col_audit:
        st.markdown("##### 📜 Response Audit Trail")
        if actions:
            audit_df = pd.DataFrame(actions, columns=["ID", "Time", "Action", "Target", "Details"])
            audit_df = audit_df[["Time", "Action", "Target", "Details"]]
            st.dataframe(audit_df, use_container_width=True, hide_index=True, height=360)
        else:
            st.info("No automated actions recorded yet.")

    st.markdown("---")
    st.caption(
        "🔒 **Safety by design:** block targets are taken only from structured source-address fields "
        "(never a blanket text scan), private IPs and an allowlist of critical addresses (DNS/gateway) "
        "are never blocked, and every action is persisted for audit."
    )
