"""Vulnerabilities tab: Trivy-based CVE findings and Ansible remediation."""

import pandas as pd
import streamlit as st

from db_manager import get_vulnerabilities, get_vulnerability_counts
from modules.ansible_remediation import playbook_for_db
from ui.components import render_kpi


def render() -> None:
    st.header("🐞 Vulnerability Management")
    st.caption(
        "CVE findings from the offline Trivy scanner — which package on which target is affected, and whether a fix exists."
    )

    counts = get_vulnerability_counts()

    if counts["total"] == 0:
        st.info(
            "No vulnerability findings yet. Run a scan with "
            "`python -m modules.vuln_scanner` (configure targets via "
            "`VULN_SCAN_IMAGES` / `VULN_SCAN_PATHS`) after pre-downloading Trivy's DB."
        )
    else:
        # KPI row — reuse the shared render_kpi card component.
        k1, k2, k3, k4 = st.columns(4)
        render_kpi(k1, "🔴", "Critical", counts["critical"], accent="#e5484d")
        render_kpi(k2, "🟠", "High", counts["high"], accent="#f5a623")
        render_kpi(k3, "🟡", "Medium", counts["medium"], accent="#e2c541")
        fix_pct = round(100 * counts["fixable"] / counts["total"]) if counts["total"] else 0
        render_kpi(k4, "🩹", "Fix available", f"{fix_pct}%", foot=f"{counts['fixable']} of {counts['total']}")

        st.markdown("---")

        # Filters
        fcol1, fcol2 = st.columns([1, 1])
        with fcol1:
            sev_filter = st.selectbox(
                "Severity", ["All", "Critical", "High", "Medium", "Low", "Unknown"], key="vuln_sev"
            )
        with fcol2:
            fixable_only = st.checkbox("Only findings with a fix available", key="vuln_fixable")

        rows = get_vulnerabilities(
            severity=None if sev_filter == "All" else sev_filter,
            fixable_only=fixable_only,
        )

        if rows:
            vuln_df = pd.DataFrame(
                rows,
                columns=[
                    "id",
                    "CVE",
                    "Package",
                    "Installed",
                    "Fixed",
                    "Severity",
                    "Target",
                    "Type",
                    "CVSS",
                    "Title",
                    "Scanned",
                ],
            ).drop(columns=["id"])
            st.subheader(f"🐞 Findings ({len(vuln_df)})")
            st.dataframe(vuln_df, use_container_width=True, hide_index=True)
        else:
            st.info("No findings match the current filters.")

        # --- Ansible remediation (SOAR, dry-run: generate & review only) ---
        st.markdown("---")
        st.subheader("🛠️ Ansible Remediation")
        st.caption(
            "Generate an Ansible playbook that upgrades the affected packages "
            "across the affected hosts. This only renders the playbook for review — "
            "it never runs `ansible-playbook`."
        )
        if counts["fixable"] == 0:
            st.info("No findings currently have a fix available, so there is nothing to remediate.")
        elif st.button("Generate remediation playbook", key="gen_playbook"):
            playbook = playbook_for_db()
            if playbook:
                st.code(playbook, language="yaml")
                st.download_button(
                    "⬇️ Download playbook",
                    data=playbook,
                    file_name="localshield_remediation.yml",
                    mime="text/yaml",
                    key="dl_playbook",
                )
            else:
                st.info("Nothing fixable to remediate.")
