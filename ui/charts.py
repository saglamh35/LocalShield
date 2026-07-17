"""Altair chart builders for the Log Analysis tab."""

from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from modules.mitre import summarize as mitre_summarize


def create_timeline_chart(df) -> Any:
    """Log intensity chart by timeline (Area Chart)"""
    if df.empty or "Time" not in df.columns:
        return None

    try:
        # Group by timestamp (15-minute intervals)
        df_chart = df.copy()

        # Convert Time column to datetime (if not already)
        if not pd.api.types.is_datetime64_any_dtype(df_chart["Time"]):
            df_chart["Time"] = pd.to_datetime(df_chart["Time"], errors="coerce")

        # Filter invalid dates
        df_chart = df_chart[df_chart["Time"].notna()]

        if df_chart.empty:
            return None

        # Split into 15-minute intervals
        df_chart["Time_Interval"] = df_chart["Time"].dt.floor("15min")
        timeline_data = df_chart.groupby("Time_Interval").size().reset_index(name="Log Count")

        chart = (
            alt.Chart(timeline_data)
            .mark_area(interpolate="monotone", fillOpacity=0.6, stroke="#1f77b4", strokeWidth=2)
            .encode(
                x=alt.X("Time_Interval:T", title="Time", axis=alt.Axis(format="%H:%M")),
                y=alt.Y("Log Count:Q", title="Log Count"),
                tooltip=[
                    alt.Tooltip("Time_Interval:T", format="%Y-%m-%d %H:%M", title="Time"),
                    alt.Tooltip("Log Count:Q", title="Log Count"),
                ],
            )
            .properties(height=300, title="Log Intensity by Timeline")
            .configure_axis(gridColor="rgba(255,255,255,0.1)")
            .configure_view(strokeWidth=0)
        )

        return chart
    except Exception:
        # Silently ignore error (show empty chart)
        return None


def create_risk_distribution_chart(df) -> Any:
    """Risk level distribution chart (Donut Chart)"""
    if df.empty or "Risk Level" not in df.columns:
        return None

    try:
        # Normalize risk levels
        df_chart = df.copy()
        df_chart["Risk_Level_Normal"] = df_chart["Risk Level"].apply(
            lambda x: (
                "High"
                if "high" in str(x).lower() or "yüksek" in str(x).lower()
                else "Medium"
                if "medium" in str(x).lower() or "orta" in str(x).lower()
                else "Low"
                if "low" in str(x).lower() or "düşük" in str(x).lower()
                else "Unspecified"
            )
        )

        risk_counts = df_chart["Risk_Level_Normal"].value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]

        # Color palette
        color_map = {"High": "#ff4444", "Medium": "#ffaa00", "Low": "#44ff44", "Unspecified": "#888888"}
        risk_counts["Color"] = risk_counts["Risk Level"].map(color_map).fillna("#888888")

        chart = (
            alt.Chart(risk_counts)
            .mark_arc(innerRadius=60, outerRadius=120)
            .encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(
                    field="Risk Level",
                    type="nominal",
                    scale=alt.Scale(domain=risk_counts["Risk Level"].tolist(), range=risk_counts["Color"].tolist()),
                    legend=alt.Legend(title="Risk Level"),
                ),
                tooltip=["Risk Level:N", "Count:Q"],
            )
            .properties(height=300, title="Risk Level Distribution")
        )

        return chart
    except Exception as e:
        st.error(f"Error creating risk distribution chart: {e}")
        return None


def create_mitre_chart(df) -> tuple:
    """
    MITRE ATT&CK coverage: detected techniques as a horizontal bar chart,
    coloured by tactic. Returns (chart, summary_rows) or (None, []).
    """
    if df.empty or "MITRE Technique" not in df.columns:
        return None, []

    try:
        rows = mitre_summarize(df["MITRE Technique"].tolist())
        if not rows:
            return None, []

        chart_df = pd.DataFrame(rows)
        chart_df["label"] = chart_df["id"] + " – " + chart_df["name"]

        chart = (
            alt.Chart(chart_df)
            .mark_bar()
            .encode(
                x=alt.X("count:Q", title="Detections"),
                y=alt.Y("label:N", title="Technique", sort="-x"),
                color=alt.Color("tactic:N", title="Tactic"),
                tooltip=[
                    alt.Tooltip("id:N", title="Technique"),
                    alt.Tooltip("name:N", title="Name"),
                    alt.Tooltip("tactic:N", title="Tactic"),
                    alt.Tooltip("count:Q", title="Detections"),
                ],
            )
            .properties(
                height=max(200, 32 * len(chart_df)),
                title="MITRE ATT&CK Techniques Detected",
            )
        )
        return chart, rows
    except Exception:
        return None, []
