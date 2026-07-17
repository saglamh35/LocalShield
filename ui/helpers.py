"""Pure dashboard helpers: risk-level mapping and log filtering.

This module must stay Streamlit-free so tests can import it (directly or via
the `dashboard` shim) without pulling in the UI stack.
"""

import pandas as pd


def get_risk_icon(risk_level) -> str:
    """Returns icon based on risk level.

    Turkish literals (yüksek/orta/düşük) are kept on purpose: databases
    created before the English migration still contain those risk values.
    """
    if pd.isna(risk_level):
        return "❓"

    risk_str = str(risk_level).strip().lower()
    if "high" in risk_str or "yüksek" in risk_str:
        return "🔴"
    elif "medium" in risk_str or "orta" in risk_str:
        return "🟠"
    elif "low" in risk_str or "düşük" in risk_str:
        return "🟢"
    return "⚪"


def get_risk_color_class(risk_level) -> str:
    """Returns CSS class based on risk level"""
    if pd.isna(risk_level):
        return ""

    risk_str = str(risk_level).strip().lower()
    if "high" in risk_str or "yüksek" in risk_str:
        return "risk-high"
    elif "medium" in risk_str or "orta" in risk_str:
        return "risk-medium"
    elif "low" in risk_str or "düşük" in risk_str:
        return "risk-low"
    return ""


def translate_risk_level(risk_level) -> str:
    """
    Translates Turkish risk levels to English for UI display.

    Args:
        risk_level: Risk level string (can be Turkish or English)

    Returns:
        str: English risk level
    """
    if pd.isna(risk_level):
        return "Unspecified"

    risk_str = str(risk_level).strip()
    risk_lower = risk_str.lower()

    # Turkish to English mapping
    if "yüksek" in risk_lower or "high" in risk_lower:
        return "High"
    elif "orta" in risk_lower or "medium" in risk_lower:
        return "Medium"
    elif "düşük" in risk_lower or "low" in risk_lower:
        return "Low"
    elif "critical" in risk_lower:
        return "Critical"

    # If already in English, capitalize properly
    if risk_str.lower() in ["high", "medium", "low", "critical"]:
        return risk_str.capitalize()

    return risk_str  # Return as-is if unknown


def map_severity(risk_level) -> str:
    """
    Maps a stored risk level (English or legacy Turkish) to the severity
    tier shown in the logs table. "critical" must be checked before "high":
    checking "high" first would swallow every value into one tier and make
    the High tier unreachable.
    """
    risk = str(risk_level).lower()
    if "critical" in risk or "kritik" in risk:
        return "Critical"
    if "high" in risk or "yüksek" in risk:
        return "High"
    if "medium" in risk or "orta" in risk:
        return "Medium"
    if "low" in risk or "düşük" in risk:
        return "Low"
    return "Unspecified"


def filter_data(df, risk_filters, event_id_filter, text_search=None, date_range=None) -> "pd.DataFrame":
    """Filters data"""
    filtered_df = df.copy()

    # Date-range filter (inclusive). date_range is (start_date, end_date) or None.
    if date_range and "Time" in filtered_df.columns:
        try:
            start, end = date_range
            if start is not None and end is not None:
                times = pd.to_datetime(filtered_df["Time"], errors="coerce")
                start_ts = pd.Timestamp(start)
                end_ts = pd.Timestamp(end) + pd.Timedelta(days=1)  # inclusive end day
                filtered_df = filtered_df[(times >= start_ts) & (times < end_ts)]
        except Exception:
            pass

    # Risk level filter
    if risk_filters:
        filtered_df = filtered_df[filtered_df["Risk Level"].str.contains("|".join(risk_filters), case=False, na=False)]

    # Event ID filter
    if event_id_filter:
        filtered_df = filtered_df[
            filtered_df["Event ID"].astype(str).str.contains(event_id_filter, case=False, na=False)
        ]

    # Advanced Search (Text Search) - Search in Message, AI Analysis, MITRE Technique
    if text_search and text_search.strip():
        search_term = text_search.strip().lower()
        mask = (
            filtered_df["Message"].astype(str).str.lower().str.contains(search_term, na=False)
            | filtered_df["AI Analysis"].astype(str).str.lower().str.contains(search_term, na=False)
            | filtered_df["MITRE Technique"].astype(str).str.lower().str.contains(search_term, na=False)
        )
        filtered_df = filtered_df[mask]

    return filtered_df
