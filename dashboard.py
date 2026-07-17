"""
Streamlit Dashboard - LocalShield Professional SIEM Interface

Thin entry point: `streamlit run dashboard.py`. The UI lives in the `ui/`
package (theme, data loaders, components, charts and one view per tab).
"""

# Re-exported so `import dashboard` keeps working for tests and callers that
# predate the ui/ package split.
from ui.helpers import (  # noqa: F401 - backward-compat re-exports
    filter_data,
    get_risk_color_class,
    get_risk_icon,
    map_severity,
    translate_risk_level,
)


def main() -> None:
    """Main dashboard function"""
    # Imported lazily so `import dashboard` (tests, tooling) stays free of
    # Streamlit page setup and heavy UI imports.
    from ui.app import run

    run()


if __name__ == "__main__":
    main()
