"""LocalShield dashboard UI package.

The Streamlit entry point stays `streamlit run dashboard.py`; that file is a
thin shim over `ui.app.run()`. Layout:

- theme.py      SOC-console CSS
- helpers.py    pure, Streamlit-free helpers (risk mapping, filtering)
- data.py       cached data loaders (DB, rules, threat feed, heartbeat)
- components.py reusable rendered widgets (KPI cards, log cards)
- charts.py     Altair chart builders
- sidebar.py    filter/management sidebar
- views/        one module per dashboard tab
- app.py        page assembly
"""
