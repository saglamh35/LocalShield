# Observability — Prometheus & Grafana

LocalShield exposes its SIEM + vulnerability KPIs as **Prometheus** metrics so you
can monitor it with the same **Prometheus → Grafana** stack most teams already run.
Staying true to the project's offline-first identity, the exporter uses only the
Python standard library (`http.server`) — no `prometheus_client`, no extra deps.

## 1. Run the exporter

```bash
python -m modules.metrics_exporter
# -> LocalShield metrics exporter on http://127.0.0.1:9109/metrics
```

Configuration (env vars, see `config.py`):

| Variable       | Default     | Meaning                                            |
|----------------|-------------|----------------------------------------------------|
| `METRICS_HOST` | `127.0.0.1` | Bind address. Keep localhost unless behind a proxy |
| `METRICS_PORT` | `9109`      | Port for `/metrics`                                |

The exporter reads the same SQLite DB (`DB_PATH`) as the rest of LocalShield, so
run it alongside the log watcher / dashboard.

## 2. Exported metrics (all gauges)

| Metric | Description |
|--------|-------------|
| `localshield_up` | `1` while the exporter is serving |
| `localshield_logs_total` | Total stored security log entries |
| `localshield_high_risk_total` | High-risk log entries |
| `localshield_open_incidents` | Currently open incidents |
| `localshield_blocked_ips` | IPs currently blocked by the response engine |
| `localshield_vulnerabilities{severity="…"}` | Stored vulnerabilities by severity (`critical/high/medium/low/unknown`) |
| `localshield_vulnerabilities_total` | Total stored vulnerabilities |
| `localshield_vulnerabilities_fixable` | Vulnerabilities with a fix available |
| `localshield_vulnerabilities_fixable_ratio` | Fraction (0–1) of vulnerabilities that have a fix |

## 3. Scrape it with Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: localshield
    static_configs:
      - targets: ["127.0.0.1:9109"]
```

## 4. Import the Grafana dashboard

`grafana/localshield_dashboard.json` is a ready-to-import dashboard.

1. Grafana → **Dashboards → New → Import**.
2. Upload `grafana/localshield_dashboard.json`.
3. Select your Prometheus data source for the `DS_PROMETHEUS` input.

It ships stat panels (Critical / High vulns, Open incidents), a fixable-ratio
gauge, and time series of vulnerabilities-by-severity and high-risk activity.
