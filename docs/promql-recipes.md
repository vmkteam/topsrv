# PromQL recipes

Common queries, alerts, and dashboard expressions for topsrv metrics. Indexed by collector. See [metrics.md](metrics.md) for the underlying metric definitions.

## Netstat — listening ports

```promql
# Inventory of publicly-reachable listeners across the fleet
topsrv_netstat_listening_ports{scope="public"}

# Same, UDP only — DNS / mDNS / WireGuard / unexpected UDP services
topsrv_netstat_listening_ports{proto="udp", scope="public"}

# Alert: a new public-bound port appeared in the last 10 minutes
# (compare current set against the set seen 10 minutes ago — non-zero rows are new exposures)
(topsrv_netstat_listening_ports{scope="public"} == 1)
  unless on (instance, proto, port, family) (topsrv_netstat_listening_ports{scope="public"} offset 10m == 1)

# Count of distinct public-bound ports per host (capacity / drift watch)
count by (instance) (topsrv_netstat_listening_ports{scope="public"} == 1)
```

## Netstat — TCP connection scope

```promql
# Established TCP connections from the public internet — scan / unexpected exposure signal
topsrv_netstat_tcp_connections{state="ESTABLISHED", direction="inbound", remote_scope="public"}

# Outbound TCP to the public internet — exfil / unexpected egress watch
sum by (instance) (topsrv_netstat_tcp_connections{direction="outbound", remote_scope="public"})
```

## Angie ACME clients

```promql
# Inventory of ACME clients per host and their current state
topsrv_angie_acme_state

# Alert: any client not in cert=valid state
topsrv_angie_acme_state{certificate!="valid"}

# Time until next ACME action (seconds; negative = overdue / stuck)
topsrv_angie_acme_next_run_seconds - time()
```

## SSL certificates

`topsrv_ssl_certificate_expiry_seconds` is one series per `.pem` file with the cert's NotAfter. `topsrv_ssl_certificate_san_info` is an info metric (value=1) enumerating every DNS name in `CN ∪ SANs` — needed for multi-host certs where the CN alone hides most served domains.

```promql
# Days until expiry per cert file
(topsrv_ssl_certificate_expiry_seconds - time()) / 86400

# Alert: any cert expiring in the next 14 days
topsrv_ssl_certificate_expiry_seconds - time() < 14 * 86400

# Every DNS name served by every cert (one row per domain)
topsrv_ssl_certificate_san_info

# Join: days-left enriched with each SAN domain (one row per domain)
(topsrv_ssl_certificate_expiry_seconds - time()) / 86400
  * on (instance, path) group_right() topsrv_ssl_certificate_san_info

# Find certs about to expire, listed by each SAN domain they cover
(topsrv_ssl_certificate_expiry_seconds - time() < 14 * 86400)
  * on (instance, path) group_right() topsrv_ssl_certificate_san_info
```
