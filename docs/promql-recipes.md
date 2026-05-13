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
