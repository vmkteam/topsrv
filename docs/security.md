# Security snapshot reference

The security collector sends one snapshot, `kind="security"`, to `/v1/inventory` every `[Security].Interval` (6h by default). It reports **facts** only: rules, scores and host roles are evaluated by the backend. To see exactly what a host sends, without sending or writing anything:

```bash
topsrv -config /etc/topsrv/topsrv.toml -security-dry-run
topsrv -config /etc/topsrv/topsrv.toml -security-dry-run -security-section kernel,sysctl
```

Collector health metrics (`topsrv_security_*`) are in [metrics.md](metrics.md#security-topsrv_security_). Configuration is in the [README](../README.md#security-snapshot).

## Envelope

The same envelope as the packages snapshot.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Always `security` |
| `scannedAt` | RFC 3339 time | Start of the pass. The backend orders snapshots by it, so a snapshot resent late from the spool never replaces a newer one |
| `host` | object | OS and kernel facts (`osId`, `osVersionId`, `kernelRelease`, `kernelArch`, `packageManager`, …) — the same `HostMeta` as `kind="packages"` |
| `data` | object | The snapshot, below |

## `data`

| Field | Type | Description |
|-------|------|-------------|
| `schemaVersion` | int | `1`. An incompatible change to the format bumps it; the backend accepts both versions during a rollout |
| `trigger` | string | What started the pass: `start` (first pass, 1–5 min after the agent starts), `interval`, `dry-run`, or the cause of an unscheduled pass |
| `agent` | object | The collector itself, below |
| `environment` | section | Where the agent runs. Not under `sections`: every other section depends on it |
| `sections` | map | Section name → section. Sections disabled in `[Security].DisabledSections` are absent |

### `agent`

| Field | Type | Description |
|-------|------|-------------|
| `keyId` | string | First 4 bytes of sha256 of the host token key, hex. A new key (state lost, state dir read-only) shows up as a new `keyId`, so tokens made with the old key are not compared to the new ones. `ephemeral` in dry-run without a stored key |
| `uid` | int | Effective uid of the agent |
| `capEff` | []string | Effective capabilities (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, …). Explains `permission_denied` in sections. `null` if unreadable |

## Sections

Every section has the same shape:

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `ok`, `partial`, `unknown` or `na`, below |
| `reason` | string | Why the section is `unknown` |
| `durationMs` | int | Time the section took |
| `gaps` | []object | Sources a `partial` section could not read: `{path, reason}`. `path` is a path on the host, never file content |
| `data` | object | Section facts, below. Absent when `unknown` |

| Status | Meaning |
|--------|---------|
| `ok` | Collected in full |
| `partial` | Some sources were unreadable, listed in `gaps`. The facts that were read are in `data` |
| `unknown` | Nothing collected; see `reason`. **Never a pass**: a check over an unknown section has no result |
| `na` | The component is absent on this host (no sshd, no Docker) |

| Reason | Meaning |
|--------|---------|
| `permission_denied` | The agent may not read the source: not root, missing capability, `/proc` mounted with `hidepid` |
| `not_found` | The source does not exist where it should (e.g. securityfs not mounted in a container) |
| `parse_error` | The source was read but not understood. Logged as `{section, file, line}` only, never the content |
| `timeout` | The section ran out of its time budget (a read hung on NFS), or was not rebuilt for two intervals. A section stuck in a blocking read is not started again until it returns |
| `container_env` | The agent runs in an app container (docker, podman, k8s) without the host root in view: host facts are not visible |
| `budget_exceeded` | A file was larger than the section reads |
| `remote_fs_skipped` | The path is on a network or automount filesystem and was not touched |
| `unsupported_platform` | Not Linux |
| `dump_inconsistent` | The source changed while it was read |

Within `data`, **`null` means not read** and an empty list or map means **read, nothing there**. For example `"hiddenModules": null` — the check did not run; `"hiddenModules": []` — it ran and found none.

## `environment`

Where the agent runs. Without it every other section could give a false pass: in a container `/etc` belongs to the container. Detection follows the order of systemd's `virt.c`.

| Field | Type | Description |
|-------|------|-------------|
| `pidNsHost` | bool | The agent sees the initial pid namespace |
| `rootIsHostRoot` | bool | The agent's `/` is the root of PID 1 (`false` for a container started with `--pid=host`) |
| `netNsHost` | bool | The agent shares the network namespace of PID 1 |
| `containerKind` | string | `none`, `docker`, `podman`, `k8s`, `lxc`, `nspawn` or `unknown`. A system container (`lxc`, `nspawn`) is a machine of its own and is collected in full |
| `libc` | string | `glibc`, `musl` or `unknown` |
| `init` | string | `systemd`, `openrc` or `other` |

In an app container (`docker`, `podman`, `k8s`) without the host root, `sysctl` and `roleSignals` are `unknown/container_env`; `kernel` is collected, its facts are kernel-wide.

## `kernel`

| Field | Type | Description |
|-------|------|-------------|
| `taint.value` | uint64 | `/proc/sys/kernel/tainted`. `taint` is `null` if unreadable |
| `taint.flags` | []string | Set taint flags as letters, below. Bits past the table come as `bitN` |
| `modules[]` | object | Loaded modules: `{name, taint}`; `taint` is the module's flags (`PO`, `OE`, …) |
| `hiddenModules` | []string | Loadable modules in `/sys/module` that are missing from `/proc/modules` — how rootkits such as Diamorphine hide. Confirmed by a second read against load/unload races. `null` when `/proc/modules` was unreadable |
| `cpuVulnerabilities` | map | `/sys/devices/system/cpu/vulnerabilities/*`: name → `{raw, class}`, below. `raw` is the kernel's line as is |
| `lsm.active` | []string | Active LSMs, `/sys/kernel/security/lsm`. `null` without securityfs |
| `lsm.lockdown` | string | Selected lockdown mode: `none`, `integrity`, `confidentiality` |
| `lsm.apparmor` | object | `{enabled, profiles, childNamespaceProfiles}`: `profiles` counts root-namespace profiles by mode (`enforce`, `complain`, …), `null` if the list is unreadable; profiles of child namespaces (LXD) are counted apart; names are not sent. Absent when AppArmor is not built in |
| `lsm.selinux` | string | `enforcing`, `permissive`, `disabled` (the LSM list is known and has no selinux) or `unknown` |
| `livepatch[]` | object | `{name, enabled, transition}`. `transition` that stays `true` means a stuck patch |
| `time` | object | Clock state from `adjtimex` (read-only): `{unsync, clockErr, maxErrorUs, offsetUs}`. `unsync` also follows any `settimeofday` (ntpdate, VMware Tools, Hyper-V), so weigh `maxErrorUs`, not the flag alone. In a container this is the host clock |
| `cmdline` | map | Only these `/proc/cmdline` tokens: `mitigations`, `lockdown`, `apparmor`, `selinux`, `security`, `module.sig_enforce`. The rest of the line is never sent: it may carry passwords |

Taint flags (`Documentation/admin-guide/tainted-kernels.rst`):

| Flag | Bit | Meaning | Flag | Bit | Meaning |
|------|-----|---------|------|-----|---------|
| `P` | 0 | Proprietary module (NVIDIA, ZFS) | `C` | 10 | Staging driver |
| `F` | 1 | Module force-loaded | `I` | 11 | Firmware bug workaround |
| `S` | 2 | CPU out of spec | `O` | 12 | Out-of-tree module (DKMS) |
| `R` | 3 | Module force-unloaded | `E` | 13 | Unsigned module |
| `M` | 4 | Machine check exception | `L` | 14 | Soft lockup |
| `B` | 5 | Bad page | `K` | 15 | Live-patched |
| `U` | 6 | Tainted from userspace | `X` | 16 | Auxiliary taint (distro) |
| `D` | 7 | Kernel died (oops, BUG) | `T` | 17 | Structure randomization |
| `A` | 8 | ACPI table overridden | `N` | 18 | In-kernel test |
| `W` | 9 | Kernel warning | `J` | 19 | Debug operation from userspace (fwctl) |

Flags stay set until reboot.

`cpuVulnerabilities.*.class`:

| Class | When |
|-------|------|
| `not_affected` | `Not affected` |
| `vulnerable` | `Vulnerable…`, `Processor vulnerable`, or a mitigation with a part still open (`…; BHI: Vulnerable`) |
| `mitigated_smt_vulnerable` | Mitigated, but `SMT vulnerable` |
| `mitigated` | `Mitigation: …` |
| `unknown` | Anything else (`Unknown: Dependent on hypervisor status`) |

## `sysctl`

Raw values; norms depend on the host role and are the backend's job. A key the kernel does not have is absent.

| Field | Type | Description |
|-------|------|-------------|
| `values` | map | Key → raw value for the KSPP set (`kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.yama.ptrace_scope`, `kernel.kexec_load_disabled`, `kernel.randomize_va_space`, `kernel.modules_disabled`, `kernel.perf_event_paranoid`, `kernel.io_uring_disabled`, `net.core.bpf_jit_harden`, `dev.tty.ldisc_autoload`, `fs.protected_*`, `fs.suid_dumpable`, `vm.unprivileged_userfaultfd`, `vm.memfd_noexec`), user namespaces (`user.max_user_namespaces`, `kernel.unprivileged_userns_clone`, `kernel.apparmor_restrict_unprivileged_userns`), `kernel.core_pattern`, forwarding and `net.bridge.bridge-nf-call-iptables` |
| `ipv4Conf` | map | Interface (`all`, `default`, `eth0`, …) → `rp_filter`, `accept_redirects`, `send_redirects`, `accept_source_route`, `log_martians`. The effective `rp_filter` is max(all, iface), so `all` alone is not enough |
| `ipv6Conf` | map | Interface → `accept_redirects`, `accept_source_route` |
| `confTruncated` | bool | More than 64 interfaces; container-side interfaces (`veth*`, `cali*`, `lxc*`) are always skipped |

## `roleSignals`

Signals for role tags (`docker-host`, `k8s-node`, `vpn-gw`, `hypervisor`, `multi-uplink`); the backend derives the tags.

| Field | Type | Description |
|-------|------|-------------|
| `processes` | []string | Running role processes, by executable (or `argv[0]` when the executable link is unreadable): `dockerd`, `containerd`, `kubelet`, `k3s`, `crio`, `conmon`, `libvirtd`, `virtqemud`, `qemu-system-*`, `lxd`, `incus`, `incusd`, `tailscaled`, `openvpn`, `cilium-agent`, `calico-node` |
| `interfaces.total` | int | Network interfaces without `lo` |
| `interfaces.devTypes` | map | `DEVTYPE` → count (`bridge`, `wireguard`, `vlan`, …) |
| `interfaces.tun` | int | tun/tap interfaces (wireguard-go, tailscale, openvpn) |
| `interfaces.names` | []string | Interfaces named `docker0`, `cni0`, `cilium_host`, `br-*`, `virbr*`, at most 32; `namesTruncated` when there were more |
| `defaultRoutes.v4` / `.v6` | int | Default routes; more than one suggests several uplinks |

## What never leaves the host

| Read | Sent |
|------|------|
| `/proc/cmdline` | Six whitelisted tokens, above |
| Environment of PID 1 | Only whether `container=` is set and its value |
| Command lines of processes | Only the base name of `argv[0]`, and only if it is a role process |
| AppArmor profiles | Counts by mode, no names |
| A file the agent failed to parse | `{path, reason}`; logs carry `{section, file, line}` |
| A panic in a parser | Its type and source location in the agent, not its value |

Every file is opened without following FIFOs or device nodes, with a size limit, and checked to be the same file before and after the open. Nothing is executed.

## Schedule

| Pass | When |
|------|------|
| First | 1–5 minutes after the agent starts, random — away from the packages scan |
| Scheduled | Every `Interval` ±10%. Always sent, changed or not, so the backend can tell "unchanged" from "agent silent" |
| Unscheduled | On a trigger, rebuilding only the affected sections, the rest from the last pass. At most one per 5 minutes, and only after the first full pass. Triggers that arrive meanwhile are merged |

A snapshot that fails to send with a network error, 5xx, 408, 429 or 401/403 is spooled and resent oldest first on later push ticks, for up to 7 days; any other 4xx drops it.

## Example

Trimmed; an Ubuntu host:

```json
{
  "kind": "security",
  "scannedAt": "2026-11-14T10:03:12Z",
  "host": { "osId": "ubuntu", "osVersionId": "24.04", "kernelRelease": "6.8.0-90-generic", "kernelArch": "amd64", "packageManager": "dpkg" },
  "data": {
    "schemaVersion": 1,
    "trigger": "start",
    "agent": { "keyId": "a1b2c3d4", "uid": 0, "capEff": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "…"] },
    "environment": {
      "status": "ok", "durationMs": 1,
      "data": { "pidNsHost": true, "rootIsHostRoot": true, "netNsHost": true, "containerKind": "none", "libc": "glibc", "init": "systemd" }
    },
    "sections": {
      "kernel": {
        "status": "ok", "durationMs": 4,
        "data": {
          "taint": { "value": 4096, "flags": ["O"] },
          "modules": [{ "name": "zfs", "taint": "PO" }, { "name": "ext4" }],
          "hiddenModules": [],
          "cpuVulnerabilities": { "spectre_v2": { "raw": "Mitigation: Enhanced / Automatic IBRS; IBPB: conditional", "class": "mitigated" } },
          "lsm": { "active": ["lockdown", "capability", "landlock", "yama", "apparmor"], "lockdown": "none",
                   "apparmor": { "enabled": true, "profiles": { "enforce": 118, "complain": 2 }, "childNamespaceProfiles": 0 }, "selinux": "disabled" },
          "time": { "unsync": false, "clockErr": false, "maxErrorUs": 16000, "offsetUs": -12 },
          "cmdline": { "mitigations": "auto" }
        }
      },
      "sysctl": {
        "status": "ok", "durationMs": 2,
        "data": {
          "values": { "kernel.kptr_restrict": "1", "kernel.yama.ptrace_scope": "1", "net.ipv4.ip_forward": "0" },
          "ipv4Conf": { "all": { "rp_filter": "2", "accept_redirects": "0" }, "eth0": { "rp_filter": "2", "accept_redirects": "1" } },
          "ipv6Conf": { "all": { "accept_redirects": "1" } }
        }
      },
      "roleSignals": {
        "status": "partial", "durationMs": 9,
        "gaps": [{ "path": "/proc", "reason": "permission_denied" }],
        "data": {
          "processes": ["containerd", "dockerd"],
          "interfaces": { "total": 3, "devTypes": { "bridge": 1 }, "tun": 0, "names": ["docker0"] },
          "defaultRoutes": { "v4": 1, "v6": 1 }
        }
      }
    }
  }
}
```
