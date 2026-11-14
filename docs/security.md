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
| `not_regular` | A FIFO, device or directory where a file should be, or the file was swapped while being opened — never read |
| `io_error` | Any other read failure (EIO and the like) |
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
| `netNsHost` | bool | The agent shares the network namespace of PID 1. In an app container that is the container's own PID 1, so `true` there says nothing about the host |
| `userNsHost` | bool | The agent is in the initial user namespace. `false` in an unprivileged LXC/LXD container or rootless podman: uid 0 and a full `capEff` are then not root of the host |
| `containerKind` | string | `none`, `docker`, `podman`, `k8s`, `lxc`, `nspawn`, `openvz` or `unknown`. A system container (`lxc`, `nspawn`, `openvz`) is a machine of its own and is collected in full. `unknown` in another pid namespace (no marker: a pod without a service account token, nerdctl) is treated as an app container; `unknown` in the host pid namespace means the agent could not tell (no `CAP_SYS_PTRACE` to compare its root with PID 1's) |
| `libc` | string | `glibc`, `musl` or `unknown`. With both loaders present (the musl package on Debian, gcompat on Alpine) the distribution decides |
| `init` | string | `systemd`, `openrc` or `other` |

In an app container (`docker`, `podman`, `k8s`, or an unidentified one) without the host root, `sysctl` and `roleSignals` are `unknown/container_env`; `kernel` is collected, its facts are kernel-wide. A manager name the agent does not know (`container=oci` in UBI images) does not end the detection: the file markers are checked next, as in systemd.

## `kernel`

| Field | Type | Description |
|-------|------|-------------|
| `taint.value` | uint64 | `/proc/sys/kernel/tainted`. `taint` is `null` if unreadable |
| `taint.flags` | []string | Set taint flags as letters, below. Bits past the table come as `bitN` |
| `modules[]` | object | Loaded modules: `{name, taint, state}`; `taint` is the module's flags (`PO`, `OE`, …), `state` is set only while `Loading` or `Unloading` |
| `hiddenModules` | []string | Loadable modules in `/sys/module` that are missing from `/proc/modules` — how rootkits such as Diamorphine and Reptile hide. Confirmed by a second read against load/unload races; built-in modules have no `initstate` and never match. A rootkit that also removes its sysfs entry (Suterusu) is not caught. `null` when `/proc/modules` was unreadable |
| `cpuVulnerabilities` | map | `/sys/devices/system/cpu/vulnerabilities/*`: name → `{raw, class}`, below. `raw` is the kernel's line as is |
| `lsm.active` | []string | Active LSMs, `/sys/kernel/security/lsm`. `null` without securityfs |
| `lsm.lockdown` | string | Selected lockdown mode: `none`, `integrity`, `confidentiality` |
| `lsm.apparmor` | object | `{enabled, profiles, childNamespaceProfiles}`: `profiles` counts root-namespace profiles by mode (`enforce`, `complain`, …), `null` if the list is unreadable; profiles of child namespaces (LXD) are counted apart; names are not sent. Absent when AppArmor is not built in |
| `lsm.selinux` | string | `enforcing`, `permissive`, `disabled` (the LSM list is known and has no selinux) or `unknown` |
| `livepatch[]` | object | `{name, enabled, transition}`. `transition` that stays `true` means a stuck patch |
| `time` | object | Clock state from `adjtimex` (read-only): `{unsync, clockErr, maxErrorUs, offsetUs}`. `unsync` also follows any `settimeofday` (ntpdate, VMware Tools, Hyper-V), so weigh `maxErrorUs`, not the flag alone. In a container this is the host clock |
| `cmdline` | map | Only whitelisted `/proc/cmdline` tokens, up to `--` (the rest goes to init). Keys with their values: `mitigations`, `lockdown`, `apparmor`, `selinux`, `security`, `lsm`, `module.sig_enforce`, `audit`, `audit_backlog_limit`, `ima_appraise`, `init_on_alloc`, `init_on_free`, `vsyscall`, `pti`, `spectre_v2`, `spec_store_bypass_disable`, `randomize_kstack_offset`, `page_alloc.shuffle`, `debugfs`, `iommu`, `intel_iommu`, `efi`. Flags, with an empty value: `nosmt`, `nokaslr`, `nopti`, `nospectre_v1`, `nospectre_v2`, `nosmap`, `nosmep`, `noibrs`, `slab_nomerge`. The rest of the line is never sent: it may carry passwords |
| `moduleSigEnforce` | bool | Only signed modules load (`/sys/module/module/parameters/sig_enforce`) — the effective value, set by the cmdline, `CONFIG_MODULE_SIG_FORCE` or lockdown. Absent without module signing |
| `secureBoot` | object | `{efi, enabled, setupMode}`. `efi: false` — a legacy BIOS boot, Secure Boot impossible. `enabled`/`setupMode` from the EFI variables; `null` when efivarfs is not readable. `setupMode: true` means keys are not enrolled and nothing is enforced |
| `kexec` | object | `{loaded, crashLoaded}`: a loaded kexec image boots without firmware and Secure Boot; a crash kernel (kdump) is normal. Absent without kexec |
| `smt` | object | `{control, active}`: `control` is `on`, `off`, `forceoff`, `notsupported` or `notimplemented`. With SMT active the `mitigated_smt_vulnerable` class stays open |
| `microcode` | string | CPU microcode revision (`0xf0`), x86 only |

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
| `vulnerable` | `vulnerable` anywhere in the line, other than `SMT vulnerable`: `Vulnerable…`, `Processor vulnerable`, a mitigation with a part still open (`…; BHI: Vulnerable`, `VMX: vulnerable`, `… - vulnerable module loaded`), arm64 `Mitigation: CSV2, but not BHB`, and SRSO on LTS kernels worded as a mitigation (`Mitigation: safe RET, no microcode`, `Mitigation: microcode`) |
| `mitigated_smt_vulnerable` | Mitigated, but `SMT vulnerable` |
| `mitigated` | `Mitigation: …` |
| `unknown` | `Unknown…` and anything else (`Unknown: Dependent on hypervisor status`) |

## `sysctl`

Raw values; norms depend on the host role and are the backend's job. A key the kernel does not have is absent.

| Field | Type | Description |
|-------|------|-------------|
| `values` | map | Key → raw value. KSPP: `kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.yama.ptrace_scope`, `kernel.kexec_load_disabled`, `kernel.randomize_va_space`, `kernel.modules_disabled`, `kernel.perf_event_paranoid`, `kernel.warn_limit`, `kernel.oops_limit`, `net.core.bpf_jit_harden`, `dev.tty.ldisc_autoload`, `dev.tty.legacy_tiocsti`, `fs.protected_*`, `fs.suid_dumpable`, `vm.unprivileged_userfaultfd`, `vm.mmap_min_addr`, `vm.mmap_rnd_bits`, `vm.mmap_rnd_compat_bits`. Other hardening: `kernel.io_uring_disabled`, `vm.memfd_noexec`, `kernel.sysrq`. User namespaces: `user.max_user_namespaces`, `kernel.unprivileged_userns_clone`, `kernel.apparmor_restrict_unprivileged_userns`, `kernel.apparmor_restrict_unprivileged_unconfined`. Paths the kernel executes: `kernel.core_pattern`, `kernel.modprobe`, `kernel.hotplug`. Network: `net.ipv4.ip_forward`, `net.ipv4.tcp_syncookies`, `net.ipv6.conf.all.forwarding`, `net.ipv4.icmp_echo_ignore_broadcasts`, `net.ipv4.icmp_ignore_bogus_error_responses`, `net.ipv4.ip_unprivileged_port_start`, `net.bridge.bridge-nf-call-iptables`, `net.bridge.bridge-nf-call-ip6tables`. `net.core.bpf_jit_harden` is root-only (0600): without root the section is `partial` |
| `ipv4Conf` | map | Interface (`all`, `default`, `eth0`, …) → `rp_filter`, `accept_redirects`, `secure_redirects`, `send_redirects`, `accept_source_route`, `log_martians`, `forwarding`, `route_localnet`. The effective `rp_filter` is max(all, iface); `accept_redirects` is all AND iface on a forwarding interface, all OR iface otherwise — hence `forwarding` per interface |
| `ipv6Conf` | map | Interface → `accept_redirects`, `accept_ra`, `accept_source_route`, `forwarding`, `disable_ipv6`. The kernel reads `accept_redirects` and `accept_ra` from the interface only (writing `all` does not change existing interfaces), and forwarding on the interface switches them off (`accept_ra=2` excepted), so `all.accept_ra=0` alone proves nothing |
| `confTruncated` | bool | More than 64 interfaces. Physical interfaces are taken first, per-guest ones (`fwbr*`, `fwln*`, `fwpr*`, `tap*`, `vnet*`, `vif*`) last; container-side interfaces (`veth*`, `cali*`, `lxc*`) are always skipped |

## `roleSignals`

Signals for role tags (`docker-host`, `k8s-node`, `vpn-gw`, `hypervisor`, `multi-uplink`); the backend derives the tags.

| Field | Type | Description |
|-------|------|-------------|
| `processes` | []string | Running role processes in the host network namespace, by executable (or `argv[0]` when the executable link is unreadable). Containers: `dockerd`, `containerd`, `crio`, `conmon`. Kubernetes: `kubelet`, `kubelite`, `k3s`, `rke2`, `k0s`, `kube-proxy`, `kube-apiserver`, `etcd`. Cluster networking: `cilium-agent`, `calico-node`, `flanneld`, `kube-router`, `antrea-agent`, `ovs-vswitchd`, `nomad`. Virtualization: `libvirtd`, `virtqemud`, `qemu-system-*`, `lxd`, `incus`, `incusd`, `firecracker`, `cloud-hypervisor`, `pvedaemon`. VPN: `tailscaled`, `openvpn`, `wireguard-go`, `charon`, `pluto`, `zerotier-one`, `nebula`, `netbird`. Routing: `bird`, `zebra`, `bgpd`, `keepalived`. A process in another network namespace (a VPN client or kubelet in a container) is not counted |
| `interfaces.total` | int | Network interfaces without `lo` |
| `interfaces.devTypes` | map | `DEVTYPE` → count (`bridge`, `wireguard`, `vlan`, `vxlan`, `bond`, …) |
| `interfaces.linkTypes` | map | Tunnels without a `DEVTYPE`, by link type: `gre`, `ipip`, `sit`, `ip6tnl`, `ip6gre` |
| `interfaces.tun` | int | tun/tap interfaces (wireguard-go, tailscale, openvpn) |
| `interfaces.names` | []string | Interfaces named `docker0`, `podman0`, `cni-podman0`, `cni0`, `cilium_host`, `flannel.1`, `vxlan.calico`, `tunl0`, `kube-ipvs0`, `lxdbr0`, `incusbr0`, `nomad`, `br-*`, `virbr*`, `vmbr*`, at most 32; `namesTruncated` when there were more. `br-*` also matches non-Docker bridges (`br-int` of OVS) |
| `defaultRoutes.v4` / `.v6` | int | Interfaces with a default route, not routes: ECMP gives one interface several. Blackhole and unreachable defaults do not count. IPv4 shows the main table only; IPv6 shows every table, so a VPN with its own table (wg-quick, tailscale) shows up too |
| `defaultRoutes.interfaces` | []string | Those interfaces, at most 16 — tell an uplink from a VPN by name |
| `markers` | []string | Role files that exist, checked with `lstat` only (never opened, so no daemon wakes up): `/dev/kvm`, `/etc/kubernetes/manifests/kube-apiserver.yaml`, `/var/lib/kubelet/config.yaml`, `/var/lib/rancher/k3s`, `/var/lib/rancher/rke2`, `/var/snap/microk8s`, `/var/lib/k0s`, `/etc/cni/net.d`, `/var/lib/containers/storage`, `/sys/module/wireguard`, `/proc/net/ip_vs`; and `/proc/xen/capabilities:control_d` for a Xen dom0 |

## What never leaves the host

| Read | Sent |
|------|------|
| `/proc/cmdline` | Six whitelisted tokens, above |
| Environment of PID 1 | Only whether `container=` is set and its value |
| Command lines of processes | Only the base name of `argv[0]`, and only if it is a role process |
| Role marker files | Only that they exist; they are never opened (Xen capabilities excepted, a one-word file) |
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
      "data": { "pidNsHost": true, "rootIsHostRoot": true, "netNsHost": true, "userNsHost": true, "containerKind": "none", "libc": "glibc", "init": "systemd" }
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
          "cmdline": { "mitigations": "auto" },
          "moduleSigEnforce": false,
          "secureBoot": { "efi": true, "enabled": true, "setupMode": false },
          "kexec": { "loaded": false, "crashLoaded": false },
          "smt": { "control": "on", "active": true },
          "microcode": "0xf0"
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
          "interfaces": { "total": 3, "devTypes": { "bridge": 1 }, "linkTypes": {}, "tun": 0, "names": ["docker0"] },
          "defaultRoutes": { "v4": 1, "v6": 1, "interfaces": ["eth0"] },
          "markers": []
        }
      }
    }
  }
}
```
