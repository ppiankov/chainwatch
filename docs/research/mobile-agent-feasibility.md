# RES-06: Mobile Agent Feasibility

**Date:** 2026-03-10
**Status:** Complete
**Verdict:** Do not pursue. The observation surface on mobile devices does not support the chainwatch/nullbot thesis. Phones have no irreversible boundaries that an agent could guard.

## Question

Is a mobile agent (Android/iOS) for nullbot feasible? What would it do?

## Findings

### Android Without Root

| Observable | API | Permission |
|-----------|-----|------------|
| Battery level, temp, voltage | `BatteryManager` | None |
| Device model, OS version | `Build.*` | None |
| Total/available RAM | `ActivityManager.getMemoryInfo()` | None |
| Total/available storage | `StorageStatsManager` | None |
| WiFi state, SSID, signal | `ConnectivityManager` | `ACCESS_WIFI_STATE` |
| Installed apps list | `PackageManager` | `QUERY_ALL_PACKAGES` (restricted on Play Store since Android 11) |
| App usage time | `UsageStatsManager` | `PACKAGE_USAGE_STATS` (user grant) |
| Thermal state | `PowerManager.getThermalStatus()` | None |

**Cannot observe:** Running processes (locked since Android 5.1.1), system logs (signature-level since 4.1), per-app network traffic, kernel metrics (/proc locked since 7.0).

### iOS

Extremely limited sandbox. Can observe: battery level (5% granularity on iOS 17+), device model, system uptime, total RAM, thermal state, available disk space. **Cannot observe:** installed apps, running processes, system logs, network traffic, CPU usage, app usage. Without MDM, the observation surface is four numbers.

### Android Device Owner (Enterprise)

The only path with a rich observation surface: network logs (`retrieveNetworkLogs()`), security logs, full app inventory, WiFi config, remote reboot. But Device Owner requires factory-reset provisioning via Apple Business Manager / Android Enterprise enrollment. **This is MDM — a different product category.**

### Local LLMs on Mobile

- **Ollama is a standard Termux package** (`pkg install ollama`). No root required.
- 1.5B-3B models run at interactive speeds on 8+ GB RAM devices.
- 7B models need flagships (16 GB RAM).
- Go binaries compile and run in Termux (need Android NDK for DNS to work).
- Thermal throttling is a real issue for sustained inference.

### Existing Mobile Agent Projects

No existing project combines local LLM + system observation on mobile. AppAgent (Tencent) operates at the UI layer. MLLM has a Go server on Android but for inference, not observation.

## Why Not to Build This

1. **Observation surface too narrow without root.** Nullbot's value on servers comes from rich, unstructured data (logs, process tables, network connections). On a non-root phone: battery 85%, storage 45 GB free, RAM 3.2 GB. These are numbers, not text that needs classification. Deterministic thresholds handle all of it.

2. **Device Owner path is MDM.** The only scenario with rich enough observations requires enterprise provisioning. That means competing with Intune and Jamf.

3. **iOS is a dead end.** Four observable numbers. Not enough to justify any agent.

4. **No irreversible boundaries.** A phone is a consumption device, not an infrastructure node. There are no payments, credentials, data destruction, or external communication boundaries that an agent could guard.

## Alternative

If mobile presence is ever needed, the correct architecture is a **mobile dashboard/alert receiver** that displays findings from server-side nullbot instances. The phone is the display, not the observation target. Or use Termux as a remote terminal: `ssh server "nullbot observe"` — no mobile-specific APIs needed.
