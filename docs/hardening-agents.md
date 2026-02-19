# Hardening AI Agents

AI agents that execute tool calls — shell commands, file operations, HTTP requests — need external enforcement. The agent's own judgment is not a safety boundary.

## Principle

Put tool execution behind a policy gate. The gate must be a separate process that the agent cannot bypass, modify, or disable.

## Options

### 1. Policy-enforced wrapper (chainwatch)

Intercepts tool calls at irreversible boundaries. Configurable policy, denylist, and per-agent profiles.

```bash
chainwatch init
chainwatch exec --profile <agent-name> -- <agent-command>
```

Requires: chainwatch binary. No root for user mode.

### 2. Container sandbox with seccomp

Run the agent inside a container with a seccomp profile that restricts syscalls.

```bash
docker run --security-opt seccomp=agent-seccomp.json <agent-image>
```

Requires: Docker/Podman, seccomp profile. Root or rootless containers.

### 3. AppArmor / SELinux profile

Enforce OS-level mandatory access control on the agent process.

```bash
# AppArmor
apparmor_parser -r /etc/apparmor.d/agent-profile
aa-exec -p agent-profile -- <agent-command>

# SELinux
semanage fcontext -a -t agent_exec_t '/usr/local/bin/agent'
restorecon -v /usr/local/bin/agent
```

Requires: AppArmor or SELinux enabled. Root for profile installation.

### 4. VM / microVM isolation

Run the agent in a dedicated virtual machine or microVM (Firecracker, gVisor).

```bash
# Firecracker example
firectl --kernel=vmlinux --root-drive=agent-rootfs.ext4
```

Requires: hypervisor support. Strongest isolation, highest overhead.

## Combining approaches

These options are not mutually exclusive. A production setup might use:

1. **chainwatch** for policy decisions (allow/deny/approve tool calls)
2. **seccomp** for syscall-level restrictions (prevent unexpected system calls)
3. **AppArmor** for file/network access control (restrict filesystem paths)

Each layer addresses a different class of risk.

## What this guide is NOT

- Not a sales pitch for any tool
- Not a replacement for threat modeling
- Not exhaustive — evaluate your own risk profile
