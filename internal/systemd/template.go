package systemd

// GuardedTemplate returns the systemd unit template for chainwatch-guarded@.service.
// The %i instance specifier is resolved by systemd to the agent name.
func GuardedTemplate() string {
	return `[Unit]
Description=Guarded service (%i) via Chainwatch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=CHAINWATCH_PROFILE=%i
ExecStart=/usr/local/bin/chainwatch exec --profile %i -- /usr/local/bin/%i
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
`
}

// DaemonTemplate returns the systemd unit for nullbot daemon service.
// Strict sandboxing: dedicated user, read-only filesystem except inbox/outbox/state.
func DaemonTemplate() string {
	return `[Unit]
Description=Nullbot daemon (inbox/outbox job processor)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nullbot
Group=nullbot
ExecStart=/usr/local/bin/nullbot daemon --inbox /home/nullbot/inbox --outbox /home/nullbot/outbox --state /home/nullbot/state
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/nullbot/inbox /home/nullbot/outbox /home/nullbot/state
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Resource limits
CPUQuota=30%
MemoryMax=512M
TasksMax=50

[Install]
WantedBy=multi-user.target
`
}
