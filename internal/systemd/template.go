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
