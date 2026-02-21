package observe

// WordPressRunbook returns investigation steps for a WordPress site.
// All commands are read-only. {{SCOPE}} is replaced with the target path.
func WordPressRunbook() *Runbook {
	return &Runbook{
		Name: "WordPress investigation",
		Type: "wordpress",
		Steps: []Step{
			{
				Command: "curl -sL -D - -o /dev/null --max-time 10 http://localhost/",
				Purpose: "check HTTP response chain for redirects",
			},
			{
				Command: "find {{SCOPE}}/wp-includes/ -name '*.php' -newer {{SCOPE}}/wp-includes/version.php -type f 2>/dev/null | head -20",
				Purpose: "find recently modified core files",
			},
			{
				Command: "grep -rl 'eval(base64_decode\\|eval(gzinflate\\|eval(str_rot13' {{SCOPE}}/wp-content/ 2>/dev/null | head -20",
				Purpose: "search for obfuscated code patterns",
			},
			{
				Command: "ls -la {{SCOPE}}/wp-content/mu-plugins/ 2>/dev/null || echo 'no mu-plugins directory'",
				Purpose: "list must-use plugins for unknown entries",
			},
			{
				Command: "find {{SCOPE}}/wp-content/plugins/ -maxdepth 1 -type d | sort",
				Purpose: "list installed plugins",
			},
			{
				Command: "find {{SCOPE}}/wp-content/uploads/ -name '*.php' -type f 2>/dev/null | head -20",
				Purpose: "find PHP files in uploads directory",
			},
			{
				Command: "cat {{SCOPE}}/.htaccess 2>/dev/null || echo 'no .htaccess'",
				Purpose: "check .htaccess for injected rewrite rules",
			},
			{
				Command: "crontab -l 2>/dev/null; cat /var/spool/cron/crontabs/* 2>/dev/null || echo 'no user crontabs accessible'",
				Purpose: "check cron jobs for suspicious entries",
			},
			{
				Command: "stat -c '%U:%G %a %n' {{SCOPE}}/wp-config.php 2>/dev/null || echo 'wp-config.php not found'",
				Purpose: "check wp-config.php ownership and permissions",
			},
			{
				Command: "awk -F: '$3==0 && $1!=\"root\" {print $1\":\"$3\":\"$7}' /etc/passwd 2>/dev/null",
				Purpose: "check for rogue UID 0 users",
			},
		},
	}
}

// LinuxRunbook returns investigation steps for a generic Linux system.
// All commands are read-only. {{SCOPE}} is replaced with the target path.
func LinuxRunbook() *Runbook {
	return &Runbook{
		Name: "Linux system investigation",
		Type: "linux",
		Steps: []Step{
			{
				Command: "uname -a",
				Purpose: "identify kernel and system",
			},
			{
				Command: "whoami && id",
				Purpose: "identify current user and groups",
			},
			{
				Command: "ps aux --sort=-%cpu | head -20",
				Purpose: "list top processes by CPU usage",
			},
			{
				Command: "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
				Purpose: "list listening ports and services",
			},
			{
				Command: "crontab -l 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null",
				Purpose: "check cron jobs and scheduled tasks",
			},
			{
				Command: "awk -F: '$3==0 && $1!=\"root\" {print}' /etc/passwd",
				Purpose: "check for rogue UID 0 users",
			},
			{
				Command: "find {{SCOPE}} -perm -o+w -type f 2>/dev/null | head -20",
				Purpose: "find world-writable files in scope",
			},
			{
				Command: "find {{SCOPE}} -newer /etc/hostname -type f 2>/dev/null | head -20",
				Purpose: "find recently modified files in scope",
			},
			{
				Command: "last -n 10 2>/dev/null || echo 'last command not available'",
				Purpose: "check recent login history",
			},
			{
				Command: "df -h && free -m",
				Purpose: "check disk and memory usage",
			},
		},
	}
}

// PostfixRunbook returns investigation steps for a Postfix mail server.
// All commands are read-only. {{SCOPE}} is replaced with the target path
// (typically /var/log for mail logs).
func PostfixRunbook() *Runbook {
	return &Runbook{
		Name: "Postfix mail server investigation",
		Type: "postfix",
		Steps: []Step{
			{
				Command: "systemctl status postfix 2>/dev/null || service postfix status 2>/dev/null || echo 'postfix service not found'",
				Purpose: "check Postfix service status",
			},
			{
				Command: "postconf mail_version 2>/dev/null || echo 'postconf not available'",
				Purpose: "identify Postfix version",
			},
			{
				Command: "mailq 2>/dev/null | tail -1 || echo 'mailq not available'",
				Purpose: "check mail queue depth",
			},
			{
				Command: "postqueue -p 2>/dev/null | head -50 || echo 'postqueue not available'",
				Purpose: "list queued messages with recipients and status",
			},
			{
				Command: "tail -100 {{SCOPE}}/mail.log 2>/dev/null || tail -100 {{SCOPE}}/maillog 2>/dev/null || journalctl -u postfix --no-pager -n 100 2>/dev/null || echo 'no mail logs found'",
				Purpose: "show recent mail log entries",
			},
			{
				Command: "grep -i 'reject\\|bounced\\|deferred\\|error\\|warning' {{SCOPE}}/mail.log 2>/dev/null | tail -30 || grep -i 'reject\\|bounced\\|deferred\\|error\\|warning' {{SCOPE}}/maillog 2>/dev/null | tail -30 || echo 'no error patterns found'",
				Purpose: "find recent delivery errors and bounces",
			},
			{
				Command: "postconf -n 2>/dev/null | grep -iE 'relay|transport|mydest|mynetworks|smtpd_recipient_restrictions|smtpd_sender_restrictions' || echo 'postconf not available'",
				Purpose: "check relay and transport configuration",
			},
			{
				Command: "postconf -n 2>/dev/null | grep -iE 'tls|ssl|smtpd_use_tls|smtp_tls' || echo 'no TLS configuration found'",
				Purpose: "check TLS configuration",
			},
			{
				Command: "ss -tlnp 2>/dev/null | grep -E ':25\\b|:587\\b|:465\\b' || netstat -tlnp 2>/dev/null | grep -E ':25\\b|:587\\b|:465\\b' || echo 'no SMTP ports listening'",
				Purpose: "check SMTP listening ports (25, 587, 465)",
			},
			{
				Command: "find /var/spool/postfix/deferred/ -type f 2>/dev/null | wc -l || echo '0'",
				Purpose: "count deferred messages",
			},
		},
	}
}

// GetRunbook returns the appropriate runbook for the given type.
// Falls back to Linux runbook for unknown types.
func GetRunbook(runbookType string) *Runbook {
	switch runbookType {
	case "wordpress", "wp":
		return WordPressRunbook()
	case "postfix", "mail":
		return PostfixRunbook()
	case "linux", "system", "generic":
		return LinuxRunbook()
	default:
		return LinuxRunbook()
	}
}
