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

// GetRunbook returns the appropriate runbook for the given type.
// Falls back to Linux runbook for unknown types.
func GetRunbook(runbookType string) *Runbook {
	switch runbookType {
	case "wordpress", "wp":
		return WordPressRunbook()
	case "linux", "system", "generic":
		return LinuxRunbook()
	default:
		return LinuxRunbook()
	}
}
