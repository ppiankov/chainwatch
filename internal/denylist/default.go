package denylist

// DefaultPatterns contains the hardcoded denylist patterns.
// These are the irreversible boundaries that are always blocked.
var DefaultPatterns = Patterns{
	URLs: []string{
		"/checkout",
		"/payment",
		"stripe.com/v1/charges",
		"stripe.com/v1/payment_intents",
		"paypal.com/v1/payments",
		"paypal.com/v2/checkout",
		"/oauth/token",
		"/api/keys",
		"/account/delete",
		"/settings/security",
	},
	Files: []string{
		"~/.ssh/id_rsa",
		"~/.ssh/id_ed25519",
		"~/.aws/credentials",
		"**/.env",
		"**/.env.local",
		"**/credentials.json",
		"**/*.kdbx",
	},
	Commands: []string{
		"rm -rf /",
		"rm -rf ~",
		"dd if=/dev/zero",
		":(){ :|:& };:",
		"mkfs.",
		"> /dev/sda",
		"chmod -R 777 /",
		"curl|sh",
		"curl | sh",
		"wget|sh",
		"wget | sh",
		"sudo su",
		"sudo -i",
		"git push --force",
		"git push -f",
		"printenv",
		"/proc/self/environ",
		"/proc/*/environ",
	},
}
