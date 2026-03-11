package observe

import (
	"strings"
	"testing"
)

const sampleClickHouseUsersXML = `<?xml version="1.0"?>
<clickhouse>
  <users>
    <default>
      <password>supersecret123</password>
      <networks>
        <ip>::/0</ip>
      </networks>
      <profile>default</profile>
      <quota>default</quota>
    </default>
    <analytics>
      <password_sha256_hex>a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2</password_sha256_hex>
      <networks>
        <ip>10.0.0.0/8</ip>
      </networks>
    </analytics>
    <replication>
      <password_double_sha1_hex>deadbeef1234567890abcdef1234567890abcdef</password_double_sha1_hex>
    </replication>
  </users>
</clickhouse>`

const sampleClickHouseConfigXML = `<?xml version="1.0"?>
<clickhouse>
  <remote_servers>
    <cluster_prod>
      <shard>
        <replica>
          <host>ch-prod-01.internal.company.com</host>
          <port>9000</port>
          <user>replication_user</user>
          <password>repl_pass_123</password>
        </replica>
        <replica>
          <host>ch-prod-02.internal.company.com</host>
          <port>9000</port>
        </replica>
      </shard>
    </cluster_prod>
  </remote_servers>
  <interserver_http_host>ch-prod-01.internal.company.com</interserver_http_host>
  <storage_configuration>
    <disks>
      <s3>
        <type>s3</type>
        <endpoint>https://s3.amazonaws.com/bucket/</endpoint>
        <access_key_id>TESTKEY00000000ID1234</access_key_id>
        <secret_access_key>exampleSecretKeyValue1234567890abcdef</secret_access_key>
      </s3>
    </disks>
  </storage_configuration>
</clickhouse>`

func TestRedactCredentials(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, count := RedactEvidence(sampleClickHouseUsersXML, rules)

	if count == 0 {
		t.Fatal("expected redactions but got 0")
	}

	// Passwords must be gone.
	if strings.Contains(redacted, "supersecret123") {
		t.Error("plaintext password not redacted")
	}
	if strings.Contains(redacted, "a1b2c3d4e5f6") {
		t.Error("SHA256 password hash not redacted")
	}
	if strings.Contains(redacted, "deadbeef1234") {
		t.Error("double SHA1 password hash not redacted")
	}

	// Redaction placeholders must be present.
	if !strings.Contains(redacted, "<password>[REDACTED]</password>") {
		t.Error("missing password redaction placeholder")
	}
	if !strings.Contains(redacted, "<password_sha256_hex>[REDACTED]</password_sha256_hex>") {
		t.Error("missing SHA256 redaction placeholder")
	}

	// Structure must be preserved.
	if !strings.Contains(redacted, "<profile>default</profile>") {
		t.Error("non-sensitive content was incorrectly redacted")
	}
}

func TestRedactHostnames(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, count := RedactEvidence(sampleClickHouseConfigXML, rules)

	if count == 0 {
		t.Fatal("expected redactions but got 0")
	}

	// Hostnames must be gone.
	if strings.Contains(redacted, "ch-prod-01.internal.company.com") {
		t.Error("hostname not redacted")
	}
	if strings.Contains(redacted, "ch-prod-02.internal.company.com") {
		t.Error("second hostname not redacted")
	}

	// Interserver host must be gone.
	if strings.Contains(redacted, "interserver_http_host>ch-prod") {
		t.Error("interserver_http_host not redacted")
	}

	// Redaction placeholders must be present.
	if !strings.Contains(redacted, "<host>[REDACTED_HOST]</host>") {
		t.Error("missing host redaction placeholder")
	}
	if !strings.Contains(redacted, "<interserver_http_host>[REDACTED_HOST]</interserver_http_host>") {
		t.Error("missing interserver_http_host redaction placeholder")
	}
}

func TestRedactUsernames(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, _ := RedactEvidence(sampleClickHouseConfigXML, rules)

	if strings.Contains(redacted, "replication_user") {
		t.Error("username in <user> tag not redacted")
	}
	if !strings.Contains(redacted, "<user>[REDACTED_USER]</user>") {
		t.Error("missing user redaction placeholder")
	}
}

func TestRedactS3Credentials(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, _ := RedactEvidence(sampleClickHouseConfigXML, rules)

	if strings.Contains(redacted, "TESTKEY00000000ID1234") {
		t.Error("S3 access key not redacted")
	}
	if strings.Contains(redacted, "wJalrXUtnFEMI") {
		t.Error("S3 secret key not redacted")
	}
	if !strings.Contains(redacted, "<access_key_id>[REDACTED]</access_key_id>") {
		t.Error("missing access_key_id redaction placeholder")
	}
	if !strings.Contains(redacted, "<secret_access_key>[REDACTED]</secret_access_key>") {
		t.Error("missing secret_access_key redaction placeholder")
	}
}

func TestRedactPreservesStructure(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, _ := RedactEvidence(sampleClickHouseConfigXML, rules)

	// Non-sensitive elements must survive.
	mustContain := []string{
		"<port>9000</port>",
		"<type>s3</type>",
		"<endpoint>https://s3.amazonaws.com/bucket/</endpoint>",
		"<cluster_prod>",
		"<shard>",
		"<replica>",
	}
	for _, s := range mustContain {
		if !strings.Contains(redacted, s) {
			t.Errorf("non-sensitive element %q was incorrectly redacted", s)
		}
	}
}

func TestRedactNoMatch(t *testing.T) {
	rules := DefaultRedactRules()
	input := "just some plain text with no XML tags"
	redacted, count := RedactEvidence(input, rules)

	if count != 0 {
		t.Errorf("expected 0 redactions, got %d", count)
	}
	if redacted != input {
		t.Error("input should be unchanged when no patterns match")
	}
}

func TestRedactEmptyInput(t *testing.T) {
	rules := DefaultRedactRules()
	redacted, count := RedactEvidence("", rules)

	if count != 0 {
		t.Errorf("expected 0 redactions, got %d", count)
	}
	if redacted != "" {
		t.Error("empty input should return empty output")
	}
}

func TestRedactEmptyRules(t *testing.T) {
	redacted, count := RedactEvidence(sampleClickHouseUsersXML, nil)

	if count != 0 {
		t.Errorf("expected 0 redactions, got %d", count)
	}
	if redacted != sampleClickHouseUsersXML {
		t.Error("input should be unchanged with no rules")
	}
}

func TestRedactCount(t *testing.T) {
	rules := DefaultRedactRules()

	// Users XML has: 1 password, 1 sha256, 1 double_sha1 = 3 credential redactions
	// Plus usernames in default/analytics/replication sections — but those are
	// section names (not <user> tags), so no username redactions here.
	_, count := RedactEvidence(sampleClickHouseUsersXML, rules)
	if count < 3 {
		t.Errorf("expected at least 3 redactions in users XML, got %d", count)
	}

	// Config XML has: 1 password, 2 hosts, 1 interserver_http_host, 1 user,
	// 1 access_key_id, 1 secret_access_key = at least 7
	_, count = RedactEvidence(sampleClickHouseConfigXML, rules)
	if count < 7 {
		t.Errorf("expected at least 7 redactions in config XML, got %d", count)
	}
}

func TestDefaultRedactRulesCompile(t *testing.T) {
	rules := DefaultRedactRules()
	if len(rules) == 0 {
		t.Fatal("DefaultRedactRules returned empty list")
	}
	for _, r := range rules {
		if r.Name == "" {
			t.Error("rule has empty name")
		}
		if r.Pattern == nil {
			t.Errorf("rule %q has nil pattern", r.Name)
		}
		if r.Replacement == "" {
			t.Errorf("rule %q has empty replacement", r.Name)
		}
	}
}
