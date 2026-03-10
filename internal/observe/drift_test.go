package observe

import "testing"

const repoUsersFixture = `
<clickhouse>
  <users>
    <alice>
      <password_sha256_hex>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</password_sha256_hex>
      <profile>readonly</profile>
      <quota>default</quota>
      <networks>
        <ip>10.0.0.0/8</ip>
      </networks>
    </alice>
    <bob>
      <password_sha256_hex>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</password_sha256_hex>
      <profile>writer</profile>
      <quota>writers</quota>
      <networks>
        <ip>192.168.1.0/24</ip>
      </networks>
    </bob>
    <carol>
      <password_sha256_hex>cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc</password_sha256_hex>
      <profile>admin</profile>
      <quota>admins</quota>
      <networks>
        <ip>172.16.0.0/12</ip>
      </networks>
    </carol>
  </users>
</clickhouse>
`

const liveUsersFixture = `USER	alice	password_sha256_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	readonly	default	ip=10.0.0.0/8
USER	bob	password_sha256_hex=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	writer	writers	ip=192.168.1.0/24
USER	carol	password_sha256_hex=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc	admin	admins	ip=172.16.0.0/12
PROFILE	readonly	readonly=1
PROFILE	writer	max_threads=2
`

const repoNoPasswordFixture = `
<clickhouse>
  <users>
    <nopass>
      <password_sha256_hex></password_sha256_hex>
      <profile>readonly</profile>
      <quota>default</quota>
      <networks>
        <ip>10.0.0.0/8</ip>
      </networks>
    </nopass>
  </users>
</clickhouse>
`

const liveNoPasswordFixture = `USER	nopass		readonly	default	ip=10.0.0.0/8
PROFILE	readonly	readonly=1
`

const repoNoQuotaFixture = `
<clickhouse>
  <users>
    <noquota>
      <password_sha256_hex>dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd</password_sha256_hex>
      <profile>readonly</profile>
      <networks>
        <ip>10.0.0.0/8</ip>
      </networks>
    </noquota>
  </users>
</clickhouse>
`

const liveNoQuotaFixture = `USER	noquota	password_sha256_hex=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd	readonly		ip=10.0.0.0/8
PROFILE	readonly	readonly=1
`

const repoOpenNetworkFixture = `
<clickhouse>
  <users>
    <openaccess>
      <password_sha256_hex>eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee</password_sha256_hex>
      <profile>readonly</profile>
      <quota>default</quota>
      <networks>
        <ip>::/0</ip>
      </networks>
    </openaccess>
  </users>
</clickhouse>
`

const liveOpenNetworkFixture = `USER	openaccess	password_sha256_hex=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee	readonly	default	ip=::/0
PROFILE	readonly	readonly=1
`

func TestDetectConfigDriftMissingInLive(t *testing.T) {
	liveOutput := `USER	alice	password_sha256_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	readonly	default	ip=10.0.0.0/8
USER	bob	password_sha256_hex=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	writer	writers	ip=192.168.1.0/24
PROFILE	readonly	readonly=1
`

	drifts, err := DetectConfigDrift([]byte(repoUsersFixture), liveOutput)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.carol",
		DriftType: driftMissingInLive,
	})
}

func TestDetectConfigDriftMissingInRepo(t *testing.T) {
	repoXML := `
<clickhouse>
  <users>
    <alice>
      <password_sha256_hex>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</password_sha256_hex>
      <profile>readonly</profile>
      <quota>default</quota>
      <networks>
        <ip>10.0.0.0/8</ip>
      </networks>
    </alice>
    <bob>
      <password_sha256_hex>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</password_sha256_hex>
      <profile>writer</profile>
      <quota>writers</quota>
      <networks>
        <ip>192.168.1.0/24</ip>
      </networks>
    </bob>
  </users>
</clickhouse>
`

	drifts, err := DetectConfigDrift([]byte(repoXML), liveUsersFixture)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.carol",
		DriftType: driftMissingInRepo,
	})
}

func TestDetectConfigDriftDivergentPasswordHash(t *testing.T) {
	liveOutput := `USER	alice	password_sha256_hex=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff	readonly	default	ip=10.0.0.0/8
USER	bob	password_sha256_hex=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	writer	writers	ip=192.168.1.0/24
USER	carol	password_sha256_hex=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc	admin	admins	ip=172.16.0.0/12
PROFILE	readonly	readonly=1
`

	drifts, err := DetectConfigDrift([]byte(repoUsersFixture), liveOutput)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.alice.password_sha256_hex",
		RepoValue: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		LiveValue: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		DriftType: driftDivergent,
	})
}

func TestDetectConfigDriftPolicyViolationEmptyPassword(t *testing.T) {
	drifts, err := DetectConfigDrift([]byte(repoNoPasswordFixture), liveNoPasswordFixture)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.nopass.password_sha256_hex",
		DriftType: driftPolicyViolation,
	})
}

func TestDetectConfigDriftPolicyViolationNoQuota(t *testing.T) {
	drifts, err := DetectConfigDrift([]byte(repoNoQuotaFixture), liveNoQuotaFixture)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.noquota.quota",
		DriftType: driftPolicyViolation,
	})
}

func TestDetectConfigDriftPolicyViolationUnrestrictedNetwork(t *testing.T) {
	drifts, err := DetectConfigDrift([]byte(repoOpenNetworkFixture), liveOpenNetworkFixture)
	if err != nil {
		t.Fatalf("DetectConfigDrift returned error: %v", err)
	}

	assertHasDrift(t, drifts, DriftResult{
		Field:     "users.openaccess.networks",
		DriftType: driftPolicyViolation,
	})
}

func assertHasDrift(t *testing.T, drifts []DriftResult, want DriftResult) {
	t.Helper()

	for _, drift := range drifts {
		if drift.Field != want.Field {
			continue
		}
		if drift.DriftType != want.DriftType {
			continue
		}
		if want.RepoValue != "" && drift.RepoValue != want.RepoValue {
			continue
		}
		if want.LiveValue != "" && drift.LiveValue != want.LiveValue {
			continue
		}

		return
	}

	t.Fatalf("drift %+v not found in %+v", want, drifts)
}
