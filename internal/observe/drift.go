package observe

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	driftMissingInLive   = "missing_in_live"
	driftMissingInRepo   = "missing_in_repo"
	driftDivergent       = "divergent"
	driftPolicyViolation = "policy_violation"
)

var (
	clickHouseHashPattern = regexp.MustCompile(`(?i)(?:password_sha256_hex|sha256_hash|sha256_password_hash)\s*(?:=|:)\s*([0-9a-f]+)`)
	bareHexPattern        = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
)

// DriftResult captures a repo-vs-live mismatch for a ClickHouse user field.
type DriftResult struct {
	Field     string
	RepoValue string
	LiveValue string
	DriftType string
}

type clickHouseUser struct {
	Name         string
	PasswordHash string
	Profile      string
	Quota        string
	Networks     []string
}

type clickHouseXMLNode struct {
	XMLName xml.Name
	Content string              `xml:",chardata"`
	Nodes   []clickHouseXMLNode `xml:",any"`
}

// DetectConfigDrift compares repo users.xml content against a normalized live
// snapshot. Live output accepts tab-separated USER records:
// USER <name> <password hash or auth params> <profile> <quota> <networks>.
// PROFILE records are ignored so callers can pass combined query output.
func DetectConfigDrift(repoXML []byte, liveOutput string) ([]DriftResult, error) {
	repoUsers, err := parseRepoUsers(repoXML)
	if err != nil {
		return nil, err
	}

	liveUsers, err := parseLiveUsers(liveOutput)
	if err != nil {
		return nil, err
	}

	names := sortedUserNames(repoUsers, liveUsers)
	drifts := make([]DriftResult, 0)

	for _, name := range names {
		repoUser, inRepo := repoUsers[name]
		liveUser, inLive := liveUsers[name]

		switch {
		case inRepo && !inLive:
			drifts = append(drifts, DriftResult{
				Field:     userField(name),
				RepoValue: renderUser(repoUser),
				LiveValue: "",
				DriftType: driftMissingInLive,
			})
		case !inRepo && inLive:
			drifts = append(drifts, DriftResult{
				Field:     userField(name),
				RepoValue: "",
				LiveValue: renderUser(liveUser),
				DriftType: driftMissingInRepo,
			})
		case inRepo && inLive:
			appendIfDifferent(&drifts, userField(name, "password_sha256_hex"), repoUser.PasswordHash, liveUser.PasswordHash)
			appendIfDifferent(&drifts, userField(name, "profile"), repoUser.Profile, liveUser.Profile)
			appendIfDifferent(&drifts, userField(name, "quota"), repoUser.Quota, liveUser.Quota)
			appendIfDifferent(
				&drifts,
				userField(name, "networks"),
				strings.Join(repoUser.Networks, ","),
				strings.Join(liveUser.Networks, ","),
			)
		}

		appendPolicyViolations(&drifts, name, repoUser, liveUser, inRepo, inLive)
	}

	sort.Slice(drifts, func(i, j int) bool {
		if drifts[i].Field != drifts[j].Field {
			return drifts[i].Field < drifts[j].Field
		}
		if drifts[i].DriftType != drifts[j].DriftType {
			return drifts[i].DriftType < drifts[j].DriftType
		}
		if drifts[i].RepoValue != drifts[j].RepoValue {
			return drifts[i].RepoValue < drifts[j].RepoValue
		}
		return drifts[i].LiveValue < drifts[j].LiveValue
	})

	return drifts, nil
}

func appendIfDifferent(drifts *[]DriftResult, field, repoValue, liveValue string) {
	if repoValue == liveValue {
		return
	}

	*drifts = append(*drifts, DriftResult{
		Field:     field,
		RepoValue: repoValue,
		LiveValue: liveValue,
		DriftType: driftDivergent,
	})
}

func appendPolicyViolations(
	drifts *[]DriftResult,
	name string,
	repoUser clickHouseUser,
	liveUser clickHouseUser,
	inRepo bool,
	inLive bool,
) {
	if (inRepo && repoUser.PasswordHash == "") || (inLive && liveUser.PasswordHash == "") {
		*drifts = append(*drifts, DriftResult{
			Field:     userField(name, "password_sha256_hex"),
			RepoValue: valueIfPresent(repoUser.PasswordHash, inRepo),
			LiveValue: valueIfPresent(liveUser.PasswordHash, inLive),
			DriftType: driftPolicyViolation,
		})
	}

	if (inRepo && repoUser.Quota == "") || (inLive && liveUser.Quota == "") {
		*drifts = append(*drifts, DriftResult{
			Field:     userField(name, "quota"),
			RepoValue: valueIfPresent(repoUser.Quota, inRepo),
			LiveValue: valueIfPresent(liveUser.Quota, inLive),
			DriftType: driftPolicyViolation,
		})
	}

	if (inRepo && hasUnrestrictedNetworks(repoUser.Networks)) ||
		(inLive && hasUnrestrictedNetworks(liveUser.Networks)) {
		*drifts = append(*drifts, DriftResult{
			Field:     userField(name, "networks"),
			RepoValue: valueIfPresent(strings.Join(repoUser.Networks, ","), inRepo),
			LiveValue: valueIfPresent(strings.Join(liveUser.Networks, ","), inLive),
			DriftType: driftPolicyViolation,
		})
	}
}

func parseRepoUsers(repoXML []byte) (map[string]clickHouseUser, error) {
	if strings.TrimSpace(string(repoXML)) == "" {
		return nil, fmt.Errorf("parse repo XML: empty input")
	}

	var root clickHouseXMLNode
	if err := xml.Unmarshal(repoXML, &root); err != nil {
		return nil, fmt.Errorf("parse repo XML: %w", err)
	}

	usersNode := findXMLNode(&root, "users")
	if usersNode == nil {
		return nil, fmt.Errorf("parse repo XML: users element not found")
	}

	users := make(map[string]clickHouseUser, len(usersNode.Nodes))
	for _, node := range usersNode.Nodes {
		name := strings.TrimSpace(node.XMLName.Local)
		if name == "" {
			continue
		}

		users[name] = parseRepoUser(name, node)
	}

	return users, nil
}

func findXMLNode(node *clickHouseXMLNode, local string) *clickHouseXMLNode {
	if node.XMLName.Local == local {
		return node
	}

	for i := range node.Nodes {
		found := findXMLNode(&node.Nodes[i], local)
		if found != nil {
			return found
		}
	}

	return nil
}

func parseRepoUser(name string, node clickHouseXMLNode) clickHouseUser {
	user := clickHouseUser{Name: name}

	for _, child := range node.Nodes {
		switch child.XMLName.Local {
		case "password_sha256_hex":
			user.PasswordHash = normalizePasswordValue(xmlNodeText(child))
		case "password":
			if user.PasswordHash == "" {
				user.PasswordHash = strings.TrimSpace(xmlNodeText(child))
			}
		case "no_password":
			user.PasswordHash = ""
		case "profile":
			user.Profile = strings.TrimSpace(xmlNodeText(child))
		case "quota":
			user.Quota = strings.TrimSpace(xmlNodeText(child))
		case "networks":
			user.Networks = parseNetworkNodes(child.Nodes)
		}
	}

	return user
}

func xmlNodeText(node clickHouseXMLNode) string {
	var parts []string

	content := strings.TrimSpace(node.Content)
	if content != "" {
		parts = append(parts, content)
	}

	for _, child := range node.Nodes {
		text := xmlNodeText(child)
		if text == "" {
			continue
		}

		parts = append(parts, text)
	}

	return strings.TrimSpace(strings.Join(parts, " "))
}

func parseNetworkNodes(nodes []clickHouseXMLNode) []string {
	networks := make([]string, 0, len(nodes))
	for _, node := range nodes {
		kind := strings.ToLower(strings.TrimSpace(node.XMLName.Local))
		value := strings.TrimSpace(xmlNodeText(node))
		if kind == "" || value == "" {
			continue
		}

		networks = append(networks, kind+"="+value)
	}

	return normalizeNetworks(networks)
}

func parseLiveUsers(liveOutput string) (map[string]clickHouseUser, error) {
	users := make(map[string]clickHouseUser)

	for index, rawLine := range strings.Split(liveOutput, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		recordType := strings.ToUpper(strings.TrimSpace(fields[0]))

		switch recordType {
		case "USER":
			if len(fields) >= 2 && strings.EqualFold(strings.TrimSpace(fields[1]), "name") {
				continue
			}
			if len(fields) < 6 {
				return nil, fmt.Errorf("parse live output line %d: want 6 USER columns", index+1)
			}

			name := strings.TrimSpace(fields[1])
			if name == "" {
				return nil, fmt.Errorf("parse live output line %d: empty user name", index+1)
			}
			if _, exists := users[name]; exists {
				return nil, fmt.Errorf("parse live output line %d: duplicate user %q", index+1, name)
			}

			users[name] = clickHouseUser{
				Name:         name,
				PasswordHash: normalizePasswordValue(fields[2]),
				Profile:      strings.TrimSpace(fields[3]),
				Quota:        strings.TrimSpace(fields[4]),
				Networks:     parseNetworkList(fields[5]),
			}
		case "PROFILE", "TYPE", "KIND", "RECORD_TYPE":
			continue
		default:
			return nil, fmt.Errorf("parse live output line %d: unknown record %q", index+1, fields[0])
		}
	}

	return users, nil
}

func parseNetworkList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	tokens := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})

	return normalizeNetworks(tokens)
}

func normalizeNetworks(tokens []string) []string {
	seen := make(map[string]struct{}, len(tokens))
	normalized := make([]string, 0, len(tokens))

	for _, token := range tokens {
		value := strings.TrimSpace(token)
		if value == "" {
			continue
		}

		if parts := strings.SplitN(value, "=", 2); len(parts) == 2 {
			value = strings.ToLower(strings.TrimSpace(parts[0])) + "=" + strings.TrimSpace(parts[1])
		}

		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	sort.Strings(normalized)
	return normalized
}

func normalizePasswordValue(raw string) string {
	value := strings.TrimSpace(strings.Trim(raw, `"'`))
	if value == "" {
		return ""
	}

	lowerValue := strings.ToLower(value)
	switch lowerValue {
	case "no_password", "none", "null", "<empty>":
		return ""
	}

	if strings.Contains(lowerValue, "no_password") {
		return ""
	}

	if matches := clickHouseHashPattern.FindStringSubmatch(value); len(matches) == 2 {
		return strings.ToLower(matches[1])
	}

	if bareHexPattern.MatchString(value) {
		return strings.ToLower(value)
	}

	return value
}

func hasUnrestrictedNetworks(networks []string) bool {
	if len(networks) == 0 {
		return true
	}

	for _, network := range networks {
		value := strings.ToLower(strings.TrimSpace(network))
		switch value {
		case "*", "ip=*", "ip=0.0.0.0", "ip=0.0.0.0/0", "ip=::", "ip=::/0", "host=*", "host_regexp=.*":
			return true
		}

		if strings.HasPrefix(value, "host_regexp=") && strings.TrimPrefix(value, "host_regexp=") == ".*" {
			return true
		}
	}

	return false
}

func sortedUserNames(repoUsers, liveUsers map[string]clickHouseUser) []string {
	names := make(map[string]struct{}, len(repoUsers)+len(liveUsers))
	for name := range repoUsers {
		names[name] = struct{}{}
	}
	for name := range liveUsers {
		names[name] = struct{}{}
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)

	return sorted
}

func userField(name string, field ...string) string {
	path := "users." + name
	if len(field) == 0 {
		return path
	}

	return path + "." + strings.Join(field, ".")
}

func renderUser(user clickHouseUser) string {
	return strings.Join([]string{
		"password_sha256_hex=" + user.PasswordHash,
		"profile=" + user.Profile,
		"quota=" + user.Quota,
		"networks=" + strings.Join(user.Networks, ","),
	}, ";")
}

func valueIfPresent(value string, present bool) string {
	if !present {
		return ""
	}

	return value
}
