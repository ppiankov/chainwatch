package redact

import "strings"

// DefaultPIIKeys are the keys automatically redacted.
var DefaultPIIKeys = []string{
	"name", "email", "phone", "ssn", "social_security",
	"address", "date_of_birth", "dob", "passport",
	"credit_card", "card_number", "cvv", "password",
}

// MaskValue replaces a value with "***". Numbers and bools are preserved.
func MaskValue(v any) any {
	switch v.(type) {
	case int, int64, float64, bool:
		return v
	case nil:
		return nil
	default:
		return "***"
	}
}

// RedactMap redacts specified keys in a map.
func RedactMap(data map[string]any, keys []string) map[string]any {
	result := make(map[string]any, len(data))
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[strings.ToLower(k)] = true
	}

	for k, v := range data {
		if keySet[strings.ToLower(k)] {
			result[k] = MaskValue(v)
		} else {
			result[k] = v
		}
	}
	return result
}

// RedactAuto redacts default PII keys plus any extra keys from a map.
func RedactAuto(data map[string]any, extraKeys []string) map[string]any {
	allKeys := append([]string{}, DefaultPIIKeys...)
	allKeys = append(allKeys, extraKeys...)
	return RedactMap(data, allKeys)
}

// RedactRecords redacts each record in a slice.
func RedactRecords(records []map[string]any, keys []string) []map[string]any {
	result := make([]map[string]any, len(records))
	for i, r := range records {
		result[i] = RedactMap(r, keys)
	}
	return result
}
