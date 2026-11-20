package audit

import (
	"slices"
	"strings"
)

// matcher selects pod label or annotation keys by a list of entries that
// passed [Options.Validate].
type matcher struct {
	// exact is the sorted, distinct exact entries.
	exact []string
	// prefixes is the wildcard entries without their "*". A bare "*" is the
	// empty prefix, which matches every key.
	prefixes []string
}

func newMatcher(entries []string) matcher {
	var m matcher
	for _, entry := range entries {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			m.prefixes = append(m.prefixes, prefix)
			continue
		}
		m.exact = append(m.exact, entry)
	}
	slices.Sort(m.exact)
	m.exact = slices.Compact(m.exact)
	return m
}

// selectKeys copies from have every exact key it has, then the keys that match
// a prefix in sorted order, until maxKeys keys are copied. omitted counts the
// matched keys that were not copied. The result is never nil.
func (m matcher) selectKeys(have map[string]string, maxKeys int) (selected map[string]string, omitted int) {
	selected = make(map[string]string)
	for _, key := range m.exact {
		if value, ok := have[key]; ok {
			selected[key] = value
		}
	}
	if len(m.prefixes) == 0 {
		return selected, 0
	}
	var wildcard []string
	for key := range have {
		if _, copied := selected[key]; !copied && m.matchesPrefix(key) {
			wildcard = append(wildcard, key)
		}
	}
	slices.Sort(wildcard)
	for _, key := range wildcard {
		if len(selected) >= maxKeys {
			omitted++
			continue
		}
		selected[key] = have[key]
	}
	return selected, omitted
}

func (m matcher) matchesPrefix(key string) bool {
	for _, prefix := range m.prefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
