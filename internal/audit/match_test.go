package audit

import (
	"maps"
	"testing"
)

func TestSelectKeys(t *testing.T) {
	tests := []struct {
		name        string
		entries     []string
		maxKeys     int
		have        map[string]string
		want        map[string]string
		wantOmitted int
	}{
		{
			name:    "exact match",
			entries: []string{"app", "missing"},
			maxKeys: 32,
			have:    map[string]string{"app": "api", "tier": "web"},
			want:    map[string]string{"app": "api"},
		},
		{
			name:    "prefix match",
			entries: []string{"app.kubernetes.io/*"},
			maxKeys: 32,
			have: map[string]string{
				"app.kubernetes.io/name":    "api",
				"app.kubernetes.io/version": "1.2.3",
				"app.kubernetes.io":         "no slash",
				"team":                      "payments",
			},
			want: map[string]string{
				"app.kubernetes.io/name":    "api",
				"app.kubernetes.io/version": "1.2.3",
			},
		},
		{
			name:    "bare star matches every key",
			entries: []string{"*"},
			maxKeys: 32,
			have:    map[string]string{"a": "1", "b": "2"},
			want:    map[string]string{"a": "1", "b": "2"},
		},
		{
			name:    "overlapping entries copy a key once",
			entries: []string{"team", "te*", "team"},
			maxKeys: 1,
			have:    map[string]string{"team": "payments"},
			want:    map[string]string{"team": "payments"},
		},
		{
			name:        "exact keys first, then wildcard matches in sorted order",
			entries:     []string{"zone", "a*"},
			maxKeys:     2,
			have:        map[string]string{"a3": "3", "a1": "1", "a2": "2", "zone": "z"},
			want:        map[string]string{"a1": "1", "zone": "z"},
			wantOmitted: 2,
		},
		{
			name:        "key matched by several prefixes counts once in omitted",
			entries:     []string{"keep", "x*", "xy*"},
			maxKeys:     1,
			have:        map[string]string{"keep": "k", "xyz": "1"},
			want:        map[string]string{"keep": "k"},
			wantOmitted: 1,
		},
		{
			name:    "no entries copy nothing",
			maxKeys: 32,
			have:    map[string]string{"app": "api"},
			want:    map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, omitted := newMatcher(tt.entries).selectKeys(tt.have, tt.maxKeys)
			if got == nil {
				t.Fatal("selectKeys() returned a nil map")
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("selectKeys() = %v, want %v", got, tt.want)
			}
			if omitted != tt.wantOmitted {
				t.Errorf("selectKeys() omitted = %d, want %d", omitted, tt.wantOmitted)
			}
		})
	}
}
