package server

import "testing"

func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		allowed []string
		want    bool
	}{
		{"empty origin always allowed", "", nil, true},
		{"empty origin even with empty list", "", []string{}, true},
		{"non-empty origin rejected when list empty", "https://x.com", nil, false},
		{"exact match allowed", "https://x.com", []string{"https://x.com"}, true},
		{"wildcard allows any", "https://attacker.com", []string{"*"}, true},
		{"no match in list", "https://x.com", []string{"https://y.com"}, false},
		{"port-different is different origin", "https://x.com:8443", []string{"https://x.com"}, false},
		{"scheme-different is different origin", "http://x.com", []string{"https://x.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := originAllowed(tc.origin, tc.allowed); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
