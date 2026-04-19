package server

import (
	"strings"
	"testing"
)

func TestValidateTCPLocalPort(t *testing.T) {
	cases := []struct {
		port    uint16
		wantErr bool
	}{
		{port: 3000, wantErr: false},
		{port: 8080, wantErr: false},
		{port: 5432, wantErr: false},
		{port: 22,   wantErr: false}, // SSH allowed
		{port: 25,   wantErr: true},  // SMTP blocked
		{port: 53,   wantErr: true},  // DNS blocked
		{port: 465,  wantErr: true},  // SMTPS blocked
		{port: 587,  wantErr: true},  // SMTP submission blocked
		{port: 0,    wantErr: true},  // port 0 invalid
	}
	for _, tc := range cases {
		err := validateTCPLocalPort(tc.port)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateTCPLocalPort(%d) error = %v, wantErr %v", tc.port, err, tc.wantErr)
		}
	}
}

func TestValidateSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// valid
		{"single char", "a", false},
		{"two chars", "ab", false},
		{"alphanumeric", "abc123", false},
		{"hyphen in middle", "my-app", false},
		{"digits only", "123", false},
		{"max length 63", strings.Repeat("a", 63), false},
		// invalid format
		{"empty", "", true},
		{"starts with hyphen", "-abc", true},
		{"ends with hyphen", "abc-", true},
		{"uppercase", "ABC", true},
		{"mixed case", "myApp", true},
		{"underscore", "my_app", true},
		{"dot", "my.app", true},
		{"space", "my app", true},
		{"too long 64 chars", strings.Repeat("a", 64), true},
		// reserved names
		{"reserved www", "www", true},
		{"reserved api", "api", true},
		{"reserved admin", "admin", true},
		{"reserved mail", "mail", true},
		{"reserved smtp", "smtp", true},
		{"reserved ftp", "ftp", true},
		{"reserved ns", "ns", true},
		{"reserved ns1", "ns1", true},
		{"reserved ns2", "ns2", true},
		{"reserved mx", "mx", true},
		{"reserved vpn", "vpn", true},
		{"reserved ssh", "ssh", true},
		{"reserved localhost", "localhost", true},
		{"reserved root", "root", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubdomain(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSubdomain(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}
