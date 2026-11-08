package api

import "testing"

func TestCheckAuthConfig(t *testing.T) {
	cases := []struct {
		password string
		disabled bool
		ok       bool
	}{
		{"", false, false},
		{"", true, true},
		{testPassword, true, false},
		{"short", false, false},
		{"elevenchars", false, false},
		{"change-me", false, false},
		{"please-CHANGE-ME-now", false, false},
		{"changeme12345", false, false},
		{"twelve chars", false, true},
		{testPassword, false, true},
	}
	for _, c := range cases {
		err := CheckAuthConfig(c.password, c.disabled)
		if (err == nil) != c.ok {
			t.Errorf("CheckAuthConfig(%q, %v) = %v, want ok=%v", c.password, c.disabled, err, c.ok)
		}
	}
}
