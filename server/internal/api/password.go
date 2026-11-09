package api

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const minPasswordLen = 12

// CheckAuthConfig refuses to run with no admin password, or a weak one,
// unless authentication was switched off on purpose.
func CheckAuthConfig(password string, disabled bool) error {
	switch {
	case disabled && password != "":
		return errors.New("LABWARDEN_AUTH_DISABLED=true and LABWARDEN_ADMIN_PASSWORD are both set: unset one of them")
	case disabled:
		return nil
	case password == "":
		return errors.New("LABWARDEN_ADMIN_PASSWORD is not set: set it, " +
			"or set LABWARDEN_AUTH_DISABLED=true to run the dashboard without a password")
	case utf8.RuneCountInString(password) < minPasswordLen:
		return fmt.Errorf("LABWARDEN_ADMIN_PASSWORD is shorter than %d characters", minPasswordLen)
	case strings.Contains(strings.ToLower(password), "change-me"), strings.Contains(strings.ToLower(password), "changeme"):
		return errors.New("LABWARDEN_ADMIN_PASSWORD is still the example placeholder: set a real password")
	}
	return nil
}
