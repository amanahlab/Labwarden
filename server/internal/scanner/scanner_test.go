package scanner

import (
	"slices"
	"testing"
)

func TestSyftEnvUsesGrypeRegistrySettings(t *testing.T) {
	env := syftEnv([]string{
		"PATH=/bin",
		"GRYPE_REGISTRY_AUTH_USERNAME=u",
		"GRYPE_REGISTRY_INSECURE_USE_HTTP=true",
		"GRYPE_REGISTRY_AUTH_PASSWORD=from-grype",
		"SYFT_REGISTRY_AUTH_PASSWORD=from-syft",
	})
	for _, want := range []string{"SYFT_REGISTRY_AUTH_USERNAME=u", "SYFT_REGISTRY_INSECURE_USE_HTTP=true", "SYFT_CHECK_FOR_APP_UPDATE=false"} {
		if !slices.Contains(env, want) {
			t.Errorf("missing %s", want)
		}
	}
	if slices.Contains(env, "SYFT_REGISTRY_AUTH_PASSWORD=from-grype") {
		t.Error("a GRYPE_ setting overrode the SYFT_ one")
	}
}
