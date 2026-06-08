package jsluice

import (
	"os"
	"path/filepath"
	"testing"
)

// customMarkerPack is a minimal external pack with ONE rule that the embedded
// rules/secrets.arb does not contain. If AnalyzeSource honors SecretRulesPath,
// the custom class appears and the embedded providers (e.g. aws_access_key) do not.
const customMarkerPack = `feature candidate from "placer" {
    value: string
    context: string
    length: number
    entropy: number
    recoveredBy: string
    placeholder: bool
}

outcome Secret {
    class: string
    confidence: number
}

rule CustomMarker priority 1 {
    when {
        candidate.value matches "^MARKER_[A-Z0-9]{10,}$"
    }
    then Secret {
        class: "custom_marker_secret",
        confidence: 0.99,
    }
}
`

// Input carries a token the custom pack matches and a real AWS key the EMBEDDED
// pack would match. Tokens must be >=20 chars to be collected as candidates.
const externalRulesInput = `const a = "AKIA1234567890ABCDEF";
const b = "MARKER_ABCDEFGHIJKLMNOP";`

func findingsByRule(findings []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.Kind == "secret" {
			out[f.Rule] = true
		}
	}
	return out
}

func TestAnalyzeSourceUsesExternalSecretRules(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "secrets-pro.arb")
	if err := os.WriteFile(packPath, []byte(customMarkerPack), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := AnalyzeSource("input.js", []byte(externalRulesInput), Options{
		Mode:            ModeSecrets,
		SecretRulesPath: packPath,
	})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}

	rules := findingsByRule(res.Findings)
	if !rules["custom_marker_secret"] {
		t.Errorf("external pack not applied: want custom_marker_secret finding, got rules %v", rules)
	}
	if rules["aws_access_key"] {
		t.Errorf("embedded rules leaked: external pack should replace them, but aws_access_key fired; got %v", rules)
	}
}

func TestAnalyzeSourceFailsLoudOnBadSecretRulesPath(t *testing.T) {
	_, err := AnalyzeSource("input.js", []byte(externalRulesInput), Options{
		Mode:            ModeSecrets,
		SecretRulesPath: "/no/such/secrets-pro.arb",
	})
	if err == nil {
		t.Fatal("AnalyzeSource with unreadable SecretRulesPath: want error, got nil")
	}
}

func TestAnalyzeSourceEmbeddedRulesStillDefaultWhenNoPath(t *testing.T) {
	res, err := AnalyzeSource("input.js", []byte(externalRulesInput), Options{Mode: ModeSecrets})
	if err != nil {
		t.Fatalf("AnalyzeSource: %v", err)
	}
	if !findingsByRule(res.Findings)["aws_access_key"] {
		t.Errorf("embedded default broke: want aws_access_key, got %v", findingsByRule(res.Findings))
	}
}
