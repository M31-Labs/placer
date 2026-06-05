package placer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSLuiceCompatBasicURL(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
const login = (redirect) => {
  document.location = "/login?redirect=" + redirect + "&method=oauth"
}
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "locationAssignment" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing locationAssignment in %#v", urls)
	}
	if got, want := found.URL, "/login?redirect=EXPR&method=oauth"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got, want := found.Method, "GET"; got != want {
		t.Fatalf("Method = %q, want %q", got, want)
	}
	if !contains(found.QueryParams, "redirect") || !contains(found.QueryParams, "method") {
		t.Fatalf("QueryParams = %#v, want redirect and method", found.QueryParams)
	}
}

func TestJSLuiceCompatFetchURL(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
fetch('/api/users?id=' + userId + '&format=json', {
  method: "POST",
  headers: {"Content-Type": "application/json", "X-Env": "stage"}
})
`))
	urls := analyzer.GetURLs()
	var found *URL
	for _, u := range urls {
		if u.Type == "fetch" {
			found = u
			break
		}
	}
	if found == nil {
		t.Fatalf("missing fetch URL in %#v", urls)
	}
	if got, want := found.URL, "/api/users?id=EXPR&format=json"; got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if got, want := found.Method, "POST"; got != want {
		t.Fatalf("Method = %q, want %q", got, want)
	}
	if got, want := found.ContentType, "application/json"; got != want {
		t.Fatalf("ContentType = %q, want %q", got, want)
	}
}

func TestJSLuiceCompatAWSSecret(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`
var config = {
  awsKey: "AKIA1234567890ABCDEF",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY"
};
`))
	secrets := analyzer.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one", secrets)
	}
	got := secrets[0]
	if got.Kind != "AWSAccessKey" || got.Severity != SeverityHigh {
		t.Fatalf("secret = %#v, want high AWSAccessKey", got)
	}
	data := got.Data.(map[string]string)
	if data["key"] != "AKIA1234567890ABCDEF" || !strings.Contains(data["secret"], "SECRETKEY") {
		t.Fatalf("data = %#v", data)
	}
	if _, err := json.Marshal(got); err != nil {
		t.Fatalf("Marshal secret: %v", err)
	}
}

func TestJSLuiceCompatUserPattern(t *testing.T) {
	patterns, err := ParseUserPatterns(strings.NewReader(`[
  {"name":"genericSecret","key":"secret","value":"^AUTH_[A-Za-z0-9]+$","severity":"medium"}
]`))
	if err != nil {
		t.Fatalf("ParseUserPatterns: %v", err)
	}
	analyzer := NewAnalyzer([]byte(`const config = {secret: "AUTH_abc123"};`))
	analyzer.AddSecretMatchers(patterns.SecretMatchers())
	secrets := analyzer.GetSecrets()
	if len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one", secrets)
	}
	if secrets[0].Kind != "genericSecret" || secrets[0].Severity != SeverityMedium {
		t.Fatalf("secret = %#v", secrets[0])
	}
}

func TestJSLuiceCompatQuery(t *testing.T) {
	analyzer := NewAnalyzer([]byte(`const x = "one"; const y = "two";`))
	var got []string
	analyzer.Query(`(string) @str`, func(n *Node) {
		got = append(got, n.AsGoType().(string))
	})
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("query got %#v", got)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
