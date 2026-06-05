package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIURLsRawInputJSONL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "--raw-input", "--include-source"}, strings.NewReader(`fetch("/api", {method:"POST"})`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	objs := parseJSONL(t, stdout.String())
	obj := objs[0]
	if obj["url"] != "/api" {
		t.Fatalf("url = %#v, stdout=%s", obj["url"], stdout.String())
	}
}

func TestCLISecretsRawInputJSONL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"secrets", "--raw-input"}, strings.NewReader(`const k = "AKIA1234567890ABCDEF";`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	obj := parseJSONL(t, stdout.String())[0]
	if obj["kind"] != "AWSAccessKey" {
		t.Fatalf("kind = %#v, stdout=%s", obj["kind"], stdout.String())
	}
}

func TestCLIQueryRawInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"query", "--raw-input", "-q", "(string) @str"}, strings.NewReader(`const x = "ok";`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != `"ok"` {
		t.Fatalf("stdout = %q, want JSON string ok", got)
	}
}

func TestCLIReadsFileListFromStdin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, []byte(`document.location = "/logout"`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls"}, strings.NewReader(path+"\n"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	for _, obj := range parseJSONL(t, stdout.String()) {
		if obj["filename"] == path && obj["url"] == "/logout" {
			return
		}
	}
	t.Fatalf("missing file URL record in %s", stdout.String())
}

func TestCLIResolvePathsAndUnique(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "--raw-input", "-R", "https://example.com/a/b/", "-u"}, strings.NewReader(`
document.location = '../../guestbook.html'
const s = '../../guestbook.html'
`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %#v", lines)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("invalid JSONL: %v", err)
	}
	if obj["url"] != "https://example.com/guestbook.html" {
		t.Fatalf("url = %#v", obj["url"])
	}
}

func parseJSONL(t *testing.T, output string) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("empty stdout")
	}
	objs := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSONL: %v\n%s", err, output)
		}
		objs = append(objs, obj)
	}
	return objs
}
