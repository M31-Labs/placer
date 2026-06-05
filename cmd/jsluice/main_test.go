package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLIURLsRawInputJSONL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"urls", "--raw-input", "--include-source"}, strings.NewReader(`fetch("/api", {method:"POST"})`), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v stderr=%s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("empty stdout")
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &obj); err != nil {
		t.Fatalf("invalid JSONL: %v\n%s", err, stdout.String())
	}
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
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &obj); err != nil {
		t.Fatalf("invalid JSONL: %v\n%s", err, stdout.String())
	}
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
