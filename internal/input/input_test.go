package input

import (
	"strings"
	"testing"
)

func TestFromEnvironmentEmptyValues(t *testing.T) {
	t.Parallel()

	lookup := func(name string) (string, bool) {
		values := map[string]string{"SET": "value", "EMPTY": ""}
		value, exists := values[name]
		return value, exists
	}

	if _, err := FromEnvironment("SET,EMPTY", lookup, false); err == nil {
		t.Fatal("expected empty environment variable to be rejected")
	}
	payload, err := FromEnvironment("SET,EMPTY", lookup, true)
	if err != nil {
		t.Fatalf("expected empty environment variable to be allowed: %v", err)
	}
	if got, want := string(payload), `{"EMPTY":"","SET":"value"}`; got != want {
		t.Fatalf("payload = %s, want %s", got, want)
	}
	if _, err := FromEnvironment("MISSING", lookup, true); err == nil {
		t.Fatal("expected missing environment variable to be rejected even when empties are allowed")
	}
}

func TestFromEnvironmentValidation(t *testing.T) {
	t.Parallel()

	lookup := func(string) (string, bool) { return "value", true }
	for _, names := range []string{"", "A,A", "1INVALID", "A,,B"} {
		if _, err := FromEnvironment(names, lookup, false); err == nil {
			t.Errorf("expected %q to be rejected", names)
		}
	}
}

func TestFromJSONEmptyValues(t *testing.T) {
	t.Parallel()

	tests := []string{
		`{}`,
		`{"value":""}`,
		`{"value":null}`,
		`{"value":[]}`,
		`{"value":{}}`,
		`{"value":[{"nested":""}]}`,
	}
	for _, document := range tests {
		document := document
		t.Run(document, func(t *testing.T) {
			t.Parallel()
			if _, err := FromJSON(strings.NewReader(document), false); err == nil {
				t.Fatal("expected empty value to be rejected")
			}
			if _, err := FromJSON(strings.NewReader(document), true); err != nil {
				t.Fatalf("expected empty value to be allowed: %v", err)
			}
		})
	}
}

func TestFromJSONAcceptsNonemptyValues(t *testing.T) {
	t.Parallel()

	payload, err := FromJSON(strings.NewReader(`{"zero":0,"false":false,"space":" ","nested":[{"key":"value"}]}`), false)
	if err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}
	if !strings.Contains(string(payload), `"zero":0`) {
		t.Fatalf("payload did not preserve the numeric value: %s", payload)
	}
}

func TestFromJSONRejectsInvalidRootsAndTrailingData(t *testing.T) {
	t.Parallel()

	for _, document := range []string{"", `[]`, `"value"`, `1`, `{"ok":true} {"extra":true}`, `{`} {
		if _, err := FromJSON(strings.NewReader(document), true); err == nil {
			t.Errorf("expected %q to be rejected", document)
		}
	}
}

func TestFromJSONRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	document := `{"value":"` + strings.Repeat("x", MaxPlaintextBytes) + `"}`
	if _, err := FromJSON(strings.NewReader(document), false); err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
}
