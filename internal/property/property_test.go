package property

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	properties, err := Parse([]string{"kind=aws=credentials", "empty="})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := properties[0].Value, "aws=credentials"; got != want {
		t.Fatalf("property value = %q, want %q", got, want)
	}
	if got := properties[1].Value; got != "" {
		t.Fatalf("empty property value = %q, want empty", got)
	}
}

func TestParseRejectsInvalidProperties(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"missing-separator"},
		{"=value"},
		{"key=one", "key=two"},
		{strings.Repeat("k", maxKeyBytes+1) + "=value"},
		{"key=" + strings.Repeat("v", maxValueBytes+1)},
	}
	tooMany := make([]string, maxProperties+1)
	for index := range tooMany {
		tooMany[index] = "key" + string(rune('A'+index)) + "=value"
	}
	tests = append(tests, tooMany)

	for _, values := range tests {
		if _, err := Parse(values); err == nil {
			t.Errorf("expected properties to be rejected: %#v", values)
		}
	}
}
