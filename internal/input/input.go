package input

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	MaxPlaintextBytes = 60 * 1024
	maxInputBytes     = 1 << 20
)

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type LookupEnv func(string) (string, bool)

func FromEnvironment(names string, lookup LookupEnv, allowEmptyValues bool) ([]byte, error) {
	if lookup == nil {
		return nil, errors.New("environment lookup is required")
	}
	if strings.TrimSpace(names) == "" {
		return nil, errors.New("--from-env requires at least one environment variable name")
	}

	values := make(map[string]string)
	for _, rawName := range strings.Split(names, ",") {
		name := strings.TrimSpace(rawName)
		if !environmentName.MatchString(name) {
			return nil, fmt.Errorf("invalid environment variable name %q", name)
		}
		if _, exists := values[name]; exists {
			return nil, fmt.Errorf("duplicate environment variable name %q", name)
		}

		value, exists := lookup(name)
		if !exists {
			return nil, fmt.Errorf("required environment variable %q is not set", name)
		}
		if value == "" && !allowEmptyValues {
			return nil, fmt.Errorf("environment variable %q is empty; use --allow-empty-values to permit it", name)
		}
		values[name] = value
	}

	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode environment variables as JSON: %w", err)
	}
	if err := validateSize(encoded); err != nil {
		return nil, err
	}

	return encoded, nil
}

func FromJSON(reader io.Reader, allowEmptyValues bool) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("JSON input reader is required")
	}

	raw, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JSON input: %w", err)
	}
	if len(raw) > maxInputBytes {
		return nil, errors.New("JSON input exceeds 1 MiB parsing limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("JSON input must contain exactly one document")
		}
		return nil, fmt.Errorf("decode trailing JSON input: %w", err)
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON input must be an object")
	}
	if !allowEmptyValues {
		if path, empty := findEmpty(object, "$"); empty {
			return nil, fmt.Errorf("JSON value at %s is empty; use --allow-empty-values to permit it", path)
		}
	}

	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("compact JSON input: %w", err)
	}
	if err := validateSize(encoded); err != nil {
		return nil, err
	}

	return encoded, nil
}

func findEmpty(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case nil:
		return path, true
	case string:
		return path, typed == ""
	case []any:
		if len(typed) == 0 {
			return path, true
		}
		for index, child := range typed {
			if emptyPath, empty := findEmpty(child, fmt.Sprintf("%s[%d]", path, index)); empty {
				return emptyPath, true
			}
		}
	case map[string]any:
		if len(typed) == 0 {
			return path, true
		}
		for key, child := range typed {
			if emptyPath, empty := findEmpty(child, path+"."+key); empty {
				return emptyPath, true
			}
		}
	}

	return "", false
}

func validateSize(encoded []byte) error {
	if len(encoded) > MaxPlaintextBytes {
		return fmt.Errorf("JSON payload is %d bytes; maximum is %d bytes", len(encoded), MaxPlaintextBytes)
	}
	return nil
}
