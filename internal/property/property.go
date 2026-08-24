package property

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

const (
	maxProperties = 32
	maxKeyBytes   = 256
	maxValueBytes = 4096
)

func Parse(values []string) ([]turnkeyapi.KeyValue, error) {
	if len(values) > maxProperties {
		return nil, fmt.Errorf("at most %d static properties are allowed", maxProperties)
	}

	properties := make([]turnkeyapi.KeyValue, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		key, propertyValue, found := strings.Cut(value, "=")
		if !found {
			return nil, errors.New("static property must use key=value syntax")
		}
		if key == "" {
			return nil, errors.New("static property key must not be empty")
		}
		if len(key) > maxKeyBytes {
			return nil, fmt.Errorf("static property key %q exceeds %d bytes", key, maxKeyBytes)
		}
		if len(propertyValue) > maxValueBytes {
			return nil, fmt.Errorf("static property value for key %q exceeds %d bytes", key, maxValueBytes)
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate static property key %q", key)
		}
		seen[key] = struct{}{}
		properties = append(properties, turnkeyapi.KeyValue{Key: key, Value: propertyValue})
	}

	return properties, nil
}
