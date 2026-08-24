package turnkeyapi

import (
	"errors"
	"fmt"
	"strings"
)

type ResponseError struct {
	StatusCode int
	RPCCode    int
	message    string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("Turnkey API request failed with HTTP status %d", e.StatusCode)
}

func (e *ResponseError) FeatureDisabled() bool {
	message := strings.ToLower(e.message)
	return strings.Contains(message, "feature") &&
		(strings.Contains(message, "disabled") || strings.Contains(message, "not enabled"))
}

type ActivityError struct {
	Status  string
	RPCCode int
	message string
}

func (e *ActivityError) Error() string {
	return fmt.Sprintf("Turnkey activity ended with status %s", e.Status)
}

func IsAuthenticationError(err error) bool {
	var responseErr *ResponseError
	return errors.As(err, &responseErr) && (responseErr.StatusCode == 401 || responseErr.RPCCode == 16)
}

func IsFeatureDisabled(err error) bool {
	var responseErr *ResponseError
	if errors.As(err, &responseErr) && responseErr.FeatureDisabled() {
		return true
	}

	var activityErr *ActivityError
	if !errors.As(err, &activityErr) {
		return false
	}
	message := strings.ToLower(activityErr.message)
	return strings.Contains(message, "feature") &&
		(strings.Contains(message, "disabled") || strings.Contains(message, "not enabled"))
}

func IsAlreadyExists(err error) bool {
	var responseErr *ResponseError
	if errors.As(err, &responseErr) && responseErr.RPCCode == 6 {
		return true
	}

	var activityErr *ActivityError
	return errors.As(err, &activityErr) && activityErr.RPCCode == 6
}

func IsInvalidArgument(err error) bool {
	var responseErr *ResponseError
	if errors.As(err, &responseErr) && responseErr.RPCCode == 3 {
		return true
	}

	var activityErr *ActivityError
	return errors.As(err, &activityErr) && activityErr.RPCCode == 3
}
