package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/tkhq/secretctl/internal/turnkeyapi"
)

const (
	codeAuthFailed      = "AUTH_FAILED"
	codeFeatureDisabled = "FEATURE_DISABLED"
	codePayloadInvalid  = "PAYLOAD_INVALID"
	codeNameConflict    = "NAME_CONFLICT"
	codeImportFailed    = "IMPORT_FAILED"
	codeListFailed      = "LIST_FAILED"
	codeInternal        = "INTERNAL_ERROR"
)

type appError struct {
	Code     string
	Message  string
	ExitCode int
	err      error
}

func (e *appError) Error() string {
	return e.Message
}

func (e *appError) Unwrap() error {
	return e.err
}

func wrapAppError(code, message string, exitCode int, err error) error {
	if err == nil {
		err = errors.New(message)
	}
	return &appError{Code: code, Message: message, ExitCode: exitCode, err: err}
}

func payloadError(message string, err error) error {
	return wrapAppError(codePayloadInvalid, message, 2, err)
}

func operationError(operation string, err error) error {
	if turnkeyapi.IsAuthenticationError(err) {
		return wrapAppError(codeAuthFailed, "Turnkey authentication failed", 3, err)
	}
	if turnkeyapi.IsFeatureDisabled(err) {
		return wrapAppError(codeFeatureDisabled, "Turnkey Secret Storage is not enabled for this organization", 4, err)
	}
	if operation == "import" && turnkeyapi.IsAlreadyExists(err) {
		return wrapAppError(codeNameConflict, "a secret with this name already exists", 5, err)
	}
	if operation == "import" && turnkeyapi.IsInvalidArgument(err) {
		return wrapAppError(codePayloadInvalid, "Turnkey rejected the secret metadata or encrypted payload", 2, err)
	}
	if operation == "list" {
		return wrapAppError(codeListFailed, "failed to list secrets", 6, err)
	}
	return wrapAppError(codeImportFailed, "failed to import secret", 6, err)
}

func writeError(writer io.Writer, err error) int {
	appErr := &appError{
		Code:     codeInternal,
		Message:  "an unexpected error occurred",
		ExitCode: 1,
		err:      err,
	}
	var classified *appError
	if errors.As(err, &classified) {
		appErr = classified
	}

	response := struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{OK: false}
	response.Error.Code = appErr.Code
	response.Error.Message = appErr.Message

	if encodeErr := json.NewEncoder(writer).Encode(response); encodeErr != nil {
		_, _ = fmt.Fprintln(writer, `{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"could not encode error output"}}`)
		return 1
	}
	return appErr.ExitCode
}
