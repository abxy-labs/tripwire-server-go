package foil

import "fmt"

type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string {
	return e.Message
}

type TokenVerificationError struct {
	Message string
	Err     error
}

func (e *TokenVerificationError) Error() string {
	return e.Message
}

func (e *TokenVerificationError) Unwrap() error {
	return e.Err
}

type APIError struct {
	Status      int
	Code        string
	Message     string
	RequestID   string
	FieldErrors []FieldError
	DocsURL     string
	Body        map[string]any
}

func (e *APIError) Error() string {
	return e.Message
}

func newGenericAPIError(status int, message string, requestID string, body map[string]any) *APIError {
	return &APIError{
		Status:    status,
		Code:      "request.failed",
		Message:   message,
		RequestID: requestID,
		Body:      body,
	}
}

func wrapInvalidJSONError(err error) *APIError {
	return &APIError{
		Status:  500,
		Code:    "response.invalid_json",
		Message: fmt.Sprintf("Foil API returned invalid JSON: %v", err),
	}
}
