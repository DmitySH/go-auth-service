package autherrors

import "fmt"

func Is(err error, status Status) bool {
	if stError, ok := err.(st); ok {
		return status == stError.Status()
	}

	return false
}

type StatusError struct {
	errorStatus Status
	innerError  error
}

func (s *StatusError) Error() string {
	if s.innerError != nil {
		return fmt.Sprintf("%s: %v", s.errorStatus, s.innerError)
	}

	return string(s.errorStatus)
}

func (s *StatusError) Status() Status {
	return s.errorStatus
}

func NewStatusError(status Status, innerError error) *StatusError {
	return &StatusError{errorStatus: status, innerError: innerError}
}
