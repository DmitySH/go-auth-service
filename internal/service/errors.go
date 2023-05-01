package service

import (
	"errors"
)

var (
	ErrEntityNotFound = errors.New("entity was not found")
	ErrSessionExpired = errors.New("session has expired")
)
