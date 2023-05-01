package entity

import "github.com/google/uuid"

type AuthUser struct {
	ID       int64
	Email    string
	Password string
}

type Session struct {
	ID          uuid.UUID
	Fingerprint uuid.UUID
	UserID      int64
}
