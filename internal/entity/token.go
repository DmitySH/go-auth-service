package entity

import "github.com/google/uuid"

type TokenPair struct {
	Access      string
	Refresh     string
	RefreshUUID uuid.UUID
}
