package entity

import "time"

type TokenPair struct {
	Access  Token
	Refresh Token
}

type Token struct {
	Token     string
	ExpiresAt time.Time
}
