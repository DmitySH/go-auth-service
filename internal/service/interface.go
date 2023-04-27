package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

type Logger interface {
	Print(v ...any)
	Printf(format string, v ...any)
	Fatal(v ...any)
	Fatalf(format string, v ...any)
	Warn(v ...any)
	Warnf(format string, v ...any)
}

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error)
	CreateUser(ctx context.Context, user entity.AuthUser) error
}

type Hasher interface {
	Hash(toHash string) (string, error)
	CompareHashes(notHashed string, hashed string) bool
}

type TokenGenerator interface {
	Generate(userEmail string) (string, error)
	ValidateTokenAndGetEmail(signedToken string) (string, error)
}

type Authorization interface {
	Register(ctx context.Context, user entity.AuthUser) error
	Login(ctx context.Context, user entity.AuthUser) (string, error)
	Validate(ctx context.Context, token string) (string, error)
}
