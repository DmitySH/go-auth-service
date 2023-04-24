package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

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
	Validate(signedToken string) (string, error)
}

type Authorization interface {
	Register(ctx context.Context, user entity.AuthUser) error
	Login(ctx context.Context, user entity.AuthUser) (string, error)
}
