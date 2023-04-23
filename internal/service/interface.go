package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error)
	CreateUser(ctx context.Context, user entity.AuthUser) error
}

type Authorization interface {
	Register(ctx context.Context, user entity.AuthUser) error
}
