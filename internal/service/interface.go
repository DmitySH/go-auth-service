package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

type AuthRepository interface {
	CreateUser(ctx context.Context, user entity.AuthUser) error
}

type Authorization interface {
	Register(ctx context.Context, user entity.AuthUser) error
}
