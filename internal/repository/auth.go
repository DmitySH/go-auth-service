package repository

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type AuthRepository struct {
	db *sqlx.DB
}

func (r AuthRepository) CreateUser(ctx context.Context, user entity.AuthUser) error {
	panic("implement me")
}

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{db: db}
}
