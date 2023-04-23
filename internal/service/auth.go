package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

type AuthService struct {
	repo AuthRepository
}

func NewAuthService(repo AuthRepository) *AuthService {
	return &AuthService{
		repo: repo,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {

	return nil
}
