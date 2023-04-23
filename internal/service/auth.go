package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

var ErrNoUser = errors.New("no such user")

type AuthService struct {
	repo AuthRepository
}

func NewAuthService(repo AuthRepository) *AuthService {
	return &AuthService{
		repo: repo,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {
	_, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)

	if getUserErr == nil {
		return fmt.Errorf("user with email = %s already registered", user.Email)
	}
	if !errors.Is(getUserErr, ErrNoUser) {
		return fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	return nil
}
