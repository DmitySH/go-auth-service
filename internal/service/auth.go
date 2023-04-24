package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

var ErrEntityNotFound = errors.New("entity was not found")

type AuthService struct {
	repo   AuthRepository
	hasher Hasher
}

func NewAuthService(repo AuthRepository, hasher Hasher) *AuthService {
	return &AuthService{
		repo:   repo,
		hasher: hasher,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {
	_, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)

	if getUserErr == nil {
		return fmt.Errorf("user with email = %s already registered", user.Email)
	}
	if !errors.Is(getUserErr, ErrEntityNotFound) {
		return fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	hashedPassword, hashPwErr := s.hasher.Hash(user.Password)
	if hashPwErr != nil {
		return fmt.Errorf("can't create password hash: %w", hashPwErr)
	}
	user.Password = hashedPassword

	if createUserErr := s.repo.CreateUser(ctx, user); createUserErr != nil {
		return fmt.Errorf("can't create user: %w", createUserErr)
	}

	return nil
}
