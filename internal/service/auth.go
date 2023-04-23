package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"golang.org/x/crypto/bcrypt"
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

	hashedPassword, hashPwErr := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if hashPwErr != nil {
		return fmt.Errorf("can't create password hash: %w", hashPwErr)
	}

	user.Password = string(hashedPassword)

	if createUserErr := s.repo.CreateUser(ctx, user); createUserErr != nil {
		return fmt.Errorf("can't create user: %w", createUserErr)
	}

	return nil
}
