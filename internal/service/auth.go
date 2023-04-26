package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/autherrors"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

type AuthService struct {
	repo           AuthRepository
	hasher         Hasher
	tokenGenerator TokenGenerator
}

func NewAuthService(repo AuthRepository, hasher Hasher, tokenGenerator TokenGenerator) *AuthService {
	return &AuthService{
		repo:           repo,
		hasher:         hasher,
		tokenGenerator: tokenGenerator,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {
	_, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)

	if getUserErr == nil {
		return autherrors.NewStatusError(autherrors.UserExists, nil)
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

func (s *AuthService) Login(ctx context.Context, user entity.AuthUser) (string, error) {
	existingUser, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		return "", autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		return "", fmt.Errorf("can't check if user exists: %w", getUserErr)
	}
	if !s.hasher.CompareHashes(user.Password, existingUser.Password) {
		return "", autherrors.NewStatusError(autherrors.UserInvalidPassword, nil)
	}

	return s.tokenGenerator.Generate(user.Email)
}

func (s *AuthService) Validate(ctx context.Context, token string) (string, error) {
	userEmail, validateErr := s.tokenGenerator.ValidateTokenAndGetEmail(token)
	if validateErr != nil {
		return "", autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	_, getUserErr := s.repo.GetUserByEmail(ctx, userEmail)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		return "", autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}

	return userEmail, nil
}
