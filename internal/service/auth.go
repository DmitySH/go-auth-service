package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/autherrors"
	"github.com/DmitySH/go-auth-service/internal/entity"
)

const logPattern = "method: %s | error: %v | parameters: %v"

const (
	registerMethod = "register"
	loginMethod    = "login"
	validateMethod = "validate"
)

type logMap map[string]interface{}

type AuthService struct {
	logger         Logger
	repo           AuthRepository
	hasher         Hasher
	tokenGenerator TokenGenerator
}

func NewAuthService(logger Logger, repo AuthRepository, hasher Hasher, tokenGenerator TokenGenerator) *AuthService {
	return &AuthService{
		logger:         logger,
		repo:           repo,
		hasher:         hasher,
		tokenGenerator: tokenGenerator,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {
	_, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)

	if getUserErr == nil {
		s.logger.Printf(logPattern, registerMethod, autherrors.UserExists, logMap{"user": user})
		return autherrors.NewStatusError(autherrors.UserExists, nil)
	}
	if !errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Warnf(logPattern, registerMethod, getUserErr, logMap{"user": user})
		return fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	hashedPassword, hashPwErr := s.hasher.Hash(user.Password)
	if hashPwErr != nil {
		s.logger.Warnf(logPattern, registerMethod, hashPwErr, logMap{"user": user})
		return fmt.Errorf("can't create password hash: %w", hashPwErr)
	}
	user.Password = hashedPassword

	if createUserErr := s.repo.CreateUser(ctx, user); createUserErr != nil {
		s.logger.Warnf(logPattern, registerMethod, createUserErr, logMap{"user": user})
		return fmt.Errorf("can't create user: %w", createUserErr)
	}

	return nil
}

func (s *AuthService) Login(ctx context.Context, user entity.AuthUser) (string, error) {
	existingUser, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, loginMethod, autherrors.UserNotExists, logMap{"user": user})
		return "", autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		s.logger.Warnf(logPattern, loginMethod, getUserErr, logMap{"user": user})
		return "", fmt.Errorf("can't check if user exists: %w", getUserErr)
	}
	if !s.hasher.CompareHashes(user.Password, existingUser.Password) {
		s.logger.Printf(logPattern, loginMethod, autherrors.UserInvalidPassword, logMap{"user": user})
		return "", autherrors.NewStatusError(autherrors.UserInvalidPassword, nil)
	}

	return s.tokenGenerator.Generate(user.Email)
}

func (s *AuthService) Validate(ctx context.Context, token string) (string, error) {
	userEmail, validateErr := s.tokenGenerator.ValidateTokenAndGetEmail(token)
	if validateErr != nil {
		s.logger.Printf(logPattern, validateMethod, autherrors.InvalidToken, logMap{"token": token})
		return "", autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	_, getUserErr := s.repo.GetUserByEmail(ctx, userEmail)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, validateMethod, autherrors.UserNotExists, logMap{"token": token})
		return "", autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}

	return userEmail, nil
}
