package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/autherrors"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/google/uuid"
	"net/mail"
	"unicode"
)

const logPattern = "method: %s | error: %v | parameters: %v"

const (
	registerMethod = "register"
	loginMethod    = "login"
	validateMethod = "validate"
	refreshMethod  = "refresh"
)

const (
	minLettersPassword  = 6
	minUppersPassword   = 2
	minSpecialsPassword = 2
	minDigitsPassword   = 2
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

	if validateEmailErr := validateEmail(user.Email); validateEmailErr != nil {
		s.logger.Printf(logPattern, registerMethod, autherrors.InvalidEmail, logMap{"user": user})
		return autherrors.NewStatusError(autherrors.InvalidEmail, nil)
	}

	if validatePasswordErr := validatePassword(user.Password); validatePasswordErr != nil {
		s.logger.Printf(logPattern, registerMethod, validatePasswordErr, logMap{"user": user})
		return autherrors.NewStatusError(autherrors.WeakPassword, validatePasswordErr)
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

func (s *AuthService) Login(ctx context.Context, user entity.AuthUser, fingerprint string) (entity.TokenPair, error) {
	fingerprintUUID, parseFingerprintErr := uuid.Parse(fingerprint)
	if parseFingerprintErr != nil {
		s.logger.Printf(logPattern, loginMethod, autherrors.InvalidFingerprint, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidFingerprint, nil)
	}

	existingUser, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, loginMethod, autherrors.UserNotExists, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		s.logger.Warnf(logPattern, loginMethod, getUserErr, logMap{"user": user})
		return entity.TokenPair{}, fmt.Errorf("can't check if user exists: %w", getUserErr)
	}
	if !s.hasher.CompareHashes(user.Password, existingUser.Password) {
		s.logger.Printf(logPattern, loginMethod, autherrors.UserInvalidPassword, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserInvalidPassword, nil)
	}

	sessionUUID := uuid.New()
	session := entity.Session{
		ID:          sessionUUID,
		UserID:      existingUser.ID,
		Fingerprint: fingerprintUUID,
	}

	tokenPair, generateTokensErr := s.tokenGenerator.GenerateTokenPair(user.Email, sessionUUID)
	if generateTokensErr != nil {
		s.logger.Warnf(logPattern, loginMethod, generateTokensErr, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't generate token pair: %w", generateTokensErr)
	}

	if createSessionErr := s.repo.CreateSession(ctx, session); createSessionErr != nil {
		s.logger.Warnf(logPattern, loginMethod, createSessionErr, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't create user's session: %w", createSessionErr)
	}

	return tokenPair, nil
}

func (s *AuthService) Validate(_ context.Context, accessToken string) (string, error) {
	userEmail, validateErr := s.tokenGenerator.ValidateAccessTokenAndGetEmail(accessToken)
	if validateErr != nil {
		s.logger.Printf(logPattern, validateMethod, autherrors.InvalidToken, logMap{"accessToken": accessToken})
		return "", autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	return userEmail, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string, fingerprint string) (entity.TokenPair, error) {
	fingerprintUUID, parseFingerprintErr := uuid.Parse(fingerprint)
	if parseFingerprintErr != nil {
		s.logger.Printf(logPattern, refreshMethod, autherrors.InvalidFingerprint, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidFingerprint, nil)
	}

	currentSessionUUID, validateErr := s.tokenGenerator.ValidateRefreshTokenAndGetSessionUUID(refreshToken)
	if validateErr != nil {
		s.logger.Printf(logPattern, refreshMethod, autherrors.InvalidToken, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	currentSession, getSessionErr := s.repo.GetSessionByUUID(ctx, currentSessionUUID)
	if errors.Is(getSessionErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, refreshMethod, autherrors.SessionNotExists, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.SessionNotExists, nil)
	}
	if getSessionErr != nil {
		s.logger.Warnf(logPattern, refreshMethod, getSessionErr, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't get user's session: %w", getSessionErr)
	}

	if deleteSessionErr := s.repo.DeleteSessionByUUID(ctx, currentSessionUUID); deleteSessionErr != nil {
		s.logger.Printf(logPattern, refreshMethod, deleteSessionErr, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't delete session: %w", deleteSessionErr)
	}

	if currentSession.Fingerprint != fingerprintUUID {
		s.logger.Printf(logPattern, refreshMethod, autherrors.InvalidSession, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidSession, errors.New("incorrect fingerprint"))
	}

	user, getUserErr := s.repo.GetUserByID(ctx, currentSession.UserID)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, refreshMethod, autherrors.UserNotExists, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		s.logger.Warnf(logPattern, refreshMethod, getUserErr, logMap{"refreshToken": refreshToken, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	newSessionUUID := uuid.New()
	newSession := entity.Session{
		ID:          newSessionUUID,
		UserID:      user.ID,
		Fingerprint: fingerprintUUID,
	}

	tokenPair, generateTokensErr := s.tokenGenerator.GenerateTokenPair(user.Email, newSessionUUID)
	if generateTokensErr != nil {
		s.logger.Warnf(logPattern, refreshMethod, generateTokensErr, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't generate token pair: %w", generateTokensErr)
	}

	if createSessionErr := s.repo.CreateSession(ctx, newSession); createSessionErr != nil {
		s.logger.Warnf(logPattern, refreshMethod, createSessionErr, logMap{"user": user, "fingerprint": fingerprint})
		return entity.TokenPair{}, fmt.Errorf("can't create user's session: %w", createSessionErr)
	}

	return tokenPair, nil
}

func validatePassword(s string) error {
	letters, specials, digits, uppers := 0, 0, 0, 0
	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			digits++
		case unicode.IsUpper(c):
			uppers++
			letters++
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			specials++
		case unicode.IsLetter(c) || c == ' ':
			letters++
		}
	}

	switch {
	case letters < minLettersPassword:
		return fmt.Errorf("too few letters: minimum is %d", minLettersPassword)
	case uppers < minUppersPassword:
		return fmt.Errorf("too few uppercase letters: minimum is %d", minUppersPassword)
	case digits < minDigitsPassword:
		return fmt.Errorf("too few digits: minimum is %d", minDigitsPassword)
	case specials < minSpecialsPassword:
		return fmt.Errorf("too few special symbols: minimum is %d", minSpecialsPassword)
	}

	return nil
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email")
	}

	return nil
}
