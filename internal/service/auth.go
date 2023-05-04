package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/autherrors"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/google/uuid"
	"net/mail"
	"time"
	"unicode"
)

const logPattern = "Request UUID: %s | Method: %s | Error: %v"

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

type AuthService struct {
	logger               Logger
	repo                 AuthRepository
	hasher               Hasher
	tokenGenerator       TokenGenerator
	sessionClearInterval time.Duration
}

func NewAuthService(logger Logger, repo AuthRepository,
	hasher Hasher, tokenGenerator TokenGenerator, sessionClearInterval time.Duration) *AuthService {
	return &AuthService{
		logger:               logger,
		repo:                 repo,
		hasher:               hasher,
		tokenGenerator:       tokenGenerator,
		sessionClearInterval: sessionClearInterval,
	}
}

func (s *AuthService) Register(ctx context.Context, user entity.AuthUser) error {
	_, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)

	if getUserErr == nil {
		s.logger.Printf(logPattern, requestUUID(ctx), registerMethod, autherrors.UserExists)
		return autherrors.NewStatusError(autherrors.UserExists, nil)
	}
	if !errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Warnf(logPattern, requestUUID(ctx), registerMethod, getUserErr)
		return fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	if validateEmailErr := validateEmail(user.Email); validateEmailErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), registerMethod, autherrors.InvalidEmail)
		return autherrors.NewStatusError(autherrors.InvalidEmail, nil)
	}

	if validatePasswordErr := validatePassword(user.Password); validatePasswordErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), registerMethod, validatePasswordErr)
		return autherrors.NewStatusError(autherrors.WeakPassword, validatePasswordErr)
	}

	hashedPassword, hashPwErr := s.hasher.Hash(user.Password)
	if hashPwErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), registerMethod, hashPwErr)
		return fmt.Errorf("can't create password hash: %w", hashPwErr)
	}
	user.Password = hashedPassword

	if createUserErr := s.repo.CreateUser(ctx, user); createUserErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), registerMethod, createUserErr)
		return fmt.Errorf("can't create user: %w", createUserErr)
	}

	return nil
}

func (s *AuthService) Login(ctx context.Context, user entity.AuthUser, fingerprint string) (entity.TokenPair, error) {
	fingerprintUUID, parseFingerprintErr := uuid.Parse(fingerprint)
	if parseFingerprintErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), loginMethod, autherrors.InvalidFingerprint)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidFingerprint, nil)
	}

	existingUser, getUserErr := s.repo.GetUserByEmail(ctx, user.Email)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, requestUUID(ctx), loginMethod, autherrors.UserNotExists)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), loginMethod, getUserErr)
		return entity.TokenPair{}, fmt.Errorf("can't check if user exists: %w", getUserErr)
	}
	if !s.hasher.CompareHashes(user.Password, existingUser.Password) {
		s.logger.Printf(logPattern, requestUUID(ctx), loginMethod, autherrors.UserInvalidPassword)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserInvalidPassword, nil)
	}

	sessionUUID := uuid.New()

	tokenPair, generateTokensErr := s.tokenGenerator.GenerateTokenPair(user.Email, sessionUUID)
	if generateTokensErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), loginMethod, generateTokensErr)
		return entity.TokenPair{}, fmt.Errorf("can't generate token pair: %w", generateTokensErr)
	}

	session := entity.Session{
		ID:          sessionUUID,
		UserID:      existingUser.ID,
		Fingerprint: fingerprintUUID,
		ExpiresAt:   tokenPair.Refresh.ExpiresAt,
	}

	if createSessionErr := s.repo.CreateSession(ctx, session); createSessionErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), loginMethod, createSessionErr)
		return entity.TokenPair{}, fmt.Errorf("can't create user's session: %w", createSessionErr)
	}

	return tokenPair, nil
}

func (s *AuthService) Validate(ctx context.Context, accessToken string) (string, error) {
	userEmail, validateErr := s.tokenGenerator.ValidateAccessTokenAndGetEmail(accessToken)
	if validateErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), validateMethod, autherrors.InvalidToken)
		return "", autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	return userEmail, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string, fingerprint string) (entity.TokenPair, error) {
	fingerprintUUID, parseFingerprintErr := uuid.Parse(fingerprint)
	if parseFingerprintErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, autherrors.InvalidFingerprint)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidFingerprint, nil)
	}

	currentSessionUUID, validateErr := s.tokenGenerator.ValidateRefreshTokenAndGetSessionUUID(refreshToken)
	if validateErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, autherrors.InvalidToken)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidToken, validateErr)
	}

	currentSession, getSessionErr := s.repo.GetSessionByUUID(ctx, currentSessionUUID)
	if errors.Is(getSessionErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, autherrors.SessionNotExists)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.SessionNotExists, nil)
	}
	if getSessionErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), refreshMethod, getSessionErr)
		return entity.TokenPair{}, fmt.Errorf("can't get user's session: %w", getSessionErr)
	}

	if deleteSessionErr := s.repo.DeleteSessionByUUID(ctx, currentSessionUUID); deleteSessionErr != nil {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, deleteSessionErr)
		return entity.TokenPair{}, fmt.Errorf("can't delete session: %w", deleteSessionErr)
	}

	if currentSession.Fingerprint != fingerprintUUID {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, autherrors.InvalidSession)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.InvalidSession, errors.New("incorrect fingerprint"))
	}

	user, getUserErr := s.repo.GetUserByID(ctx, currentSession.UserID)
	if errors.Is(getUserErr, ErrEntityNotFound) {
		s.logger.Printf(logPattern, requestUUID(ctx), refreshMethod, autherrors.UserNotExists)
		return entity.TokenPair{}, autherrors.NewStatusError(autherrors.UserNotExists, nil)
	}
	if getUserErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), refreshMethod, getUserErr)
		return entity.TokenPair{}, fmt.Errorf("can't check if user exists: %w", getUserErr)
	}

	newSessionUUID := uuid.New()

	tokenPair, generateTokensErr := s.tokenGenerator.GenerateTokenPair(user.Email, newSessionUUID)
	if generateTokensErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), refreshMethod, generateTokensErr)
		return entity.TokenPair{}, fmt.Errorf("can't generate token pair: %w", generateTokensErr)
	}

	newSession := entity.Session{
		ID:          newSessionUUID,
		UserID:      user.ID,
		Fingerprint: fingerprintUUID,
		ExpiresAt:   tokenPair.Refresh.ExpiresAt,
	}

	if createSessionErr := s.repo.CreateSession(ctx, newSession); createSessionErr != nil {
		s.logger.Warnf(logPattern, requestUUID(ctx), refreshMethod, createSessionErr)
		return entity.TokenPair{}, fmt.Errorf("can't create user's session: %w", createSessionErr)
	}

	return tokenPair, nil
}

func (s *AuthService) StartClearingExpiredSessions(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.sessionClearInterval)
		defer func() {
			ticker.Stop()
			s.logger.Printf("stop clearing old sessions")
		}()

		s.logger.Printf("start clearing old sessions")

		s.clearExpiredSessions(ctx)
		for {
			select {
			case <-ticker.C:
				s.clearExpiredSessions(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
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

func requestUUID(ctx context.Context) uuid.UUID {
	reqUUIDValue := ctx.Value("request_id")
	if reqUUIDValue == nil {
		return uuid.Nil
	}

	reqUUID, ok := reqUUIDValue.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}

	return reqUUID
}

func (s *AuthService) clearExpiredSessions(ctx context.Context) {
	s.logger.Printf("clearing old sessions...")

	if deleteSessionsErr := s.repo.DeleteExpiredSessions(ctx, time.Now()); deleteSessionsErr != nil {
		s.logger.Fatal("can't clear old sessions: %w", deleteSessionsErr)
	}
}
