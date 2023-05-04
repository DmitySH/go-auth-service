package service

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/google/uuid"
	"time"
)

type Logger interface {
	Print(v ...any)
	Printf(format string, v ...any)
	Fatal(v ...any)
	Fatalf(format string, v ...any)
	Warn(v ...any)
	Warnf(format string, v ...any)
}

type AuthRepository interface {
	CreateUser(ctx context.Context, user entity.AuthUser) error
	CreateSession(ctx context.Context, session entity.Session) error
	GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error)
	GetUserByID(ctx context.Context, id int64) (entity.AuthUser, error)
	GetSessionByUUID(ctx context.Context, sessionUUID uuid.UUID) (entity.Session, error)
	DeleteSessionByUUID(ctx context.Context, sessionUUID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context, olderThan time.Time) error
}

type Hasher interface {
	Hash(toHash string) (string, error)
	CompareHashes(notHashed string, hashed string) bool
}

type TokenGenerator interface {
	GenerateTokenPair(userEmail string, sessionUUID uuid.UUID) (entity.TokenPair, error)
	ValidateAccessTokenAndGetEmail(signedToken string) (string, error)
	ValidateRefreshTokenAndGetSessionUUID(signedToken string) (uuid.UUID, error)
}

type Authorization interface {
	Register(ctx context.Context, user entity.AuthUser) error
	Login(ctx context.Context, user entity.AuthUser, fingerprint string) (entity.TokenPair, error)
	Validate(ctx context.Context, accessToken string) (string, error)
	Refresh(ctx context.Context, refreshToken string, fingerprint string) (entity.TokenPair, error)
	StartClearingExpiredSessions(ctx context.Context)
}
