package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/DmitySH/go-auth-service/internal/service"
	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"time"
)

const (
	userTable    = "auth_user"
	sessionTable = "session"
)

type AuthRepository struct {
	db   *sqlx.DB
	psql sq.StatementBuilderType
}

func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error) {
	getUserSQL, args, buildSqlErr := r.psql.Select("*").
		From(userTable).
		Where(sq.Eq{"email": email}).
		ToSql()
	if buildSqlErr != nil {
		return entity.AuthUser{}, fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	var user entity.AuthUser
	getUserErr := r.db.GetContext(ctx, &user, getUserSQL, args...)

	if errors.Is(getUserErr, sql.ErrNoRows) {
		return entity.AuthUser{}, service.ErrEntityNotFound
	}
	if getUserErr != nil {
		return entity.AuthUser{}, fmt.Errorf("error during sql executing: %w", getUserErr)
	}

	return user, nil
}

func (r *AuthRepository) GetUserByID(ctx context.Context, id int64) (entity.AuthUser, error) {
	getUserSQL, args, buildSqlErr := r.psql.Select("*").
		From(userTable).
		Where(sq.Eq{"id": id}).
		ToSql()
	if buildSqlErr != nil {
		return entity.AuthUser{}, fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	var user entity.AuthUser
	getUserErr := r.db.GetContext(ctx, &user, getUserSQL, args...)

	if errors.Is(getUserErr, sql.ErrNoRows) {
		return entity.AuthUser{}, service.ErrEntityNotFound
	}
	if getUserErr != nil {
		return entity.AuthUser{}, fmt.Errorf("error during sql executing: %w", getUserErr)
	}

	return user, nil
}

func (r *AuthRepository) CreateUser(ctx context.Context, user entity.AuthUser) error {
	createUserSQL, args, buildSqlErr := r.psql.Insert(userTable).
		Columns("email", "password").
		Values(user.Email, user.Password).
		ToSql()

	if buildSqlErr != nil {
		return fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	_, createUserErr := r.db.ExecContext(ctx, createUserSQL, args...)
	if createUserErr != nil {
		return fmt.Errorf("error during sql execution: %w", createUserErr)
	}

	return nil
}

func (r *AuthRepository) CreateSession(ctx context.Context, session entity.Session) error {
	createSessionSQL, args, buildSqlErr := r.psql.Insert(sessionTable).
		Columns("id", "user_id", "fingerprint", "expires_at").
		Values(session.ID, session.UserID, session.Fingerprint, session.ExpiresAt).
		ToSql()

	if buildSqlErr != nil {
		return fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	_, createSessionErr := r.db.ExecContext(ctx, createSessionSQL, args...)
	if createSessionErr != nil {
		return fmt.Errorf("error during sql execution: %w", createSessionErr)
	}

	return nil
}

func (r *AuthRepository) GetSessionByUUID(ctx context.Context, sessionUUID uuid.UUID) (entity.Session, error) {
	getSessionSQL, args, buildSqlErr := r.psql.Select("*").
		From(sessionTable).
		Where(sq.Eq{"id": sessionUUID}).
		ToSql()

	if buildSqlErr != nil {
		return entity.Session{}, fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	var session entity.Session
	getSessionErr := r.db.GetContext(ctx, &session, getSessionSQL, args...)
	if errors.Is(getSessionErr, sql.ErrNoRows) {
		return entity.Session{}, service.ErrEntityNotFound
	}
	if getSessionErr != nil {
		return entity.Session{}, fmt.Errorf("error during sql executing: %w", getSessionErr)
	}

	return session, nil
}

func (r *AuthRepository) DeleteSessionByUUID(ctx context.Context, sessionUUID uuid.UUID) error {
	deleteSessionSQL, args, buildSqlErr := r.psql.Delete(sessionTable).
		Where(sq.Eq{"id": sessionUUID}).
		ToSql()

	if buildSqlErr != nil {
		return fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	_, deleteSessionErr := r.db.ExecContext(ctx, deleteSessionSQL, args...)
	if deleteSessionErr != nil {
		return fmt.Errorf("error during sql execution: %w", deleteSessionErr)
	}

	return nil
}

func (r *AuthRepository) DeleteExpiredSessions(ctx context.Context, expiresAfter time.Time) error {
	deleteSessionsSQL, args, buildSqlErr := r.psql.Delete(sessionTable).
		Where(sq.Lt{"expires_at": expiresAfter}).
		ToSql()

	if buildSqlErr != nil {
		return fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	_, deleteSessionsErr := r.db.ExecContext(ctx, deleteSessionsSQL, args...)
	if deleteSessionsErr != nil {
		return fmt.Errorf("error during sql execution: %w", deleteSessionsErr)
	}

	return nil
}

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{
		db:   db,
		psql: sq.StatementBuilder.PlaceholderFormat(sq.Dollar)}
}
