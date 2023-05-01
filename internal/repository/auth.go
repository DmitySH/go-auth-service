package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/DmitySH/go-auth-service/internal/service"
	sq "github.com/Masterminds/squirrel"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
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

func (r *AuthRepository) GetUserByEmailAndPassword(ctx context.Context, email string, password string) (entity.AuthUser, error) {
	getUserSQL, args, buildSqlErr := r.psql.Select("*").
		From(userTable).
		Where(sq.Eq{"email": email, "password": password}).
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
		Columns("id", "user_id", "fingerprint").
		Values(session.ID, session.UserID, session.Fingerprint).
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

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{
		db:   db,
		psql: sq.StatementBuilder.PlaceholderFormat(sq.Dollar)}
}
