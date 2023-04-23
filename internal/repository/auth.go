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

const userTable = "auth_user"

type AuthRepository struct {
	db   *sqlx.DB
	psql sq.StatementBuilderType
}

func (r AuthRepository) GetUserByEmail(ctx context.Context, email string) (entity.AuthUser, error) {
	getUserSQL, args, buildSqlErr := r.psql.Select("*").From(userTable).Where(sq.Eq{
		"email": email,
	}).ToSql()
	if buildSqlErr != nil {
		return entity.AuthUser{}, fmt.Errorf("can't build sql: %w", buildSqlErr)
	}

	var user entity.AuthUser
	getUserErr := r.db.GetContext(ctx, &user, getUserSQL, args...)

	if errors.Is(getUserErr, sql.ErrNoRows) {
		return entity.AuthUser{}, service.ErrNoUser
	}
	if getUserErr != nil {
		return entity.AuthUser{}, fmt.Errorf("can't get user: %w", getUserErr)
	}

	return user, nil
}

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{
		db:   db,
		psql: sq.StatementBuilder.PlaceholderFormat(sq.Dollar)}
}
