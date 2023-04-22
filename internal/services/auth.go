package services

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthRepository interface {
	CreateUser(ctx context.Context, user entity.AuthUser) error
}

type AuthService struct {
	auth.UnimplementedAuthServer
	repo AuthRepository
}

func NewAuthService(repo AuthRepository) *AuthService {
	return &AuthService{
		repo: repo,
	}
}

func Register(context.Context, *auth.RegisterRequest) (*emptypb.Empty, error) {
	panic("implement me")
}

func Login(context.Context, *auth.LoginRequest) (*auth.LoginResponse, error) {
	panic("implement me")
}

func Validate(context.Context, *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	panic("implement me")
}
