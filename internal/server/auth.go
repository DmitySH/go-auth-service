package server

import (
	"context"
	"github.com/DmitySH/go-auth-service/internal/service"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthServer struct {
	auth.UnimplementedAuthServer
	authSvc service.Authorization
}

func NewAuthServer(service service.Authorization) *AuthServer {
	return &AuthServer{
		authSvc: service,
	}
}

func (s *AuthServer) Register(ctx context.Context, req *auth.RegisterRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	return &auth.LoginResponse{Token: ""}, nil
}

func (s *AuthServer) Validate(ctx context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	return &auth.ValidateResponse{UserId: 0}, nil
}
