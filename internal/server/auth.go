package server

import (
	"context"
	"fmt"
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

func (s *AuthServer) Register(_ context.Context, req *auth.RegisterRequest) (*emptypb.Empty, error) {
	registerRequest := convertRegisterRequest(req)
	if registerErr := s.authSvc.Register(context.Background(), registerRequest); registerErr != nil {
		return nil, fmt.Errorf("registration error: %w", registerErr)
	}

	return &emptypb.Empty{}, nil
}

func (s *AuthServer) Login(_ context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	loginRequest := convertLoginRequest(req)
	token, loginErr := s.authSvc.Login(context.Background(), loginRequest)
	if loginErr != nil {
		return nil, fmt.Errorf("login error: %w", loginErr)
	}

	return &auth.LoginResponse{Token: token}, nil
}

func (s *AuthServer) Validate(_ context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	return &auth.ValidateResponse{UserId: 0}, nil
}
