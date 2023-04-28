package server

import (
	"context"
	"fmt"
	"github.com/DmitySH/go-auth-service/internal/autherrors"
	"github.com/DmitySH/go-auth-service/internal/service"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	registerErr := s.authSvc.Register(context.Background(), registerRequest)
	if autherrors.Is(registerErr, autherrors.UserExists) {
		return nil, status.Error(codes.AlreadyExists, registerErr.Error())
	}
	if autherrors.Is(registerErr, autherrors.WeakPassword) {
		return nil, status.Error(codes.InvalidArgument, registerErr.Error())
	}
	if registerErr != nil {
		return nil, fmt.Errorf("registration error: %w", registerErr)
	}

	return &emptypb.Empty{}, nil
}

func (s *AuthServer) Login(_ context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	loginRequest := convertLoginRequest(req)
	token, loginErr := s.authSvc.Login(context.Background(), loginRequest)
	if autherrors.Is(loginErr, autherrors.UserNotExists) {
		return nil, status.Error(codes.NotFound, loginErr.Error())
	}
	if autherrors.Is(loginErr, autherrors.UserInvalidPassword) {
		return nil, status.Error(codes.PermissionDenied, loginErr.Error())
	}

	if loginErr != nil {
		return nil, fmt.Errorf("login error: %w", loginErr)
	}

	return &auth.LoginResponse{Token: token}, nil
}

func (s *AuthServer) Validate(_ context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	userEmail, validateErr := s.authSvc.Validate(context.Background(), req.Token)
	if autherrors.Is(validateErr, autherrors.InvalidToken) {
		return nil, status.Error(codes.PermissionDenied, validateErr.Error())
	}
	if autherrors.Is(validateErr, autherrors.UserNotExists) {
		return nil, status.Error(codes.NotFound, validateErr.Error())
	}

	if validateErr != nil {
		return nil, fmt.Errorf("validate error: %w", validateErr)
	}

	return &auth.ValidateResponse{UserEmail: userEmail}, nil
}
