package server

import (
	"context"
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
	if autherrors.OneOf(registerErr, autherrors.WeakPassword, autherrors.InvalidEmail) {
		return nil, status.Error(codes.InvalidArgument, registerErr.Error())
	}
	if registerErr != nil {
		return nil, status.Error(codes.Internal, registerErr.Error())
	}

	return &emptypb.Empty{}, nil
}

func (s *AuthServer) Login(_ context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	loginRequest := convertLoginRequest(req)
	tokenPair, loginErr := s.authSvc.Login(context.Background(), loginRequest, req.GetFingerprint())
	if autherrors.Is(loginErr, autherrors.UserNotExists) {
		return nil, status.Error(codes.NotFound, loginErr.Error())
	}
	if autherrors.Is(loginErr, autherrors.UserInvalidPassword) {
		return nil, status.Error(codes.PermissionDenied, loginErr.Error())
	}
	if autherrors.Is(loginErr, autherrors.InvalidFingerprint) {
		return nil, status.Error(codes.InvalidArgument, loginErr.Error())
	}

	if loginErr != nil {
		return nil, status.Error(codes.Internal, loginErr.Error())
	}

	return &auth.LoginResponse{AccessToken: tokenPair.Access, RefreshToken: tokenPair.Refresh}, nil
}

func (s *AuthServer) Validate(_ context.Context, req *auth.ValidateRequest) (*auth.ValidateResponse, error) {
	userEmail, validateErr := s.authSvc.Validate(context.Background(), req.GetAccessToken())
	if autherrors.Is(validateErr, autherrors.InvalidToken) {
		return nil, status.Error(codes.PermissionDenied, validateErr.Error())
	}

	if validateErr != nil {
		return nil, status.Error(codes.Internal, validateErr.Error())
	}

	return &auth.ValidateResponse{UserEmail: userEmail}, nil
}

func (s *AuthServer) Refresh(_ context.Context, req *auth.RefreshRequest) (*auth.RefreshResponse, error) {
	tokenPair, refreshErr := s.authSvc.Refresh(context.Background(), req.GetRefreshToken(), req.GetFingerprint())
	if autherrors.Is(refreshErr, autherrors.InvalidFingerprint) {
		return nil, status.Error(codes.InvalidArgument, refreshErr.Error())
	}
	if autherrors.OneOf(refreshErr, autherrors.InvalidSession, autherrors.InvalidToken) {
		return nil, status.Error(codes.PermissionDenied, refreshErr.Error())
	}
	if autherrors.OneOf(refreshErr, autherrors.UserExists, autherrors.SessionNotExists) {
		return nil, status.Error(codes.NotFound, refreshErr.Error())
	}

	if refreshErr != nil {
		return nil, status.Error(codes.Internal, refreshErr.Error())
	}

	return &auth.RefreshResponse{AccessToken: tokenPair.Access, RefreshToken: tokenPair.Refresh}, nil
}
