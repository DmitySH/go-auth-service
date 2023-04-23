package server

import (
	"github.com/DmitySH/go-auth-service/internal/entity"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
)

func convertRegisterRequest(req *auth.RegisterRequest) entity.AuthUser {
	return entity.AuthUser{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	}
}
