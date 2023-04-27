package middleware

import (
	"context"
	"github.com/DmitySH/go-auth-service/pkg/log"
	"google.golang.org/grpc"
)

func LogInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {

	log.Logger().Infof("called %s | parameters {%v}", info.FullMethod, req)

	return handler(ctx, req)
}
