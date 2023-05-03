package middleware

import (
	"context"
	"fmt"
	"github.com/DmitySH/go-auth-service/pkg/log"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"regexp"
)

func LogInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	reqUUID := uuid.New()

	logStr := fmt.Sprintf("Request: %s | Method: %s | parameters: {%+v}", reqUUID, info.FullMethod, req)
	safeLogStr := hidePasswordFromLog(logStr)
	log.Logger().Infof(safeLogStr)

	ctx = context.WithValue(ctx, "request_id", reqUUID)

	return handler(ctx, req)
}

func hidePasswordFromLog(logStr string) string {
	re := regexp.MustCompile(`password:"(.*)"`)

	return re.ReplaceAllString(logStr, `password:"***"`)
}
