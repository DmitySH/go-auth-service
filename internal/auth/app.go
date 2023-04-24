package auth

import (
	"github.com/DmitySH/go-auth-service/internal/hashser"
	"github.com/DmitySH/go-auth-service/internal/repository"
	"github.com/DmitySH/go-auth-service/internal/server"
	"github.com/DmitySH/go-auth-service/internal/service"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
	"github.com/DmitySH/go-auth-service/pkg/grpcutils"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"log"
)

func Run() {
	serverCfg := grpcutils.GRPCServerConfig{
		Host: viper.GetString("SERVER_HOST"),
		Port: viper.GetInt("SERVER_PORT"),
	}
	db, connectDbErr := repository.NewPostgresDB(repository.DBConfig{
		Host:     viper.GetString("DB_HOST"),
		Port:     viper.GetInt("DB_PORT"),
		Username: viper.GetString("DB_USERNAME"),
		Password: viper.GetString("DB_PASSWORD"),
		DBName:   viper.GetString("DB_NAME"),
		SSLMode:  viper.GetString("DB_SSL_MODE"),
	})
	if connectDbErr != nil {
		log.Fatal("can't initialize db instance:", connectDbErr)
	}

	authRepo := repository.NewAuthRepository(db)
	passwordHasher := hashser.NewBcryptHasher(bcrypt.DefaultCost)
	authService := service.NewAuthService(authRepo, passwordHasher)
	authServer := server.NewAuthServer(authService)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	auth.RegisterAuthServer(grpcServer, authServer)

	runSrvErr := grpcutils.RunAndShutdownServer(serverCfg, grpcServer)
	if runSrvErr != nil {
		log.Fatal("run server error:", runSrvErr)
	}
}
