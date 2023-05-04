package auth

import (
	"github.com/DmitySH/go-auth-service/internal/hashser"
	"github.com/DmitySH/go-auth-service/internal/middleware"
	"github.com/DmitySH/go-auth-service/internal/repository"
	"github.com/DmitySH/go-auth-service/internal/server"
	"github.com/DmitySH/go-auth-service/internal/service"
	"github.com/DmitySH/go-auth-service/internal/tokengen"
	"github.com/DmitySH/go-auth-service/pkg/api/auth"
	"github.com/DmitySH/go-auth-service/pkg/grpcutils"
	"github.com/DmitySH/go-auth-service/pkg/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	easy "github.com/t-tomalak/logrus-easy-formatter"
	"google.golang.org/grpc"
	"io"
	defaultlog "log"
	"os"
	"time"
)

const (
	appName = "dmity-auth"
	logPath = "logs/log.log"
)

const day = time.Hour * 24

func Run() {
	logFile, openFileErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if openFileErr != nil {
		defaultlog.Fatalln("can't create/open log file:", openFileErr)
	}
	defer logFile.Close()

	log.SetLogrusLogger(&logrus.Logger{
		Out: io.MultiWriter(os.Stderr, logFile),
		Formatter: &easy.Formatter{
			TimestampFormat: "2006-01-02 15:04:05",
			LogFormat:       "[%lvl%]: %time% - %msg%\n",
		},
		Level: logrus.InfoLevel,
		Hooks: make(map[logrus.Level][]logrus.Hook),
	})

	logger := log.Logger()

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
		defaultlog.Fatalln("can't initialize db instance:", connectDbErr)
	}

	authRepo := repository.NewAuthRepository(db)
	passwordHasher := hashser.NewBcryptHasher(viper.GetInt("BCRYPT_COST"))
	tokenGenerator := tokengen.NewJWTGenerator(
		viper.GetString("JWT_ACCESS_TOKEN_SECRET_KEY"),
		viper.GetString("JWT_REFRESH_TOKEN_SECRET_KEY"),
		appName,
		time.Minute*time.Duration(viper.GetInt("JWT_ACCESS_TOKEN_MINUTES_TTL")),
		day*time.Duration(viper.GetInt("JWT_REFRESH_TOKEN_DAYS_TTL")))

	authService := service.NewAuthService(logger, authRepo, passwordHasher, tokenGenerator,
		time.Minute*time.Duration(viper.GetInt("SESSION_CLEAR_INTERVAL_MINUTES")))
	authServer := server.NewAuthServer(authService)

	var opts = []grpc.ServerOption{
		grpc.UnaryInterceptor(middleware.LogInterceptor),
	}
	grpcServer := grpc.NewServer(opts...)

	auth.RegisterAuthServer(grpcServer, authServer)

	runSrvErr := grpcutils.RunAndShutdownServer(serverCfg, grpcServer)
	if runSrvErr != nil {
		logger.Fatal("run server error:", runSrvErr)
	}
}
