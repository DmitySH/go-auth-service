package main

import (
	"github.com/DmitySH/go-auth-service/internal/auth"
	"github.com/DmitySH/go-auth-service/pkg/config"
)

const cfgPath = "configs/app.env"

func main() {
	config.LoadEnvConfig(cfgPath)
	auth.Run()
}
