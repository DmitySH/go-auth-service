package main

import (
	"github.com/DmitySH/go-auth-service/config"
	"github.com/DmitySH/go-auth-service/internal/app"
)

const cfgPath = "config/app.env"

func main() {
	config.LoadEnvConfig(cfgPath)
	app.Run()
}
