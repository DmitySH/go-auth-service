package main

import (
	"github.com/DmitySH/go-http-proxy/config"
	"github.com/DmitySH/go-http-proxy/internal/app"
)

const cfgPath = "config/app.env"

func main() {
	config.LoadEnvConfig(cfgPath)
	app.Run()
}
