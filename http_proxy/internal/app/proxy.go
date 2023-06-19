package app

import (
	"context"
	"fmt"
	gw "github.com/DmitySH/go-http-proxy/gateway/auth"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"net"
	"net/http"
)

const (
	swaggerFilePath = "swagger-ui/swagger.json"
	swaggerUIPath   = "swagger-ui"
)

func Run() {
	srvAddr := fmt.Sprintf("%s:%d", viper.GetString("SERVER_HOST"), viper.GetInt("SERVER_PORT"))
	httpListener, listenErr := net.Listen("tcp", srvAddr)
	if listenErr != nil {
		log.Fatalln("failed to listen:", listenErr)
	}
	defer httpListener.Close()

	gwMux := runtime.NewServeMux()
	grpcEndpointAddr := fmt.Sprintf("%s:%d", viper.GetString("ENDPOINT_HOST"), viper.GetInt("ENDPOINT_PORT"))
	ctx := context.Background()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if regErr := gw.RegisterAuthHandlerFromEndpoint(ctx, gwMux, grpcEndpointAddr, opts); regErr != nil {
		log.Fatalln("failed to register handler for grpc endpoint:", regErr)
	}

	httpMux := http.NewServeMux()
	httpMux.Handle("/", gwMux)
	httpMux.HandleFunc("/docs/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, swaggerFilePath)
	})
	httpMux.Handle("/docs/", http.StripPrefix("/docs/", http.FileServer(http.Dir(swaggerUIPath))))

	if serveErr := http.Serve(httpListener, httpMux); serveErr != nil {
		log.Fatalln(serveErr)
	}
}
