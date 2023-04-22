package grpcutils

import (
	"fmt"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type GRPCServerConfig struct {
	Host string
	Port int
}

func RunAndShutdownServer(serverCfg GRPCServerConfig, grpcServer *grpc.Server) error {
	listener, listenErr := net.Listen("tcp",
		fmt.Sprintf("%s:%d", serverCfg.Host, serverCfg.Port))
	if listenErr != nil {
		return fmt.Errorf("can't listen: %w", listenErr)
	}
	defer listener.Close()

	log.Printf("starting server on %s:%d\n", serverCfg.Host, serverCfg.Port)

	stopChan := make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stopChan
		log.Println("shutting down server")
		grpcServer.Stop()
	}()

	if serveErr := grpcServer.Serve(listener); serveErr != nil {
		return fmt.Errorf("serving error: %w", serveErr)
	}
	log.Println("server stopped")

	return nil
}
