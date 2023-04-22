.PHONY: proto
gen-proto:
	protoc --go_out=. --go_opt=paths=source_relative \
        --go-grpc_out=. --go-grpc_opt=paths=source_relative \
        api/auth/auth.proto

.PHONY: run
run:
	go run cmd/auth/main.go

.PHONY: up
up:
	docker-compose up --build