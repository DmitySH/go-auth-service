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

.PHONY:migration
migration:
	echo "Use: migrate create -ext sql -dir db/migration -seq <MIGRATION_NAME>"

.PHONY: migrate-up
migrate-up:
	migrate -path db/migration -database "postgresql://dmity:Jq5eL2eH2mF@localhost:5440/auth-stg?sslmode=disable" -verbose up

.PHONY: migrate-down
migrate-down:
	migrate -path db/migration -database "postgresql://dmity:Jq5eL2eH2mF@localhost:5440/auth-stg?sslmode=disable" -verbose down
