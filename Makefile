.PHONY: dev-up dev-down migrate migrate-down test lint build seed

dev-up:
	docker compose -f deploy/docker-compose.yml up -d postgres redis

dev-down:
	docker compose -f deploy/docker-compose.yml down

migrate:
	migrate -path migrations -database "$$(grep DATABASE_URL .env | cut -d= -f2)" up

migrate-down:
	migrate -path migrations -database "$$(grep DATABASE_URL .env | cut -d= -f2)" down 1

test:
	go test ./...

lint:
	go vet ./...

build:
	go build -o bin/api ./cmd/api && go build -o bin/worker ./cmd/worker

seed:
	go run ./cmd/devtools/seed