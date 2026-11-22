.PHONY: build run test cover cover-html lint clean migrate-up migrate-down

# Override at command line, e.g.
#   NANB_PG_CONN=postgres://user:pass@localhost:5432/db?sslmode=disable make migrate-up
NANB_PG_CONN ?= postgres://nanbchatapp:password@localhost:5432/nanb_chat_app?sslmode=disable

build:
	go build -o bin/nanb-server ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

cover:
	go test -coverpkg=./internal/identity/...,./internal/crypto/...,./internal/auth/...,./internal/delivery/...,./internal/media/...,./internal/push/...,./internal/retention/... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

cover-html: cover
	go tool cover -html=coverage.out -o coverage.html

lint:
	go vet ./...

clean:
	rm -rf bin/ coverage.out coverage.html

migrate-up:
	migrate -path migrations -database "$(NANB_PG_CONN)" up

migrate-down:
	migrate -path migrations -database "$(NANB_PG_CONN)" down 1
