.PHONY: help dev build frontend-build frontend-embed test test-go test-e2e lint vet clean migrate sqlc docker-up docker-down

LOCAL_COMPOSE := docker compose -f docker-compose.yml -f docker-compose.local-minio.yml

help:
	@echo "Hash - common commands"
	@echo "  make dev           start the opt-in local postgres+minio stack, run server"
	@echo "  make build         build server + worker with embedded frontend"
	@echo "  make test          run all tests (Go unit + Playwright e2e)"
	@echo "  make test-go       run Go unit tests only"
	@echo "  make test-e2e      run Playwright e2e tests only"
	@echo "  make lint          go vet + svelte-check"
	@echo "  make vet           go vet ./..."
	@echo "  make sqlc          regenerate sqlc Go from queries"
	@echo "  make migrate       run goose migrations against HASH_DB_URL"
	@echo "  make docker-up     start hash with the opt-in bundled local MinIO"
	@echo "  make docker-down   stop and remove containers"
	@echo "  make clean         remove build artifacts"

dev:
	$(LOCAL_COMPOSE) up -d postgres minio
	go run ./cmd/server

frontend-build:
	cd frontend && bun install --frozen-lockfile && bun run build

frontend-embed:
	test -f frontend/build/index.html
	test ! -L cmd/server/frontend/build
	mkdir -p cmd/server/frontend/build
	for name in .gitignore .gitkeep README.md; do test ! -e "frontend/build/$$name" && test ! -L "frontend/build/$$name" || exit 1; done
	find cmd/server/frontend/build -mindepth 1 -maxdepth 1 ! -name .gitignore ! -name .gitkeep ! -name README.md -exec rm -rf -- {} +
	cp -R frontend/build/. cmd/server/frontend/build/

build: frontend-build
	mkdir -p bin
	$(MAKE) frontend-embed
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/server ./cmd/server
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/worker ./cmd/worker

test: test-go test-e2e

test-go:
	go test ./... -race -count=1 -timeout 60s

test-e2e:
	cd e2e && bun install --frozen-lockfile && bunx playwright test

lint:
	go vet ./...
	cd frontend && bun run check

vet:
	go vet ./...

sqlc:
	bash scripts/generate-sqlc.sh

migrate:
	goose -dir internal/db/migrations postgres "$$HASH_DB_URL" up

docker-up:
	$(LOCAL_COMPOSE) up -d --build

docker-down:
	$(LOCAL_COMPOSE) down

clean:
	rm -rf bin frontend/build frontend/.svelte-kit
