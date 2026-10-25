# Common tasks. `make help` lists them.
SHELL := /bin/sh

PODMAN    ?= podman
IMAGE     ?= localhost/trivy-scanner
NAME      ?= trivy-scanner
PORT      ?= 8080
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Rootless podman API socket; XDG_RUNTIME_DIR is unset in some non-login ssh sessions.
RUNTIME   := $(or $(XDG_RUNTIME_DIR),/run/user/$(shell id -u))
# CACHE: directory on the server (the podman host) that holds Trivy's cache; overridable.
CACHE     ?= /tmp/trivy
SOCKET    ?= $(RUNTIME)/podman/podman.sock

.DEFAULT_GOAL := help
.PHONY: help test check fmt vet frontend bindings dev dev-frontend build build-server run demo screenshots \
        headless headless-socket headless-image headless-up headless-down headless-update \
        headless-logs headless-status headless-tunnel

help: ## List the targets
	@awk -F':.*## ' '/^[a-zA-Z_-]+:.*## /{printf "  %-17s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Development -------------------------------------------------------------

test: ## Run the tests as CI does (fixtures, no podman needed)
	go test -race -count=1 ./...

fmt: ## Format the Go code
	gofmt -w .

vet: ## go vet, with and without the production tag
	go vet ./...
	go vet -tags production ./...

check: ## Everything CI checks that runs without GTK: gofmt, tidy, vet, tests, headless build
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "needs gofmt:"; echo "$$unformatted"; exit 1; fi
	go mod tidy -diff
	$(MAKE) vet test build-server

frontend: ## Build the Vue app into frontend/dist (embedded by the Go binary)
	cd frontend && npm ci --ignore-scripts --no-audit --no-fund && npm run build

bindings: ## Regenerate frontend/bindings from the Go services (needs the wails3 CLI)
	CGO_ENABLED=0 wails3 generate bindings -silent

dev: ## Hot reload: Vite HMR + rebuild-on-save Go server (http://localhost:8080)
	scripts/dev.sh

dev-frontend: ## Vite dev server with hot reload; then run: FRONTEND_DEVSERVER_URL=http://127.0.0.1:9245 go run .
	cd frontend && npm run dev

build: frontend ## Desktop release build (needs GTK4 + WebKitGTK 6)
	go build -tags production -trimpath -ldflags "-w -s -X main.version=$(VERSION)" -o trivy-scanner .

build-server: frontend ## Headless server build, no GTK needed
	CGO_ENABLED=0 go build -tags server,production -trimpath -ldflags "-w -s -X main.version=$(VERSION)" -o trivy-scanner .

run: frontend ## Run the desktop app with real podman
	go run .

demo: frontend ## Run the desktop app on recorded data (dev build only)
	TRIVY_SCANNER_FAKE_PODMAN=1 go run .

screenshots: ## Regenerate docs/screenshots (needs Node and Playwright)
	scripts/screenshots.sh

## Headless server in podman (no Go on the host; see docs/headless.md) ------

headless: headless-socket headless-up headless-tunnel ## Build, start, and print the ssh tunnel command

headless-socket: ## Enable the rootless podman API socket the app drives
	systemctl --user enable --now podman.socket

headless-image: ## Build the image
	$(PODMAN) build -t $(IMAGE) --build-arg VERSION=$(VERSION) -f Containerfile .

headless-up: headless-image ## (Re)create and start the container, listening on 127.0.0.1:$(PORT)
	-$(PODMAN) rm -f $(NAME)
	mkdir -p $(CACHE)
	$(PODMAN) run -d --name $(NAME) --restart unless-stopped \
		--network host --security-opt label=disable \
		-e WAILS_SERVER_PORT=$(PORT) \
		-e TRIVY_SCANNER_CACHE=$(CACHE) \
		-v "$(SOCKET):/run/podman/podman.sock" \
		-v $(NAME)-data:/data \
		$(IMAGE)

headless-down: ## Stop and remove the container (the data volume stays)
	$(PODMAN) rm -f $(NAME)

headless-update: ## git pull origin main, then rebuild and restart
	git pull origin main
	$(MAKE) headless-up

headless-logs: ## Follow the container logs
	$(PODMAN) logs -f $(NAME)

headless-status: ## Show the container and whether it answers on localhost
	@$(PODMAN) ps --filter name=^$(NAME)$$ --format '{{.Names}}\t{{.Status}}'
	@curl -s -o /dev/null -w 'http://localhost:$(PORT)/ -> %{http_code}\n' http://localhost:$(PORT)/ || true

headless-tunnel: ## Print the command to run on YOUR machine to reach it
	@echo "On your machine:  ssh -L $(PORT):localhost:$(PORT) $$(id -un)@$$(hostname -f 2>/dev/null || hostname)"
	@echo "Then open:        http://localhost:$(PORT)"
