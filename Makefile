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
# Build tags for the production vet; the dev container (no GTK) sets this to server,production.
VET_TAGS  ?= production
# -race needs cgo, which pulls in GTK; the dev container sets RACE to empty.
RACE      ?= -race
SOCKET    ?= $(RUNTIME)/podman/podman.sock
# OUT: where `make build` and `make build-server` write the binary.
OUT       ?= trivy-scanner

.DEFAULT_GOAL := help
.PHONY: help test check fmt fmt-check mod-check lint lint-go lint-frontend govulncheck tools format-frontend audit-frontend vet frontend bindings wails3-install dev dev-frontend build build-server run run-mcp run-mcp-server demo screenshots lighthouse \
        headless headless-socket headless-image headless-up headless-down headless-update \
        headless-logs headless-status headless-tunnel

help: ## List the targets
	@awk -F':.*## ' '/^[a-zA-Z_-]+:.*## /{printf "  %-17s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Development -------------------------------------------------------------

test: ## Run the tests as CI does (fixtures, no podman needed)
	go test $(RACE) -count=1 ./...

fmt: ## Format the Go code
	gofmt -w .

fmt-check: ## Fail if any Go file needs gofmt
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "These files need gofmt:"; echo "$$unformatted"; exit 1; fi

# Dev tool versions. Renovate keeps them current through the `# renovate:` comments (renovate.json5).
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2
GOLANGCI_LINT_VERSION := v2.15.0
# renovate: datasource=go depName=golang.org/x/vuln
GOVULNCHECK_VERSION := v1.9.0
# renovate: datasource=go depName=golang.org/x/tools
GOIMPORTS_VERSION := v0.52.0
# renovate: datasource=npm depName=lighthouse
LIGHTHOUSE_VERSION := 13.6.0

mod-check: ## Fail if go.mod/go.sum are not tidy, then verify the modules
	go mod tidy -diff
	go mod verify

lint: lint-go lint-frontend ## golangci-lint plus the frontend's Biome lint and format check (as CI runs them)

lint-go: ## golangci-lint on the server-tag build (CGO off, no GTK needed)
	CGO_ENABLED=0 go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --build-tags server ./...

govulncheck: ## govulncheck on the whole module (the GUI package needs the GTK headers to type-check)
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

tools: ## Install goimports, golangci-lint and govulncheck into GOBIN (for editors)
	go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

lint-frontend: ## Biome lint, format check and knip (unused exports and dependencies) for the Vue app (needs `make frontend` once for node_modules)
	cd frontend && npm run lint && npm run format:check && npm run knip

format-frontend: ## Reformat the Vue app with Biome
	cd frontend && npm run format

audit-frontend: ## npm audit of the runtime dependencies (HIGH and above fails)
	cd frontend && npm audit --omit=dev --audit-level=high

vet: ## go vet, with and without the production tag
	go vet ./...
	go vet -tags $(VET_TAGS) ./...

check: ## Everything CI checks that runs without GTK: gofmt, tidy, vet, tests, headless build
	$(MAKE) fmt-check
	go mod tidy -diff
	$(MAKE) vet test build-server

frontend: ## Build the Vue app into frontend/dist (embedded by the Go binary)
	cd frontend && npm ci --ignore-scripts --no-audit --no-fund && npm run build

wails3-install: ## Install the wails3 CLI at the go.mod version into GOBIN (default: $$(go env GOPATH)/bin)
	CGO_ENABLED=0 go install -tags server github.com/wailsapp/wails/v3/cmd/wails3@$$(go list -m -f '{{.Version}}' github.com/wailsapp/wails/v3)

bindings: ## Regenerate frontend/bindings from the Go services (needs the wails3 CLI)
	CGO_ENABLED=0 wails3 generate bindings -silent

dev: ## Hot reload via `wails3 dev` in server mode: Vite HMR + rebuild-on-save Go (http://localhost:8080)
	scripts/dev.sh

dev-frontend: ## Vite dev server with hot reload; then run: FRONTEND_DEVSERVER_URL=http://127.0.0.1:9245 go run .
	cd frontend && npm run dev

build: frontend ## Desktop release build (needs GTK4 + WebKitGTK 6)
	go build -tags production -trimpath -buildvcs=false -ldflags "-w -s -X github.com/cthtrifork/trivy-dashboard-wail3/internal/app.version=$(VERSION)" -o $(OUT) .

build-server: frontend ## Headless server build, no GTK needed
	CGO_ENABLED=0 go build -tags server,production -trimpath -buildvcs=false -ldflags "-w -s -X github.com/cthtrifork/trivy-dashboard-wail3/internal/app.version=$(VERSION)" -o $(OUT) .

run: frontend ## Run the desktop app with real podman
	go run .

run-mcp: frontend ## Desktop app with Wails' MCP server on 127.0.0.1:9099 (dev only; see docs/mcp.md)
	go run -tags mcp .

run-mcp-server: frontend ## Headless app with the MCP server; only app_info, windows_list, emit_event work (no webview)
	CGO_ENABLED=0 go run -tags server,mcp .

demo: frontend ## Run the desktop app on recorded data (dev build only)
	TRIVY_SCANNER_FAKE_PODMAN=1 go run .

screenshots: ## Regenerate docs/screenshots (needs Node and Playwright)
	scripts/screenshots.sh

lighthouse: ## Lighthouse scores for the UI, written to ./lighthouse (needs Node and Chrome; CHROME_PATH)
	LIGHTHOUSE_VERSION=$(LIGHTHOUSE_VERSION) scripts/lighthouse.sh

## Headless server in podman (no Go on the host; see docs/headless.md) ------

headless: headless-socket headless-up headless-tunnel ## Build, start, and print the ssh tunnel command

headless-socket: ## Enable the rootless podman API socket the app drives
	systemctl --user enable --now podman.socket

headless-image: ## Build the image
	$(PODMAN) build -t $(IMAGE) --build-arg VERSION=$(VERSION) -f build/docker/headless.Dockerfile .

headless-up: headless-image ## (Re)create and start the container, listening on 127.0.0.1:$(PORT)
	-$(PODMAN) rm -f $(NAME)
	mkdir -p $(CACHE)
	$(PODMAN) run -d --name $(NAME) --restart unless-stopped \
		--network host --security-opt label=disable --userns=keep-id \
		-e WAILS_SERVER_PORT=$(PORT) \
		-e TRIVY_SCANNER_CACHE=$(CACHE) \
		$(if $(GITHUB_TOKEN),-e GITHUB_TOKEN -e GITHUB_ACTOR -e GITHUB_USER) \
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
