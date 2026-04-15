APP_NAME = topsrv
BUILD_DIR = bin
export GOEXPERIMENT = jsonv2
export CGO_ENABLED = 0

.PHONY: build run test test-integration fmt lint clean init demo demo-stop

build:
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME) -config cfg/local.toml -verbose

test:
	go test ./...

test-integration:
	docker compose -f docker-compose.test.yml up -d --wait
	go test -tags=integration -count=1 -v ./internal/topsrv/...
	docker compose -f docker-compose.test.yml down

fmt:
	@golangci-lint fmt

lint:
	@golangci-lint version
	@golangci-lint run

clean:
	rm -rf $(BUILD_DIR)

init:
	@test -f cfg/local.toml || cp cfg/local.toml.dist cfg/local.toml

demo: build demo-stop
	@echo "Starting VictoriaMetrics on :8428..."
	@victoria-metrics -httpListenAddr=:8428 -storageDataPath=/tmp/topsrv-vm-data \
		-retentionPeriod=1d > /tmp/topsrv-vm.log 2>&1 &
	@sleep 2
	@echo "Starting topsrv on :9100 with push to VM..."
	@$(BUILD_DIR)/$(APP_NAME) -config cfg/demo.toml -verbose > /tmp/topsrv-demo.log 2>&1 &
	@sleep 2
	@echo ""
	@echo "=== topsrv demo ==="
	@echo "  Metrics:   http://localhost:9100/metrics"
	@echo "  VM UI:     http://localhost:8428/vmui"
	@echo "  Dashboard: open docs/dashboard/common.html in browser"
	@echo ""
	@echo "  Stop: make demo-stop"

demo-stop:
	@-pkill -f "bin/topsrv.*demo" 2>/dev/null
	@-pkill -f "victoria-metrics.*topsrv-vm-data" 2>/dev/null
	@echo "demo stopped"
