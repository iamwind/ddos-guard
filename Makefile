.PHONY: build test clean run

APP_NAME = ddosguard
BUILD_DIR = build

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/ddosguard/

test:
	go test ./...

clean:
	@rm -rf $(BUILD_DIR)

run: build
	./$(BUILD_DIR)/$(APP_NAME) -config config.yaml

deps:
	go mod tidy
	go mod download
