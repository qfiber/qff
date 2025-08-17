# Makefile

# Variables
VERSION := 1.0.0
BUILD_DIR := build
QFF_ENGINE_BIN := $(BUILD_DIR)/qff-engine
QFF_CLI_BIN := $(BUILD_DIR)/qff

# Go build flags
GO := go
GO_FLAGS := -trimpath -mod=readonly
LDFLAGS := "-X main.Version=$(VERSION) -s -w"

.PHONY: all build clean install uninstall

all: build

build: $(QFF_ENGINE_BIN) $(QFF_CLI_BIN)

$(QFF_ENGINE_BIN):
	@echo "#######################################"
	@echo "#                                     #"
	@echo "#    QFF - qFiber Firewall Manager    #"
	@echo "#                                     #"
	@echo "#######################################"
	@echo "Building qff-engine..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.Version=1.0.0 -s -w" -o build/qff-engine ./cmd/qff-engine

$(QFF_CLI_BIN):
	@echo "Building qff (CLI)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GO_FLAGS) -ldflags $(LDFLAGS) -o $(QFF_CLI_BIN) ./cmd/qff

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)

install:
	@echo "Installing qff binaries and configuration..."
	sudo cp build/$(BINARY_ENGINE_NAME) /usr/local/bin/
	sudo cp build/$(BINARY_CLI_NAME) /usr/local/bin/qff-cli
	sudo mkdir -p /etc/qff
	sudo cp -n configs/qff.conf /etc/qff/
	sudo cp -n configs/cli.conf /etc/qff/
	@echo "Installing systemd service..."
	sudo cp systemd/qff.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Install complete."
	@echo " "
	@echo " "
	@echo "|-> Before you start the software, make sure to"
	@echo "|-> edit the config file to allow access to the server"
	@echo "|-> Failing to edit the file might make your connection drop"
	@echo " "
	@echo " "
	@echo "|-> To enable and start the service, run:"
	@echo "|-> sudo systemctl enable --now qff.service"

uninstall:
	@echo "Uninstalling..."
	@sudo systemctl stop qff.service
	@sudo systemctl disable qff.service
	@sudo rm -f /usr/local/bin/qff-engine
	@sudo rm -f /usr/local/bin/qff
	@sudo rm -f /etc/systemd/system/qff.service
	@sudo rm -rf /etc/qff
	@sudo systemctl daemon-reload