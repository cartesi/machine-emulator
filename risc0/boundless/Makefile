# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Required (from environment or .env)
PINATA_JWT              ?=
BOUNDLESS_WALLET_KEY    ?=

# Ethereum RPC
ETH_RPC_URL       ?= https://ethereum-sepolia-rpc.publicnode.com

# Step log
STEP_LOG_MCYCLES        ?= 100

# IPFS
IPFS_GATEWAY            ?= https://gateway.pinata.cloud/ipfs

# Pricing (reverse Dutch auction)
MIN_PRICE_ETH           ?= 0.001
MAX_PRICE_ETH           ?= 0.01
TIMEOUT                 ?= 3600
RAMP_UP_PERIOD          ?= 300

# Lua
LUA_BIN                 ?= lua5.4
LUA                     ?= $(LUA_BIN)
CARTESI_MACHINE         ?= cartesi-machine.lua

# Paths
BUILD_DIR               := $(abspath build)
RISC0_DIR               := $(abspath ..)
STEP_LOG_UTIL           := $(RISC0_DIR)/step-log-util.lua
ARTIFACTS_DIR           := $(RISC0_DIR)/artifacts
GUEST_BIN               := $(ARTIFACTS_DIR)/cartesi-risc0-guest-step-prover.bin
IMAGE_ID_FILE           := $(ARTIFACTS_DIR)/cartesi-risc0-guest-step-prover-image-id.txt
STEP_LOG                := $(BUILD_DIR)/step.log
TEMPLATE                := $(abspath request.yaml.template)

.PHONY: all prove check-env step-log artifacts upload-guest upload-input \
        request submit check-balance clean help

help:
	@echo "Boundless Workflow Automation"
	@echo ""
	@echo "Full pipeline:"
	@echo "  make prove              Run entire workflow (step-log -> upload -> submit)"
	@echo ""
	@echo "Individual targets:"
	@echo "  make check-env          Validate required environment variables"
	@echo "  make step-log           Generate step log (STEP_LOG_MCYCLES=$(STEP_LOG_MCYCLES))"
	@echo "  make artifacts          Build RISC0 guest ELF and Image ID"
	@echo "  make upload-guest       Upload guest binary to IPFS via Pinata"
	@echo "  make upload-input       Wrap step log in GuestEnv format and upload"
	@echo "  make request            Generate request.yaml from template"
	@echo "  make submit             Submit proof request to Boundless"
	@echo "  make check-balance      Check wallet Sepolia ETH balance"
	@echo "  make clean              Remove build directory"
	@echo ""
	@echo "Configuration (override via env vars or make args):"
	@echo "  STEP_LOG_MCYCLES=$(STEP_LOG_MCYCLES)"
	@echo "  MIN_PRICE_ETH=$(MIN_PRICE_ETH)"
	@echo "  MAX_PRICE_ETH=$(MAX_PRICE_ETH)"
	@echo "  TIMEOUT=$(TIMEOUT)"
	@echo "  ETH_RPC_URL=$(ETH_RPC_URL)"


prove: check-env step-log artifacts upload-guest upload-input request submit


check-env:
	@if [ -z "$(PINATA_JWT)" ]; then \
		echo "Error: PINATA_JWT is not set"; \
		exit 1; \
	fi
	@if [ -z "$(BOUNDLESS_WALLET_KEY)" ]; then \
		echo "Error: BOUNDLESS_WALLET_KEY is not set"; \
		exit 1; \
	fi
	@for cmd in curl jq boundless $(LUA_BIN); do \
		if ! command -v $$cmd > /dev/null 2>&1; then \
			echo "Error: '$$cmd' not found in PATH"; \
			exit 1; \
		fi; \
	done
	@echo "Environment OK"

step-log: $(STEP_LOG)

$(STEP_LOG):
	@mkdir -p $(BUILD_DIR)
	$(CARTESI_MACHINE) \
		--hash-tree=hash_function:sha256 \
		--max-mcycle=0 \
		--log-step=$(STEP_LOG_MCYCLES),$(STEP_LOG)
	@echo "Step log: $(STEP_LOG) ($$(stat -f%z "$(STEP_LOG)" 2>/dev/null || stat -c%s "$(STEP_LOG)" 2>/dev/null) bytes)"

artifacts: $(IMAGE_ID_FILE)

$(IMAGE_ID_FILE):
	$(MAKE) -C $(RISC0_DIR) export-artifacts
	@echo "Image ID: $$(cat $(IMAGE_ID_FILE))"


upload-guest: $(BUILD_DIR)/guest-cid.txt

$(BUILD_DIR)/guest-cid.txt: $(GUEST_BIN)
	@mkdir -p $(BUILD_DIR)
	@echo "Uploading guest binary to IPFS..."
	@RESPONSE=$$(curl -s -X POST "https://api.pinata.cloud/pinning/pinFileToIPFS" \
		-H "Authorization: Bearer $(PINATA_JWT)" \
		-F "file=@$(GUEST_BIN);filename=cartesi-risc0-guest-step-prover.bin"); \
	CID=$$(echo "$$RESPONSE" | jq -r '.IpfsHash // empty'); \
	if [ -z "$$CID" ]; then \
		echo "Upload failed:"; \
		echo "$$RESPONSE" | jq .; \
		exit 1; \
	fi; \
	echo "$$CID" > $(BUILD_DIR)/guest-cid.txt; \
	echo "Guest CID: $$CID"; \
	echo "Guest URL: $(IPFS_GATEWAY)/$$CID"

upload-input: $(BUILD_DIR)/input-cid.txt

$(BUILD_DIR)/input-cid.txt: $(STEP_LOG)
	@mkdir -p $(BUILD_DIR)
	@echo "Wrapping step log in GuestEnv V0 format..."
	@printf '\x00' > $(BUILD_DIR)/step-guestenv.bin
	@cat $(STEP_LOG) >> $(BUILD_DIR)/step-guestenv.bin
	@echo "GuestEnv file: $$(stat -f%z "$(BUILD_DIR)/step-guestenv.bin" 2>/dev/null || stat -c%s "$(BUILD_DIR)/step-guestenv.bin" 2>/dev/null) bytes"
	@echo "Uploading to IPFS..."
	@RESPONSE=$$(curl -s -X POST "https://api.pinata.cloud/pinning/pinFileToIPFS" \
		-H "Authorization: Bearer $(PINATA_JWT)" \
		-F "file=@$(BUILD_DIR)/step-guestenv.bin;filename=cartesi-step-log-$(STEP_LOG_MCYCLES)mcycles.bin"); \
	CID=$$(echo "$$RESPONSE" | jq -r '.IpfsHash // empty'); \
	if [ -z "$$CID" ]; then \
		echo "Upload failed:"; \
		echo "$$RESPONSE" | jq .; \
		exit 1; \
	fi; \
	echo "$$CID" > $(BUILD_DIR)/input-cid.txt; \
	echo "Input CID: $$CID"; \
	echo "Input URL: $(IPFS_GATEWAY)/$$CID"

request: $(BUILD_DIR)/request.yaml

$(BUILD_DIR)/request.yaml: $(BUILD_DIR)/guest-cid.txt $(BUILD_DIR)/input-cid.txt $(IMAGE_ID_FILE) $(TEMPLATE)
	@echo "Generating request.yaml..."
	@IMAGE_ID=$$(cat $(IMAGE_ID_FILE)); \
	GUEST_CID=$$(cat $(BUILD_DIR)/guest-cid.txt); \
	INPUT_CID=$$(cat $(BUILD_DIR)/input-cid.txt); \
	GUEST_URL="$(IPFS_GATEWAY)/$$GUEST_CID"; \
	INPUT_URL="$(IPFS_GATEWAY)/$$INPUT_CID"; \
	INPUT_URL_HEX=$$($(LUA) $(STEP_LOG_UTIL) hex-encode "$$INPUT_URL"); \
	MIN_WEI=$$($(LUA) -e "print(string.format('%.0f', $(MIN_PRICE_ETH) * 1e18))"); \
	MAX_WEI=$$($(LUA) -e "print(string.format('%.0f', $(MAX_PRICE_ETH) * 1e18))"); \
	sed \
		-e "s|__IMAGE_ID__|$$IMAGE_ID|g" \
		-e "s|__GUEST_IPFS_URL__|$$GUEST_URL|g" \
		-e "s|__INPUT_URL_HEX__|$$INPUT_URL_HEX|g" \
		-e "s|__MIN_PRICE_WEI__|$$MIN_WEI|g" \
		-e "s|__MAX_PRICE_WEI__|$$MAX_WEI|g" \
		-e "s|__TIMEOUT__|$(TIMEOUT)|g" \
		-e "s|__RAMP_UP_PERIOD__|$(RAMP_UP_PERIOD)|g" \
		$(TEMPLATE) > $(BUILD_DIR)/request.yaml; \
	echo "Request written to $(BUILD_DIR)/request.yaml"; \
	echo "  Image ID:  $$IMAGE_ID"; \
	echo "  Guest URL: $$GUEST_URL"; \
	echo "  Input URL: $$INPUT_URL"; \
	echo "  Price:     $(MIN_PRICE_ETH) - $(MAX_PRICE_ETH) ETH"; \
	echo "  Timeout:   $(TIMEOUT)s"

submit: $(BUILD_DIR)/request.yaml
	@echo "Submitting proof request to Boundless..."
	@echo "This may take several minutes depending on proof complexity."
	@echo ""
	@START=$$(date +%s); \
	if boundless requestor submit-file \
		--no-preflight --wait \
		$(BUILD_DIR)/request.yaml 2>&1 | tee $(BUILD_DIR)/submit-result.txt; then \
		END=$$(date +%s); \
		ELAPSED=$$((END - START)); \
		echo ""; \
		echo "Proof fulfilled in $${ELAPSED}s (~$$((ELAPSED / 60))m $$((ELAPSED % 60))s)"; \
		REQUEST_ID=$$(grep -oE '0x[0-9a-fA-F]{48}' $(BUILD_DIR)/submit-result.txt | head -1); \
		if [ -n "$$REQUEST_ID" ]; then \
			echo "Request ID: $$REQUEST_ID"; \
			echo "$$REQUEST_ID" > $(BUILD_DIR)/request-id.txt; \
		fi; \
	else \
		echo ""; \
		echo "Proof request failed. See $(BUILD_DIR)/submit-result.txt"; \
		exit 1; \
	fi

check-balance:
	@if ! command -v cast > /dev/null 2>&1; then \
		echo "Error: 'cast' (Foundry) not found. Install from https://getfoundry.sh"; \
		exit 1; \
	fi
	@if [ -z "$(BOUNDLESS_WALLET_KEY)" ]; then \
		echo "Error: BOUNDLESS_WALLET_KEY not set"; \
		exit 1; \
	fi
	@ADDR=$$(cast wallet address "$(BOUNDLESS_WALLET_KEY)"); \
	echo "Wallet: $$ADDR"; \
	BALANCE_WEI=$$(cast balance "$$ADDR" --rpc-url "$(ETH_RPC_URL)"); \
	BALANCE_ETH=$$(cast from-wei "$$BALANCE_WEI" ether 2>/dev/null || echo "$$BALANCE_WEI wei"); \
	echo "Balance: $$BALANCE_ETH ETH"; \
	if [ "$$BALANCE_WEI" = "0" ]; then \
		echo ""; \
		echo "Wallet has no Sepolia ETH. Get some from:"; \
		echo "  https://faucets.chain.link/sepolia"; \
		echo "  https://www.alchemy.com/faucets/ethereum-sepolia"; \
	fi

clean:
	rm -rf $(BUILD_DIR)
