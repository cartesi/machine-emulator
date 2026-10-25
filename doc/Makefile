# Docker image tag — must match the tag used by the root Makefile's
# build-emulator-image target so the docs image layers on top of an
# emulator built from the local source. Locked kernel/rootfs images may require
# emulator features not present in any released base image.
TAG ?= devel

DOCS_IMAGE = cartesi/machine-emulator-docs
PRT_IMAGE = cartesi/machine-emulator-prt

DEPENDENCIES_LOCK ?= $(abspath ../dependencies.lock)
include $(DEPENDENCIES_LOCK)
export MACHINE_GUEST_TOOLS_TAG
export MACHINE_GUEST_TOOLS_DEB_SHA256
export MACHINE_GUEST_TOOLS_TARBALL_SHA256
export LINUX_TAG
export LINUX_VERSION
export LINUX_SHA256

# Docker image platform
BUILD_PLATFORM ?=

ifneq ($(BUILD_PLATFORM),)
DOCKER_PLATFORM=--platform $(BUILD_PLATFORM)
endif

DEV_ENV_HAS_DOCGEN ?= no
RECIPES_DIR ?= $(CURDIR)/recipes
REPLACE_CACHE_DIR := $(RECIPES_DIR)/cache
export RECIPES_DIR REPLACE_CACHE_DIR
export LUA_PATH := $(CURDIR)/?.lua;$(RECIPES_DIR)/?.lua;$(LUA_PATH);;
# Lua 5.4 prefers LUA_PATH_5_4, which make env sets.
ifdef LUA_PATH_5_4
export LUA_PATH_5_4 := $(CURDIR)/?.lua;$(RECIPES_DIR)/?.lua;$(LUA_PATH_5_4)
endif
export PATH := $(RECIPES_DIR):$(PATH)

STYLUA=stylua
STYLUA_FLAGS=--indent-type Spaces --respect-ignores

.PHONY: build-docs-image prepare-readme clean format-lua check-format-lua check-lua test-prt-repeat
.DELETE_ON_ERROR:

# Lua linting/formatting for the recipe snippets and pandoc filters. The
# generated cache (REPLACE_CACHE_DIR) holds extracted block bodies that are
# rewritten on every render, so it is excluded from both tools.
format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) .

check-format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) --check .

check-lua:
	luacheck . --exclude-files '$(REPLACE_CACHE_DIR)/**'

.PHONY: build-prt-image run-prt-bridge
build-prt-image:
	$(MAKE) -C .. uarch-with-toolchain
	$(MAKE) build-docs-image
	docker build $(DOCKER_PLATFORM) --build-context emulator=.. \
		--build-arg TOOLS_BASE=$(DOCS_IMAGE):$(TAG) --target runtime \
		-t $(PRT_IMAGE):$(TAG) -f Dockerfile.prt .

PRT_OUTPUT_DIR ?= $(REPLACE_CACHE_DIR)/prt-chain
PRT_INPUT_CONFIRMATIONS ?= 8
PRT_DISPUTE_CONFIRMATIONS ?= 4
PRT_TEST_REORG ?= no
PRT_TEST_RESTART ?= no
PRT_PROFILE ?= no
PRT_FEE_BUMP_BLOCKS ?= 3
PRT_FEE_BUMP_PERCENT ?= 15
PRT_MAX_FEE_PER_GAS ?= 100000000000
PRT_MAX_PRIORITY_FEE_PER_GAS ?= 10000000000
PRT_OBSERVATION_ENV = -e PRT_INPUT_CONFIRMATIONS=$(PRT_INPUT_CONFIRMATIONS) \
    -e PRT_DISPUTE_CONFIRMATIONS=$(PRT_DISPUTE_CONFIRMATIONS) -e PRT_TEST_REORG=$(PRT_TEST_REORG) -e PRT_TEST_RESTART=$(PRT_TEST_RESTART) \
    -e PRT_PROFILE=$(PRT_PROFILE) \
    -e PRT_FEE_BUMP_BLOCKS=$(PRT_FEE_BUMP_BLOCKS) -e PRT_FEE_BUMP_PERCENT=$(PRT_FEE_BUMP_PERCENT) \
    -e PRT_MAX_FEE_PER_GAS=$(PRT_MAX_FEE_PER_GAS) -e PRT_MAX_PRIORITY_FEE_PER_GAS=$(PRT_MAX_PRIORITY_FEE_PER_GAS)
PRT_HOST_ENV = PRT_INPUT_CONFIRMATIONS=$(PRT_INPUT_CONFIRMATIONS) \
    PRT_DISPUTE_CONFIRMATIONS=$(PRT_DISPUTE_CONFIRMATIONS) PRT_TEST_REORG=$(PRT_TEST_REORG) PRT_TEST_RESTART=$(PRT_TEST_RESTART) \
    PRT_PROFILE=$(PRT_PROFILE) \
    PRT_FEE_BUMP_BLOCKS=$(PRT_FEE_BUMP_BLOCKS) PRT_FEE_BUMP_PERCENT=$(PRT_FEE_BUMP_PERCENT) \
    PRT_MAX_FEE_PER_GAS=$(PRT_MAX_FEE_PER_GAS) PRT_MAX_PRIORITY_FEE_PER_GAS=$(PRT_MAX_PRIORITY_FEE_PER_GAS)
PRT_RPC_PORT ?= 8545
run-prt-bridge:
	mkdir -p "$(PRT_OUTPUT_DIR)"
	docker run --rm $(DOCKER_PLATFORM) --user "$$(id -u):$$(id -g)" \
		$(PRT_OBSERVATION_ENV) \
		-v "$(PRT_OUTPUT_DIR):/work" $(PRT_IMAGE):$(TAG) $(PRT_MODE)

PRT_MODE ?= story
PRT_TEST_COMMAND ?= bash recipes/prt-demo.sh $(PRT_MODE)
.PHONY: test-prt-bridge test-prt-bridge-unit test-prt-transactions test-prt-proofs prt-container-exec
test-prt-bridge-unit: PRT_TEST_COMMAND = lua5.4 recipes/prt-bridge-test.lua
test-prt-bridge-unit: prt-container-exec

test-prt-transactions: PRT_TEST_COMMAND = bash recipes/prt-demo.sh transactions
test-prt-transactions: prt-container-exec

test-prt-proofs: PRT_TEST_COMMAND = bash recipes/prt-demo.sh proofs
test-prt-proofs: prt-container-exec

# The demo. The PRT image plays the chain, and deployment, mining, narration, and every player run
# on the host, whose filesystem has reflinks. The Dave artifacts the host reads are copied from the
# image, once per image id.
test-prt-bridge:
	@set -e; \
	dave="$(REPLACE_CACHE_DIR)/dave-$$(docker image inspect --format '{{.Id}}' $(PRT_IMAGE):$(TAG) | cut -c8-19)"; \
	if [ ! -d "$$dave" ]; then \
	    container=$$(docker create $(DOCKER_PLATFORM) $(PRT_IMAGE):$(TAG)); \
	    mkdir -p "$$dave.tmp/prt/contracts" "$$dave.tmp/cartesi-rollups/contracts"; \
	    docker cp "$$container:/opt/dave/prt/contracts/out" "$$dave.tmp/prt/contracts/"; \
	    docker cp "$$container:/opt/dave/cartesi-rollups/contracts/out" "$$dave.tmp/cartesi-rollups/contracts/"; \
	    docker rm "$$container" > /dev/null; \
	    mv "$$dave.tmp" "$$dave"; \
	fi; \
	chain=$$(docker run -d --rm $(DOCKER_PLATFORM) -p 127.0.0.1:$(PRT_RPC_PORT):8545 -v "$(CURDIR):/work" \
	    --entrypoint bash $(PRT_IMAGE):$(TAG) /work/recipes/prt-demo.sh chain); \
	trap 'docker logs "$$chain" > "$(PRT_OUTPUT_DIR)/anvil.log" 2>&1; docker stop "$$chain" > /dev/null' EXIT; \
	eval "$$($(MAKE) -s -C .. env)"; \
	export LUA_PATH_5_4="$$LUA_PATH_5_4;$$(luarocks --lua-version 5.4 path --lr-path)"; \
	$(PRT_HOST_ENV) MAKE=$(MAKE) RECIPES_DIR=$(RECIPES_DIR) PRT_OUTPUT_DIR=$(PRT_OUTPUT_DIR) \
	    PRT_RPC_URL=http://127.0.0.1:$(PRT_RPC_PORT) PRT_DAVE_DIR="$$dave" \
	    bash $(RECIPES_DIR)/prt-demo.sh $(PRT_MODE)

# Runs PRT_TEST_COMMAND in the PRT image, over the current recipe sources.
prt-container-exec:
	docker run --rm $(DOCKER_PLATFORM) --entrypoint bash --user "$$(id -u):$$(id -g)" \
		$(PRT_OBSERVATION_ENV) \
		-e RECIPES_DIR=/work/recipes -e PRT_OUTPUT_DIR=/work/recipes/cache/prt-chain \
		-e 'LUA_PATH=/work/recipes/?.lua;;' \
		-v "$(DEPENDENCIES_LOCK):/dependencies.lock:ro" \
		-v "$(CURDIR):/work" \
		-v "$(abspath ../src/cartesi/evmu.lua):/usr/local/share/lua/5.4/cartesi/evmu.lua:ro" \
		-w /work $(PRT_IMAGE):$(TAG) -c '$(PRT_TEST_COMMAND)'

ROOTFS_DOCS_INPUTS := \
    $(RECIPES_DIR)/Dockerfile.rootfs-docs \
    $(RECIPES_DIR)/build-rootfs-docs.sh \
    $(RECIPES_DIR)/puppet.c \
    $(wildcard $(RECIPES_DIR)/hello/*)

ROOTFS_DOCS_EXT2 := $(RECIPES_DIR)/rootfs-docs.ext2
ROOTFS_DOCS_KEY := $(RECIPES_DIR)/rootfs-docs.inputs.sha256
ROOTFS_DOCS_INPUTS_HASH := $(shell { \
	cat $(sort $(ROOTFS_DOCS_INPUTS)); \
	printf '%s\n' \
	    '$(MACHINE_GUEST_TOOLS_TAG)' \
	    '$(MACHINE_GUEST_TOOLS_DEB_SHA256)' \
	    '$(MACHINE_GUEST_TOOLS_TARBALL_SHA256)'; \
	} | sha256sum | head -c 64)
ROOTFS_DOCS_INPUTS_TRIGGER := $(RECIPES_DIR)/.rootfs-docs-$(ROOTFS_DOCS_INPUTS_HASH)

# Fingerprint of the recipe inputs. Generated and gitignored, embedded into the
# image at build time and re-derived here to spot a stale committed image
# without rebuilding. Both sides use the same input list so they cannot drift.
$(ROOTFS_DOCS_INPUTS_TRIGGER):
	touch $@

$(ROOTFS_DOCS_KEY): $(ROOTFS_DOCS_INPUTS_TRIGGER)
	printf '%s' '$(ROOTFS_DOCS_INPUTS_HASH)' > $@

# Build the image. build-rootfs-docs.sh embeds $(ROOTFS_DOCS_KEY) into it. The
# generated key is order-only because check-rootfs-docs validates it by content;
# its checkout-time mtime must not make the committed image look stale.
$(ROOTFS_DOCS_EXT2): $(ROOTFS_DOCS_INPUTS) | $(ROOTFS_DOCS_KEY)
	cd $(RECIPES_DIR) && ./build-rootfs-docs.sh

# Content-aware convenience alias, since the real target is an absolute path.
.PHONY: build-rootfs-docs
build-rootfs-docs: ensure-rootfs-docs

# Verify the committed image matches the current recipe inputs. No rebuild and no
# network, so CI runs it after a git lfs pull. A missing or stale image is a hard
# error. e2cp copies the embedded fingerprint out under a -have suffix to compare
# against the freshly derived one.
.PHONY: check-rootfs-docs
check-rootfs-docs: $(ROOTFS_DOCS_KEY)
	@test -s $(ROOTFS_DOCS_EXT2) || { \
	    echo "ERROR: rootfs-docs.ext2 missing, run 'git lfs pull'"; exit 1; }
	@e2cp $(ROOTFS_DOCS_EXT2):/var/log/rootfs-docs.inputs.sha256 $(ROOTFS_DOCS_KEY)-have
	@cmp -s $(ROOTFS_DOCS_KEY) $(ROOTFS_DOCS_KEY)-have || { \
	    echo "ERROR: rootfs-docs.ext2 is stale (recipe inputs changed)."; \
	    echo "Run 'make -C doc build-rootfs-docs' and commit it."; \
	    exit 1; \
	}

ROOTFS_DOCS_LICENSES := $(RECIPES_DIR)/rootfs-docs.licenses.md
ROOTFS_DOCS_LICENSE_INPUTS := \
    $(RECIPES_DIR)/build-rootfs-docs-license.sh \
    $(RECIPES_DIR)/Dockerfile.rootfs-docs \
    $(wildcard $(RECIPES_DIR)/third-party/repo-info/*)

# Package and license report for the committed image. It is derived from the
# ext2 itself rather than from a rebuild, and committed alongside it so a
# checkout carries the license information with the binary.
.PHONY: build-rootfs-docs-license
build-rootfs-docs-license: | ensure-rootfs-docs
	$(MAKE) $(ROOTFS_DOCS_LICENSES)

$(ROOTFS_DOCS_LICENSES): $(ROOTFS_DOCS_EXT2) $(ROOTFS_DOCS_LICENSE_INPUTS)
	cd $(RECIPES_DIR) && ./build-rootfs-docs-license.sh > $(ROOTFS_DOCS_LICENSES)

# Local convenience used before the docs image is built. Fetch the image from
# LFS if absent or still an unsmudged pointer, rebuild it locally if the embedded
# fingerprint no longer matches the recipe inputs.
.PHONY: ensure-rootfs-docs
ensure-rootfs-docs:
	@if [ ! -s $(ROOTFS_DOCS_EXT2) ] || \
	    git lfs pointer --check --file $(ROOTFS_DOCS_EXT2) >/dev/null 2>&1; then \
	    echo "rootfs-docs.ext2 not present, fetching from git lfs..."; \
	    git lfs pull --include "$(ROOTFS_DOCS_EXT2)" || true; \
	fi
	@if $(MAKE) -s check-rootfs-docs >/dev/null 2>&1; then \
	    echo "rootfs-docs.ext2 is up to date."; \
	else \
	    echo "rootfs-docs.ext2 missing or stale, rebuilding locally..."; \
	    rm -f $(ROOTFS_DOCS_EXT2); \
	    $(MAKE) $(ROOTFS_DOCS_EXT2); \
	fi

check-docs-image:
	@if docker images $(DOCKER_PLATFORM) -q $(DOCS_IMAGE):$(TAG) 2>/dev/null | grep -q .; then \
		echo "Docker image $(DOCS_IMAGE):$(TAG) exists"; \
	else \
		echo "Docker image $(DOCS_IMAGE):$(TAG) does not exist. Creating:"; \
		$(MAKE) build-docs-image; \
	fi

docs-image-exec: check-docs-image
	docker run --hostname playground --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-e DOCS_IMAGE_ID=$$(docker image inspect --format '{{.Id}}' $(DOCS_IMAGE):$(TAG)) \
		-e DEPENDENCIES_LOCK=/dependencies.lock \
		-e MACHINE_GUEST_TOOLS_TAG \
		-e MACHINE_GUEST_TOOLS_DEB_SHA256 \
		-e MACHINE_GUEST_TOOLS_TARBALL_SHA256 \
		-e LINUX_TAG \
		-e LINUX_VERSION \
		-e LINUX_SHA256 \
		-v $(CURDIR):/work \
		-v $(DEPENDENCIES_LOCK):/dependencies.lock:ro \
		-w /work \
		$(DOCS_IMAGE):$(TAG) /bin/bash -c "$(CONTAINER_COMMAND)"

run-docs-image: check-docs-image
	docker run \
        --hostname playground \
        --name playground \
        --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-e DOCS_IMAGE_ID=$$(docker image inspect --format '{{.Id}}' $(DOCS_IMAGE):$(TAG)) \
		-e DEPENDENCIES_LOCK=/dependencies.lock \
		-e MACHINE_GUEST_TOOLS_TAG \
		-e MACHINE_GUEST_TOOLS_DEB_SHA256 \
		-e MACHINE_GUEST_TOOLS_TARBALL_SHA256 \
		-e LINUX_TAG \
		-e LINUX_VERSION \
		-e LINUX_SHA256 \
		-v $(CURDIR):/work \
		-v $(DEPENDENCIES_LOCK):/dependencies.lock:ro \
		-w /work \
	    -it \
		$(DOCS_IMAGE):$(TAG) \
	    /bin/bash

build-docs-image: | ensure-rootfs-docs
	@if [ "$(EMULATOR_IMAGE_READY)" != yes ]; then \
		$(MAKE) -C .. build-emulator-image TAG=$(TAG); \
	fi
	base=$$(docker image inspect --format '{{ index .Config.Labels "io.cartesi.machine-emulator.base-image" }}' cartesi/machine-emulator:$(TAG)); \
	docker build $(DOCKER_PLATFORM) \
	    --build-arg TAG=$(TAG) \
	    --build-arg LINUX_URL=$(LINUX_URL) \
	    --build-arg LINUX_SHA256=$(LINUX_SHA256) \
	    $${base:+--build-arg BUILDER_BASE=$$base} \
	    -t $(DOCS_IMAGE):$(TAG) .

# Full local equivalent of the CI documentation setup. CI may skip the emulator
# build after Depot has loaded the image by setting EMULATOR_IMAGE_READY=yes.
prepare-readme:
	$(MAKE) ensure-rootfs-docs
	$(MAKE) build-rootfs-docs-license
	@if [ "$(EMULATOR_IMAGE_READY)" != yes ]; then \
	    $(MAKE) -C .. build-emulator-image TAG=$(TAG); \
	fi
	$(MAKE) build-docs-image EMULATOR_IMAGE_READY=yes

$(REPLACE_CACHE_DIR):
	mkdir -p $@

# Standalone recipe tests never read template.d or render the documentation.
RECIPE_TEST_ENV ?= no
GAME_TEST_DIR := $(REPLACE_CACHE_DIR)/game-tests
.PHONY: test-prt-protocol test-vg test-vg-execution test-prt-game test-prt-repeat

# HOST=yes runs the recipes outside the docs image, against the local emulator build set up
# by eval $(make env). The default images the docs image would provide live in BUILD_DIR,
# and the installed command name links to the CLI script in the emulator's source tree.
HOST ?= no
ifeq ($(HOST),yes)
BUILD_DIR := $(CURDIR)/build
RECIPE_TEST_ENV := yes
export CARTESI_IMAGES_PATH := $(BUILD_DIR)/images
# Timestamps print as in the docs image.
export TZ := UTC
# The recipes and the README blocks expect GNU tools, as in the docs image. MacPorts keeps
# them under their usual names in GNU_BIN_DIR.
GNU_BIN_DIR ?= /opt/local/libexec/gnubin
export PATH := $(GNU_BIN_DIR):$(PATH)
HOST_COMMANDS := ../src/cartesi-machine ../src/cartesi-machine-stored-hash
HOST_FILES := $(HOST_COMMANDS) $(CARTESI_IMAGES_PATH)/linux.bin $(CARTESI_IMAGES_PATH)/rootfs.ext2

$(HOST_COMMANDS): ../src/%:
	ln -s $*.lua $@

$(CARTESI_IMAGES_PATH)/linux.bin: $(DEPENDENCIES_LOCK)
	mkdir -p $(@D)
	curl -sSfL -o $@ $(LINUX_URL)
	echo '$(LINUX_SHA256)  $@' | sha256sum -c -

$(CARTESI_IMAGES_PATH)/rootfs.ext2: | check-rootfs-docs
	mkdir -p $(@D)
	ln -sf $(ROOTFS_DOCS_EXT2) $@

test-prt-protocol test-vg test-vg-execution $(GAME_TEST_DIR)/initial-hash: | $(HOST_FILES)

# Rendering runs the blocks here as well. The emulator build and the images take the place of
# the docs image, so their hash stands in for its ID.
DEV_ENV_HAS_DOCGEN := yes
DOCS_IMAGE_ID := host-$(shell cat ../src/cartesi.so ../src/libcartesi* ../src/cartesi-jsonrpc-machine \
    ../src/*.lua ../src/cartesi/*.lua $(DEPENDENCIES_LOCK) $(ROOTFS_DOCS_EXT2) | shasum -a 256 | cut -c1-16)
template.d: | $(HOST_FILES)
endif

ifeq ($(RECIPE_TEST_ENV),yes)
.PHONY: prt-demo-fixture
prt-demo-fixture: $(GAME_TEST_DIR)/initial-hash

test-prt-protocol:
	bash $(RECIPES_DIR)/game-runner-test.sh
	@work=$$(mktemp -d); \
	    trap 'cd "$$work" && rm -f claims.txt outputs.txt verdict.txt round_1.txt round_1_inputs.txt \
	        round_1_mcycles.txt round_1_proofs.txt round_1_timeouts.txt round_1_uarch_cycles.txt && \
	        cd / && rmdir "$$work" || exit 1' EXIT; \
	    cd "$$work" && lua5.4 $(RECIPES_DIR)/prt-test.lua && \
	    lua5.4 $(RECIPES_DIR)/game-transport-test.lua && \
	    lua5.4 $(RECIPES_DIR)/vg-clock-test.lua

$(GAME_TEST_DIR)/initial-hash: $(RECIPES_DIR)/game-test-fixtures.sh $(RECIPES_DIR)/calc.sh
	mkdir -p $(GAME_TEST_DIR)
	cd $(GAME_TEST_DIR) && bash $(RECIPES_DIR)/game-test-fixtures.sh

test-vg: $(GAME_TEST_DIR)/initial-hash
	cd $(GAME_TEST_DIR) && lua5.4 $(RECIPES_DIR)/game-transport-test.lua && \
	    lua5.4 $(RECIPES_DIR)/vg-clock-test.lua && lua5.4 $(RECIPES_DIR)/vg-test.lua
test-vg-execution: $(GAME_TEST_DIR)/initial-hash
	cd $(GAME_TEST_DIR) && lua5.4 $(RECIPES_DIR)/vg-test.lua execution

# The machine-backed PRT suite also records the reference tournament. test-prt-game always
# runs it. test-prt-repeat records only when no recording exists, then compares a fresh run.
define record-prt-tournament
mkdir -p $(GAME_TEST_DIR)/prt-machine
cd $(GAME_TEST_DIR)/prt-machine && bash $(RECIPES_DIR)/prt-machine-test.sh $(GAME_TEST_DIR)
endef

test-prt-game: $(GAME_TEST_DIR)/initial-hash
	$(record-prt-tournament)

$(GAME_TEST_DIR)/prt-run/verdict: $(GAME_TEST_DIR)/initial-hash
	$(record-prt-tournament)

test-prt-repeat: $(GAME_TEST_DIR)/prt-run/verdict
	bash $(RECIPES_DIR)/prt-repeat-test.sh $(GAME_TEST_DIR)/rolling-calculator-template \
	    $(GAME_TEST_DIR) $(GAME_TEST_DIR)/prt-run
else
test-prt-protocol test-vg test-vg-execution test-prt-game test-prt-repeat:
	$(MAKE) docs-image-exec CONTAINER_COMMAND="make $@ RECIPE_TEST_ENV=yes"
endif

ifeq ($(DEV_ENV_HAS_DOCGEN),yes)

ifeq ($(DOCS_IMAGE_ID),)
$(error DOCS_IMAGE_ID is not set)
endif

# template.d holds the paths of the environment that generated it, so a change of environment,
# such as between the docs image and the host, regenerates it.
DOCS_IMAGE_TRIGGER := $(REPLACE_CACHE_DIR)/.docs-image-$(lastword $(subst :, ,$(DOCS_IMAGE_ID)))
$(DOCS_IMAGE_TRIGGER): | $(REPLACE_CACHE_DIR)
	rm -f $(REPLACE_CACHE_DIR)/.docs-image-*
	touch $@

# The README quotes the cartesi.hash-tree module this environment's Lua uses.
HASH_TREE_LUA := $(shell lua5.4 -e 'io.write(package.searchpath("cartesi.hash-tree", package.path))')

# Where the default kernel and rootfs images live, as the README names them.
CARTESI_IMAGES_DIR := $(or $(CARTESI_IMAGES_PATH),/usr/share/cartesi-machine/images)

# Dry-run: scan the template, populate cache directories, and emit one make
# rule per annotated block into template.d. The rendered output IS the .d
# file (pandoc emits the RawBlock that replace.lua builds).
template.d: README.md.template replace.lua $(DOCS_IMAGE_TRIGGER) | $(REPLACE_CACHE_DIR)
	ln -sfn '$(HASH_TREE_LUA)' $(REPLACE_CACHE_DIR)/hash-tree.lua
	REPLACE_CACHE_DIR=$(REPLACE_CACHE_DIR) RECIPES_DIR=$(RECIPES_DIR) \
	    pandoc -f markdown -t plain \
	    -M write-user-dependencies=README.md \
	    -M docs_image=$(DOCS_IMAGE):$(TAG) \
	    -M cartesi_images_path=$(CARTESI_IMAGES_DIR) \
	    -M docs_image_id="$(DOCS_IMAGE_ID)" \
	    --lua-filter replace.lua README.md.template -o $@

ifeq (,$(filter clean prt-demo-fixture build-prt-tools-image build-prt-calibration-image measure-prt-gas test-prt-contracts prt-contracts-exec test-prt-bridge test-prt-bridge-unit test-prt-transactions test-prt-proofs prt-container-exec build-prt-image run-prt-bridge test-prt-protocol test-vg test-vg-execution test-prt-game test-prt-repeat,$(MAKECMDGOALS)))
-include template.d
endif

# Diagrams rendered from committed sources under images/. Generated into the same
# dir and committed, like README.md itself. Regenerated only when a source changes.
# Order-only prereq of README.md below: a render always brings them up to date,
# without forcing a re-render when only the image bytes change (the template
# references the path, not the contents).
# Diagrams are committed SVGs under images/, like README.md itself, with no background of
# their own so they inherit the page. state-tree's ink colors depend on the theme, so it is
# built in a light and a dark variant that the template selects with a <picture>;
# outputs-merkle-tree and fixed-point-tree read on both themes, so a single variant serves both.
DOC_DIAGRAMS := \
    images/outputs-merkle-tree.svg \
    images/fixed-point-tree.svg \
    images/state-tree-light.svg images/state-tree-dark.svg

# outputs-merkle-tree pins its node positions for a perfectly symmetric binary tree (dot's own
# layout skews internal nodes), so it renders with neato -n, which uses the given positions
# and runs no layout. Held nodes are filled and the unmaterialized interiors are transparent
# outlines, so its colors read on both themes from one variant.
images/outputs-merkle-tree.svg: images/outputs-merkle-tree.dot
	neato -n -Tsvg $< -o $@

# fixed-point-tree uses the same pinned positions and style as outputs-merkle-tree.
images/fixed-point-tree.svg: images/fixed-point-tree.dot
	neato -n -Tsvg $< -o $@

# state-tree draws an actual machine's state hash-tree over the address space. It
# instantiates a machine and reads its memory ranges, so it is a Lua program that emits the
# SVG directly rather than a Graphviz source. Its first argument selects the palette.
images/state-tree-light.svg: images/state-tree.lua
	lua5.4 $< light > $@
images/state-tree-dark.svg: images/state-tree.lua
	lua5.4 $< dark > $@

# Real run: render the document. template.d adds per-cache-file prereqs to
# README.md, so editing a recipe propagates here naturally. check-rootfs-docs is
# order-only so a recipe-input change that leaves the committed image stale fails
# the render here (as in CI) without forcing a re-render on every invocation.
README.md: README.md.template replace.lua alerts.lua github.template.md template.d | check-rootfs-docs $(DOC_DIAGRAMS)
	REPLACE_CACHE_DIR=$(REPLACE_CACHE_DIR) RECIPES_DIR=$(RECIPES_DIR) \
	    pandoc -f markdown -s -t gfm --toc \
	    -M docs_image=$(DOCS_IMAGE):$(TAG) \
	    -M cartesi_images_path=$(CARTESI_IMAGES_DIR) \
	    --lua-filter replace.lua --lua-filter alerts.lua \
	    --template=github.template.md \
	    README.md.template -o $@

README.html: README.md README.md.template replace.lua alerts.lua github.template.html template.d
	REPLACE_CACHE_DIR=$(REPLACE_CACHE_DIR) RECIPES_DIR=$(RECIPES_DIR) \
	    pandoc -f markdown+emoji -s -t html5 --toc --mathjax \
	    -M docs_image=$(DOCS_IMAGE):$(TAG) \
	    -M cartesi_images_path=$(CARTESI_IMAGES_DIR) \
	    --lua-filter replace.lua --lua-filter alerts.lua \
	    --template=github.template.html \
	    README.md.template -o $@

else

# Without docgen tools on the host, delegate the whole build to the docs
# container. Inside, DEV_ENV_HAS_DOCGEN=yes activates the rules above and
# evaluates staleness against template.d.
.PHONY: README.md README.html
README.md: | prepare-readme
	@jobs=$(if $(JOBS),$(JOBS),$$(docker run --rm $(DOCS_IMAGE):$(TAG) nproc)); \
	$(MAKE) docs-image-exec CONTAINER_COMMAND="rm -f template.d && make -j$$jobs README.md DEV_ENV_HAS_DOCGEN=yes"

# Inside, README.html depends on README.md, so one container invocation builds
# both. Splitting them across two invocations lets the bind mount's attribute
# cache serve the second one stale mtimes for files the first one touched,
# which redoes work that is already up to date.
README.html: | prepare-readme
	@jobs=$(if $(JOBS),$(JOBS),$$(docker run --rm $(DOCS_IMAGE):$(TAG) nproc)); \
	$(MAKE) docs-image-exec CONTAINER_COMMAND="rm -f template.d && make -j$$jobs README.html DEV_ENV_HAS_DOCGEN=yes"
endif

clean:
	rm -f README.md README.html template.d
	rm -f $(RECIPES_DIR)/rootfs-docs.tar
	rm -f $(ROOTFS_DOCS_KEY) $(ROOTFS_DOCS_KEY)-have
	rm -f $(RECIPES_DIR)/.rootfs-docs-*
	rm -rf recipes/cache
