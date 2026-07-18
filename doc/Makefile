# Docker image tag — must match the tag used by the root Makefile's
# build-emulator-image target so the docs image layers on top of an
# emulator built from the local source. Locked kernel/rootfs images may require
# emulator features not present in any released base image.
TAG ?= devel

DOCS_IMAGE = cartesi/machine-emulator-docs

DEPENDENCIES_LOCK ?= $(abspath ../dependencies.lock)
include $(DEPENDENCIES_LOCK)
export MACHINE_GUEST_TOOLS_TAG
export MACHINE_GUEST_TOOLS_DEB_SHA256
export MACHINE_GUEST_TOOLS_TARBALL_SHA256
export MACHINE_LINUX_IMAGE_TAG
export MACHINE_LINUX_IMAGE_FILENAME
export MACHINE_LINUX_IMAGE_SHA256

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

STYLUA=stylua
STYLUA_FLAGS=--indent-type Spaces --respect-ignores

.PHONY: build-docs-image prepare-readme clean format-lua check-format-lua check-lua
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
		-e MACHINE_LINUX_IMAGE_TAG \
		-e MACHINE_LINUX_IMAGE_FILENAME \
		-e MACHINE_LINUX_IMAGE_SHA256 \
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
		-e MACHINE_LINUX_IMAGE_TAG \
		-e MACHINE_LINUX_IMAGE_FILENAME \
		-e MACHINE_LINUX_IMAGE_SHA256 \
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
	    --build-arg MACHINE_GUEST_TOOLS_TAG=$(MACHINE_GUEST_TOOLS_TAG) \
	    --build-arg MACHINE_LINUX_IMAGE_TAG=$(MACHINE_LINUX_IMAGE_TAG) \
	    --build-arg MACHINE_LINUX_IMAGE_FILENAME=$(MACHINE_LINUX_IMAGE_FILENAME) \
	    --build-arg MACHINE_LINUX_IMAGE_SHA256=$(MACHINE_LINUX_IMAGE_SHA256) \
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

ifeq ($(DEV_ENV_HAS_DOCGEN),yes)

ifeq ($(DOCS_IMAGE_ID),)
$(error DOCS_IMAGE_ID is not set)
endif

# Dry-run: scan the template, populate cache directories, and emit one make
# rule per annotated block into template.d. The rendered output IS the .d
# file (pandoc emits the RawBlock that replace.lua builds).
template.d: README.md.template replace.lua | $(REPLACE_CACHE_DIR)
	REPLACE_CACHE_DIR=$(REPLACE_CACHE_DIR) RECIPES_DIR=$(RECIPES_DIR) \
	    pandoc -f markdown -t plain \
	    -M write-user-dependencies=README.md \
	    -M docs_image=$(DOCS_IMAGE):$(TAG) \
	    -M docs_image_id="$(DOCS_IMAGE_ID)" \
	    --lua-filter replace.lua README.md.template -o $@

ifeq (,$(filter clean,$(MAKECMDGOALS)))
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
# outputs-tree reads on both themes, so a single variant serves both.
DOC_DIAGRAMS := \
    images/outputs-tree.svg \
    images/state-tree-light.svg images/state-tree-dark.svg

# outputs-tree pins its node positions for a perfectly symmetric binary tree (dot's own
# layout skews internal nodes), so it renders with neato -n, which uses the given positions
# and runs no layout. Held nodes are filled and the unmaterialized interiors are transparent
# outlines, so its colors read on both themes from one variant.
images/outputs-tree.svg: images/outputs-tree.dot
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
	    --lua-filter replace.lua --lua-filter alerts.lua \
	    --template=github.template.md \
	    README.md.template -o $@

README.html: README.md README.md.template replace.lua alerts.lua github.template.html template.d
	REPLACE_CACHE_DIR=$(REPLACE_CACHE_DIR) RECIPES_DIR=$(RECIPES_DIR) \
	    pandoc -f markdown+emoji -s -t html5 --toc --mathjax \
	    -M docs_image=$(DOCS_IMAGE):$(TAG) \
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
	rm -rf $(REPLACE_CACHE_DIR)
