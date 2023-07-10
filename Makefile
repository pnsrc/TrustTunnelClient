BUILD_DIR = build
EXPORT_DIR ?= bin

.PHONY: all clean

bootstrap_deps:
	./scripts/bootstrap_conan_deps.py conandata.yml \
		https://github.com/AdguardTeam/NativeLibsCommon.git \
		https://github.com/AdguardTeam/DnsLibs.git

build_libs: bootstrap_deps
	mkdir -p $(BUILD_DIR) && cd $(BUILD_DIR) && \
	cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DCMAKE_C_COMPILER="clang" \
		-DCMAKE_CXX_COMPILER="clang++" \
		-DCMAKE_CXX_FLAGS="-stdlib=libc++" \
		..
	cmake --build $(BUILD_DIR) --target vpnlibs_core

build_standalone_client: build_libs
	cmake --build $(BUILD_DIR) --target standalone_client

build_wizard:
	cmake --build $(BUILD_DIR) --target setup_wizard

all: build_standalone_client build_wizard

build_and_export_standalone_client: build_standalone_client build_wizard
	mkdir -p $(EXPORT_DIR)
	cp $(BUILD_DIR)/standalone_client/standalone_client \
		$(BUILD_DIR)/standalone_client/setup_wizard \
		$(EXPORT_DIR)
	@echo "Binaries are stored in $(EXPORT_DIR)"

clean:
	cmake --build $(BUILD_DIR) --target clean
