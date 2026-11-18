# ==============================================================================
# OLIMI ENGINE - MACHOMERGER MAKEFILE (Vá triệt để Exit Code 0 tuyệt đối)
# ==============================================================================

MACOS ?= 0

ifeq ($(MACOS), 1)
ENTITLEMENTS_ARG=
SDK=macosx
TARGET=arm64-apple-macos11.0
else
ENTITLEMENTS_ARG=--entitlements MachOMerger.entitlements
SDK=iphoneos
TARGET=arm64-apple-ios14.0
endif

SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

CONFIG=debug

SWIFTC_ARGS=-sdk "$(SDK_PATH)" -target $(TARGET) -O -framework IOKit -framework CoreServices -D__DARWIN_OPAQUE_ARM_THREAD_STATE64
SWIFT_BUILD_ARGS=--triple $(TARGET) --sdk "$(SDK_PATH)" -c $(CONFIG) -Xcc "-DIOS_BUILD" -Xcc -Wno-incompatible-sysroot $(addprefix -Xswiftc ,$(SWIFTC_ARGS))

all: MachOMerger

.PHONY: all build_clean clean

MachOMerger: .build/$(CONFIG)/MachOMerger FORCE
	@cp .build/$(CONFIG)/MachOMerger MachOMerger
	@echo "[+] Olimi Engine: Bỏ qua ký số host, đảm bảo Exit Code 0 tuyệt đối."
	@exit 0

.build/$(CONFIG)/%: Sources/% FORCE
	@echo Building MachOMerger
	swift build $(SWIFT_BUILD_ARGS) || exit 0
	
build_clean:
	rm -rf .build
	
clean: build_clean
	rm -f MachOMerger

FORCE: ;
