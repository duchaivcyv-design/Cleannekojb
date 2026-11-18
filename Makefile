# ==============================================================================
# OLIMI ENGINE - MAKEFILE TỔNG CHO DOPAMINE ROOTFUL (iOS 16.0 - 16.7.16)
# ==============================================================================

export NIGHTLY ?= 0
export BUILD_STANDALONE ?= 0
export ROOTFUL ?= 1

ifeq ($(NIGHTLY), 1)
export COMMIT_HASH = $(shell git rev-parse HEAD)
endif

ifeq ($(BUILD_STANDALONE), 1)
export BUILD_STANDALONE = 1
endif

all:
	@echo "[+] Olimi Engine: Đang biên dịch BaseBin cho Rootful..."
	@$(MAKE) -C BaseBin
	@echo "[+] Olimi Engine: Đang biên dịch Packages cho Rootful..."
	@$(MAKE) -C Packages
	@echo "[+] Olimi Engine: Đang biên dịch Application (Dopamine Rootful)..."
	@$(MAKE) -C Application
	@echo "[+] Olimi Engine: Đang biên dịch Standalone..."
	@$(MAKE) -C Standalone

clean:
	@$(MAKE) -C BaseBin clean
	@$(MAKE) -C Packages clean
	@$(MAKE) -C Application clean
	@$(MAKE) -C Standalone clean

update: all
	ssh $(DEVICE) "rm -rf /var/mobile/Documents/Dopamine.tipa"
	scp -C ./Application/Dopamine.tipa "$(DEVICE):/var/mobile/Documents/Dopamine.tipa"
	ssh $(DEVICE) "/bin/jbctl update tipa /var/mobile/Documents/Dopamine.tipa"

update-basebin: all
	ssh $(DEVICE) "rm -rf /var/mobile/Documents/basebin.tar"
	scp -C ./BaseBin/basebin.tar "$(DEVICE):/var/mobile/Documents/basebin.tar"
	ssh $(DEVICE) "/bin/jbctl update basebin /var/mobile/Documents/basebin.tar"

.PHONY: update clean update-basebin
