CC := g++
CCFLAGS += -std=c++11 -Wall -g -O0

ARCH=$(shell uname -m)
ifeq ($(ARCH), aarch64)
	LIBRARY	= -llz4-arm64
else
	LIBRARY = -llz4-x64
endif
LDFLAGS += -Wl,--gc-sections -Wl,--as-needed -Llib $(LIBRARY) -ldl -no-pie 

GIT_VERSION := $(shell git describe --abbrev=6 --dirty --always --tags)

SRC := \
	src/core.cc \
	src/proc.cc \
	src/lz4.cc \
	src/arthur.cc

OBJ := $(SRC:src/%.cc=build/%.o)
DEP := $(OBJ:%.o=%.d)
INC := -Iinclude
DEF := -DGIT_VERSION=\"$(GIT_VERSION)\" 
TARGET = arthur
TARGET_G = arthur_g
PACKAGE = Arthur-$(GIT_VERSION)-$(shell uname -s)-$(shell uname -p).tar.gz
PACKAGE_G = Arthur-$(GIT_VERSION)-$(shell uname -s)-$(shell uname -p)-Debug.tar.gz

.PHONY: clean all test cleanall distclean package
.SUFFIXES:
.SECONDARY:

all: $(TARGET)

build/$(TARGET_G): $(OBJ)
	@echo LINK $(notdir $@)
	@$(CC) $(CCFLAGS) -o $@ $(OBJ) $(LDFLAGS)

build/$(TARGET): build/$(TARGET_G)
	@strip $< -o $@

$(TARGET): build/$(TARGET)
	@ln -sf build/$(TARGET) $@

build/%.o: src/%.cc
	@echo CC $<
	@mkdir -p $(dir $@)
	@$(CC) $(CCFLAGS) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

test: $(TARGET)
	@bash tests/run.sh proc
	@bash tests/run.sh cli
	@bash tests/run.sh stream
	@bash tests/run.sh monitor-stop
	@bash tests/run.sh monitor-errors
	@bash tests/run.sh recovery-errors
	@bash tests/run.sh child-cleanup
	@bash tests/run.sh event-identity
	@bash tests/run.sh detach-relay-error
	@bash tests/run.sh final-wait-error
	@bash tests/run.sh clone-wait-error
	@bash tests/run.sh collect-event-error
	@bash tests/run.sh detach
	@bash tests/run.sh attach-relay
	@bash tests/run.sh detach-failure
	@bash tests/run.sh restore-failure
	@bash tests/run.sh mode0-relay
	@bash tests/run.sh static-fallback
	@bash tests/run.sh dontfork
	@bash tests/run.sh shared
	@bash tests/run.sh late-thread
	@bash tests/run.sh prot-none
	@bash tests/run.sh write-only
	@bash tests/run.sh rwx-file
	@bash tests/run.sh worker
	@bash tests/run.sh leader-exit
	@bash tests/run.sh exec
	@bash tests/run.sh clone-process
	@bash tests/run.sh fatal
	@bash tests/run.sh ignored
	@bash tests/run.sh sync-ignored
	@bash tests/run.sh group-stop
	@bash tests/run.sh relay
	@bash tests/run.sh snapshot
	@bash tests/run.sh snapshot-collision
	@bash tests/run.sh fork-cont
	@bash tests/run.sh race
	@bash tests/run.sh vanish
	@bash tests/run.sh register-failure
	@bash tests/run.sh close
	@bash tests/run.sh atomic
	@bash tests/run.sh checksum
	@bash tests/run.sh format
	@bash tests/run.sh reuse
	@bash tests/run.sh trailing
	@bash tests/run.sh task-enumeration
	@bash tests/run.sh clone-identity
	@bash tests/run.sh disposition-read
	@bash tests/run.sh child-stack-restore
	@bash tests/run.sh pt-call-recovery
	@bash tests/run.sh call-alignment
	@bash tests/run.sh child-detach-esrch
	@bash tests/run.sh injection-crash
	@bash tests/run.sh crash-detach
	@bash tests/run.sh duplicate-options
	@bash tests/run.sh low-stack

clean:
	@rm -rf build $(TARGET)
	@rm -rf Arthur-*.tar.gz

cleanall: clean

distclean: cleanall

host.log: $(TARGET) 
	@sh -c "uname -a; cat /etc/*release; ldd ./arthur" > $@

$(PACKAGE): $(TARGET)
	@echo $@
	@tar cfz $(PACKAGE) build/arthur 

$(PACKAGE_G): $(TARGET) host.log
	@echo $@
	@tar cfz $(PACKAGE_G) build/arthur build/arthur_g host.log 

package: $(PACKAGE) $(PACKAGE_G)
	@echo $*

-include $(DEP)
